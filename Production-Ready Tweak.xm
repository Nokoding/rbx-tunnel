#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <dlfcn.h>
#import <dispatch/dispatch.h>
#import <pthread.h>
#import <errno.h>
#import "fishhook.h" // Include fishhook header

#define LOG(fmt, ...) NSLog(@"[rbx-tunnel] " fmt, ##__VA_ARGS__)
#define PROXY_HOST "crossover.proxy.rlwy.net"
#define PROXY_PORT 50156
#define CONNECT_TIMEOUT 10 // seconds

// MARK: - Original Function Pointers

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static void (*orig_freeaddrinfo)(struct addrinfo *);

// MARK: - State Management

static BOOL g_hooksInstalled = NO;
static pthread_mutex_t g_dnsMutex = PTHREAD_MUTEX_INITIALIZER;
static __thread BOOL g_inGetaddrinfo = NO; // Thread-local recursion guard

// MARK: - SOCKS5 Implementation

typedef enum {
    SOCKS5_VERSION = 0x05,
    SOCKS5_CMD_CONNECT = 0x01,
    SOCKS5_CMD_UDP_ASSOCIATE = 0x03,
    SOCKS5_ATYP_IPV4 = 0x01,
    SOCKS5_ATYP_DOMAIN = 0x03,
    SOCKS5_ATYP_IPV6 = 0x04,
    SOCKS5_AUTH_NONE = 0x00
} SOCKS5Constants;

static BOOL perform_socks5_handshake(int sockfd) {
    uint8_t greeting[] = {SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE};
    
    if (send(sockfd, greeting, sizeof(greeting), 0) != sizeof(greeting)) {
        LOG("SOCKS5 greeting failed: %s", strerror(errno));
        return NO;
    }
    
    uint8_t response[2];
    ssize_t received = recv(sockfd, response, 2, 0);
    
    if (received != 2 || response[0] != SOCKS5_VERSION || response[1] != SOCKS5_AUTH_NONE) {
        LOG("SOCKS5 auth failed");
        return NO;
    }
    
    return YES;
}

static BOOL send_socks5_connect_request(int sockfd, const struct sockaddr *target_addr) {
    uint8_t request[256];
    size_t request_len = 0;
    
    request[request_len++] = SOCKS5_VERSION;
    request[request_len++] = SOCKS5_CMD_CONNECT;
    request[request_len++] = 0x00; // Reserved
    
    if (target_addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)target_addr;
        request[request_len++] = SOCKS5_ATYP_IPV4;
        memcpy(&request[request_len], &sin->sin_addr.s_addr, 4);
        request_len += 4;
        memcpy(&request[request_len], &sin->sin_port, 2);
        request_len += 2;
    } else if (target_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)target_addr;
        request[request_len++] = SOCKS5_ATYP_IPV6;
        memcpy(&request[request_len], &sin6->sin6_addr, 16);
        request_len += 16;
        memcpy(&request[request_len], &sin6->sin6_port, 2);
        request_len += 2;
    } else {
        LOG("Unsupported address family: %d", target_addr->sa_family);
        return NO;
    }
    
    if (send(sockfd, request, request_len, 0) != (ssize_t)request_len) {
        LOG("SOCKS5 request send failed");
        return NO;
    }
    
    uint8_t response[256];
    ssize_t received = recv(sockfd, response, 4, 0);
    if (received < 4) {
        LOG("SOCKS5 response too short");
        return NO;
    }
    
    if (response[0] != SOCKS5_VERSION || response[1] != 0x00) {
        LOG("SOCKS5 connect failed: ver=%d, rep=%d", response[0], response[1]);
        return NO;
    }
    
    // Read remaining bytes based on address type
    size_t remaining = 0;
    switch (response[3]) {
        case SOCKS5_ATYP_IPV4: remaining = 4 + 2; break;
        case SOCKS5_ATYP_IPV6: remaining = 16 + 2; break;
        case SOCKS5_ATYP_DOMAIN: {
            uint8_t len;
            recv(sockfd, &len, 1, 0);
            remaining = len + 2;
            break;
        }
        default:
            LOG("Unknown address type in response: %d", response[3]);
            return NO;
    }
    
    // Drain remaining bytes
    uint8_t dummy[256];
    while (remaining > 0) {
        ssize_t to_read = remaining > sizeof(dummy) ? sizeof(dummy) : remaining;
        ssize_t r = recv(sockfd, dummy, to_read, 0);
        if (r <= 0) break;
        remaining -= r;
    }
    
    return YES;
}

static int connect_to_proxy() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    
    // Set non-blocking initially to avoid blocking on DNS/connect
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    
    // Resolve proxy host using original getaddrinfo (bypass hook)
    struct addrinfo *result = NULL;
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    // Temporarily restore original to avoid recursion
    g_inGetaddrinfo = YES;
    int ret = orig_getaddrinfo(PROXY_HOST, NULL, &hints, &result);
    g_inGetaddrinfo = NO;
    
    if (ret != 0 || !result) {
        close(sockfd);
        return -1;
    }
    
    memcpy(&proxy_addr.sin_addr, 
           &((struct sockaddr_in *)result->ai_addr)->sin_addr, 
           sizeof(struct in_addr));
    orig_freeaddrinfo(result);
    
    // Attempt non-blocking connect
    ret = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    
    if (ret < 0 && errno == EINPROGRESS) {
        // Wait for connection with timeout
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        
        struct timeval tv;
        tv.tv_sec = CONNECT_TIMEOUT;
        tv.tv_usec = 0;
        
        ret = select(sockfd + 1, NULL, &fdset, NULL, &tv);
        if (ret <= 0) {
            close(sockfd);
            return -1;
        }
        
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            close(sockfd);
            return -1;
        }
    } else if (ret < 0) {
        close(sockfd);
        return -1;
    }
    
    // Restore blocking mode for SOCKS5 handshake
    fcntl(sockfd, F_SETFL, flags);
    
    if (!perform_socks5_handshake(sockfd)) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// MARK: - Hooked Functions

int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!g_hooksInstalled) return orig_connect(sockfd, addr, addrlen);
    
    // Skip local connections and non-IP sockets
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return orig_connect(sockfd, addr, addrlen);
    }
    
    // Check if this is a private/local address (bypass proxy)
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        if ((ip >> 24) == 127 || (ip >> 16) == 0xC0A8 || (ip >> 12) == 0xAC1) {
            return orig_connect(sockfd, addr, addrlen);
        }
    }
    
    LOG("Intercepting connect to port %d", 
        ntohs(((struct sockaddr_in *)addr)->sin_port));
    
    // CRITICAL FIX: If we're on main thread, don't block
    if (pthread_main_np()) {
        LOG("WARNING: connect() called on main thread - deferring");
        // For main thread, we must not block. Return EINPROGRESS and handle async.
        // This is a simplification - real implementation needs async handling
        errno = EINPROGRESS;
        return -1;
    }
    
    // Establish proxy connection
    int proxy_sock = connect_to_proxy();
    if (proxy_sock < 0) {
        LOG("Failed to connect to SOCKS5 proxy");
        return orig_connect(sockfd, addr, addrlen); // Fallback to direct
    }
    
    // Send SOCKS5 CONNECT request
    if (!send_socks5_connect_request(proxy_sock, addr)) {
        close(proxy_sock);
        return orig_connect(sockfd, addr, addrlen); // Fallback
    }
    
    // Replace user's socket with proxy socket using dup2
    // This is tricky - we need to preserve the original fd number
    // Instead, we'll use a socket pair to splice data (simplified here)
    
    LOG("SOCKS5 tunnel established");
    
    // For simplicity in this fix, we'll use the proxy socket directly
    // In production, you'd want proper socket splicing or fd replacement
    dup2(proxy_sock, sockfd);
    close(proxy_sock);
    
    return 0;
}

ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    // UDP ASSOCIATE logic would go here
    // For now, pass through (Roblox primarily uses TCP)
    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    return orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

int hooked_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    // CRITICAL FIX: Prevent infinite recursion
    if (g_inGetaddrinfo) {
        // We're already inside getaddrinfo (resolving proxy host), bypass
        return orig_getaddrinfo(node, service, hints, res);
    }
    
    // Bypass for proxy host itself
    if (node && strcmp(node, PROXY_HOST) == 0) {
        g_inGetaddrinfo = YES;
        int ret = orig_getaddrinfo(node, service, hints, res);
        g_inGetaddrinfo = NO;
        return ret;
    }
    
    // For all other DNS, we could route through SOCKS5 here
    // For now, just log and pass through (avoiding recursion issues)
    if (node) {
        LOG("DNS resolve: %s", node);
    }
    
    return orig_getaddrinfo(node, service, hints, res);
}

void hooked_freeaddrinfo(struct addrinfo *res) {
    orig_freeaddrinfo(res);
}

// MARK: - Initialization

static void install_hooks(void) {
    if (g_hooksInstalled) return;
    
    LOG("Installing network hooks...");
    
    struct rebinding bindings[] = {
        {"connect", (void *)hooked_connect, (void **)&orig_connect},
        {"sendto", (void *)hooked_sendto, (void **)&orig_sendto},
        {"recvfrom", (void *)hooked_recvfrom, (void **)&orig_recvfrom},
        {"getaddrinfo", (void *)hooked_getaddrinfo, (void **)&orig_getaddrinfo},
        {"freeaddrinfo", (void *)hooked_freeaddrinfo, (void **)&orig_freeaddrinfo}
    };
    
    int ret = rebind_symbols(bindings, 5);
    if (ret != 0) {
        LOG("Failed to rebind symbols: %d", ret);
        return;
    }
    
    g_hooksInstalled = YES;
    LOG("Hooks installed successfully");
}

// CRITICAL FIX: Delayed initialization to avoid early runtime issues
__attribute__((constructor))
static void init() {
    LOG("rbx-tunnel loading (pid: %d)", getpid());
    
    // Ensure we're in Roblox
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (![bundleId isEqualToString:@"com.roblox.robloxmobile"]) {
        LOG("Not Roblox (%@), aborting", bundleId);
        return;
    }
    
    LOG("Confirmed Roblox environment");
    
    // Delay hook installation to avoid constructor race conditions
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), 
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            install_hooks();
        }
    });
}
