// Tweak.xm
#import <Foundation/Foundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <dlfcn.h>
#import <dispatch/dispatch.h>
#import <pthread.h>
#import <errno.h>
#import <fcntl.h>

#define LOG(fmt, ...) NSLog(@"[rbx-tunnel] " fmt, ##__VA_ARGS__)
#define PROXY_HOST "crossover.proxy.rlwy.net"
#define PROXY_PORT 50156
#define CONNECT_TIMEOUT 5

// MARK: - Function Pointers (resolved at runtime via dlsym)

static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static void (*orig_freeaddrinfo)(struct addrinfo *) = NULL;

// MARK: - State

static BOOL g_initialized = NO;
static __thread BOOL g_inGetaddrinfo = NO;

// MARK: - SOCKS5 Implementation (same as before, optimized)

typedef enum {
    SOCKS5_VERSION = 0x05,
    SOCKS5_CMD_CONNECT = 0x01,
    SOCKS5_ATYP_IPV4 = 0x01,
    SOCKS5_ATYP_DOMAIN = 0x03,
    SOCKS5_AUTH_NONE = 0x00
} SOCKS5Constants;

static BOOL socks5_handshake(int sockfd) {
    uint8_t greeting[] = {SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE};
    if (send(sockfd, greeting, sizeof(greeting), 0) != sizeof(greeting)) return NO;
    
    uint8_t resp[2];
    return (recv(sockfd, resp, 2, 0) == 2 && resp[0] == SOCKS5_VERSION && resp[1] == 0x00);
}

static BOOL socks5_request(int sockfd, const struct sockaddr *addr) {
    uint8_t req[256];
    size_t len = 0;
    
    req[len++] = SOCKS5_VERSION;
    req[len++] = SOCKS5_CMD_CONNECT;
    req[len++] = 0x00;
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        req[len++] = SOCKS5_ATYP_IPV4;
        memcpy(&req[len], &sin->sin_addr, 4); len += 4;
        memcpy(&req[len], &sin->sin_port, 2); len += 2;
    } else {
        return NO; // IPv6 not implemented for brevity
    }
    
    if (send(sockfd, req, len, 0) != (ssize_t)len) return NO;
    
    uint8_t resp[256];
    if (recv(sockfd, resp, 4, 0) != 4 || resp[1] != 0x00) return NO;
    
    // Drain remaining
    size_t skip = (resp[3] == SOCKS5_ATYP_IPV4) ? 6 : (resp[3] == SOCKS5_ATYP_DOMAIN) ? resp[4] + 2 : 18;
    recv(sockfd, resp, skip > 256 ? 256 : skip, 0);
    
    return YES;
}

static int connect_proxy_async(void) {
    // Resolve proxy host using original getaddrinfo (bypass hook)
    g_inGetaddrinfo = YES;
    struct addrinfo *res = NULL, hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (orig_getaddrinfo(PROXY_HOST, NULL, &hints, &res) != 0 || !res) {
        g_inGetaddrinfo = NO;
        return -1;
    }
    g_inGetaddrinfo = NO;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) goto cleanup;
    
    // Non-blocking connect with timeout
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in *proxy = (struct sockaddr_in *)res->ai_addr;
    proxy->sin_port = htons(PROXY_PORT);
    
    int ret = orig_connect(sock, (struct sockaddr *)proxy, sizeof(*proxy));
    if (ret < 0 && errno == EINPROGRESS) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        struct timeval tv = {CONNECT_TIMEOUT, 0};
        
        ret = select(sock + 1, NULL, &fds, NULL, &tv);
        if (ret <= 0) {
            close(sock);
            sock = -1;
            goto cleanup;
        }
        
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            close(sock);
            sock = -1;
            goto cleanup;
        }
    }
    
    fcntl(sock, F_SETFL, flags);
    
    if (!socks5_handshake(sock) || !socks5_request(sock, (struct sockaddr *)proxy)) {
        close(sock);
        sock = -1;
    }
    
cleanup:
    orig_freeaddrinfo(res);
    return sock;
}

// MARK: - Hooked Functions (Interposed)

int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!g_initialized || !addr) return orig_connect(sockfd, addr, addrlen);
    
    // Skip local/private
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        uint8_t *b = (uint8_t *)&sin->sin_addr;
        if (b[0] == 127 || b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)) {
            return orig_connect(sockfd, addr, addrlen);
        }
    }
    
    LOG("Connecting to port %d", ntohs(((struct sockaddr_in *)addr)->sin_port));
    
    // Main thread check - critical fix
    if (pthread_main_np()) {
        LOG("Main thread connect - using direct");
        return orig_connect(sockfd, addr, addrlen);
    }
    
    int proxy = connect_proxy_async();
    if (proxy < 0) {
        LOG("Proxy failed, using direct");
        return orig_connect(sockfd, addr, addrlen);
    }
    
    // Replace socket fd
    dup2(proxy, sockfd);
    close(proxy);
    
    LOG("Tunneled via SOCKS5");
    return 0;
}

ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    return orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

int hooked_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
    if (g_inGetaddrinfo || !node) {
        return orig_getaddrinfo(node, service, hints, res);
    }
    
    // Log DNS for debugging
    LOG("DNS: %s", node);
    
    return orig_getaddrinfo(node, service, hints, res);
}

void hooked_freeaddrinfo(struct addrinfo *res) {
    orig_freeaddrinfo(res);
}

// MARK: - Interpose Section (No Fishhook Needed)

typedef struct {
    const void *replacement;
    const void *original;
} interpose_t;

__attribute__((used)) static const interpose_t interposers[] 
__attribute__((section("__DATA,__interpose"))) = {
    { (const void *)hooked_connect, (const void *)connect },
    { (const void *)hooked_sendto, (const void *)sendto },
    { (const void *)hooked_recvfrom, (const void *)recvfrom },
    { (const void *)hooked_getaddrinfo, (const void *)getaddrinfo },
    { (const void *)hooked_freeaddrinfo, (const void *)freeaddrinfo },
};

// MARK: - Initialization

__attribute__((constructor))
static void init() {
    LOG("Loading rbx-tunnel...");
    
    // Verify bundle
    NSString *bundle = [[NSBundle mainBundle] bundleIdentifier];
    if (![bundle isEqualToString:@"com.roblox.robloxmobile"]) {
        LOG("Wrong bundle: %@, exiting", bundle);
        return;
    }
    
    // Resolve original functions via dlsym (RTLD_NEXT gets the "real" ones)
    orig_connect = dlsym(RTLD_NEXT, "connect");
    orig_sendto = dlsym(RTLD_NEXT, "sendto");
    orig_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    orig_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    orig_freeaddrinfo = dlsym(RTLD_NEXT, "freeaddrinfo");
    
    if (!orig_connect || !orig_getaddrinfo) {
        LOG("Failed to resolve originals");
        return;
    }
    
    // Delay to avoid early initialization issues
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), 
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        g_initialized = YES;
        LOG("rbx-tunnel active");
    });
}
