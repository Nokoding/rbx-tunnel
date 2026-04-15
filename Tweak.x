#import <arpa/inet.h>
#import <dlfcn.h>
#import <errno.h>
#import <netdb.h>
#import <netinet/in.h>
#import <pthread.h>
#import <stdbool.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <unistd.h>
#import "fishhook.h"

#define PROXY_HOST "crossover.proxy.rlwy.net"
#define PROXY_PORT 50156
#define SOCKS5_VERSION 0x05
#define SOCKS5_NO_AUTH 0x00
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static void (*orig_freeaddrinfo)(struct addrinfo *);

static struct sockaddr_in g_proxy_addr;
static struct sockaddr_in g_udp_relay_addr;
static int g_udp_associated = 0;
static int g_tcp_control_fd = -1;
static _Thread_local bool g_in_getaddrinfo = false;

struct host_map_entry {
    struct addrinfo *ai;
    struct sockaddr_in addr;
    char host[256];
    struct host_map_entry *next;
};

struct socks5_dest {
    uint8_t atyp;
    uint16_t port;
    union {
        struct in_addr ipv4;
        char domain[256];
    } addr;
};

static struct host_map_entry *g_host_map = NULL;

static bool sockaddr_equal(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a && b && a->sin_family == b->sin_family && a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static bool is_proxy_addr(const struct sockaddr_in *sa) {
    if (!sa || sa->sin_family != AF_INET) return false;
    if (sa->sin_port == htons(PROXY_PORT)) {
        if (g_proxy_addr.sin_addr.s_addr != 0 && sa->sin_addr.s_addr == g_proxy_addr.sin_addr.s_addr) {
            return true;
        }
    }
    if (g_udp_associated && sockaddr_equal(sa, &g_udp_relay_addr)) {
        return true;
    }
    return false;
}

static void add_host_map_entry(struct addrinfo *ai, const char *host) {
    // DNS proxying disabled - not used
}

static struct host_map_entry *find_host_map_entry(const struct sockaddr_in *addr) {
    // DNS proxying disabled - not used
    return NULL;
}

static void remove_host_map_entries_for_ai(struct addrinfo *ai) {
    // DNS proxying disabled - not used
}

static bool resolve_proxy_addr(void) {
    if (g_proxy_addr.sin_addr.s_addr != 0) return true;

    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = NULL;
    g_in_getaddrinfo = true;
    int rv = orig_getaddrinfo(PROXY_HOST, "50156", &hints, &result);
    g_in_getaddrinfo = false;
    if (rv != 0 || !result) {
        // Proxy resolution failed - fall back to direct connections
        return false;
    }
    for (struct addrinfo *ai = result; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addr) {
            memcpy(&g_proxy_addr, ai->ai_addr, sizeof(g_proxy_addr));
            g_proxy_addr.sin_port = htons(PROXY_PORT);
            orig_freeaddrinfo(result);
            return true;
        }
    }
    orig_freeaddrinfo(result);
    return false;
}

static void build_socks5_dest(const struct sockaddr_in *dest4, const char *domain, struct socks5_dest *out) {
    if (!dest4 || !out) return;
    out->port = dest4->sin_port;
    if (domain && domain[0]) {
        out->atyp = 0x03;
        strncpy(out->addr.domain, domain, sizeof(out->addr.domain) - 1);
    } else {
        out->atyp = SOCKS5_ATYP_IPV4;
        out->addr.ipv4 = dest4->sin_addr;
    }
}

static int socks5_send_all(int sockfd, const void *buf, size_t len) {
    const uint8_t *ptr = buf;
    while (len > 0) {
        ssize_t sent = send(sockfd, ptr, len, 0);
        if (sent <= 0) {
            return -1;
        }
        ptr += sent;
        len -= sent;
    }
    return 0;
}

static int socks5_recv_all(int sockfd, void *buf, size_t len) {
    uint8_t *ptr = buf;
    while (len > 0) {
        ssize_t recvd = recv(sockfd, ptr, len, 0);
        if (recvd <= 0) {
            return -1;
        }
        ptr += recvd;
        len -= recvd;
    }
    return 0;
}

static bool perform_socks5_handshake(int sockfd) {
    uint8_t greeting[3] = {SOCKS5_VERSION, 0x01, SOCKS5_NO_AUTH};
    if (socks5_send_all(sockfd, greeting, sizeof(greeting)) != 0) return false;

    uint8_t resp[2] = {0};
    if (socks5_recv_all(sockfd, resp, sizeof(resp)) != 0) return false;
    return resp[0] == SOCKS5_VERSION && resp[1] == SOCKS5_NO_AUTH;
}

static bool perform_socks5_tcp_connect(int sockfd, const struct socks5_dest *dest) {
    if (!dest) return false;
    uint8_t buffer[4 + 1 + 256 + 2];
    size_t offset = 0;
    buffer[offset++] = SOCKS5_VERSION;
    buffer[offset++] = SOCKS5_CMD_CONNECT;
    buffer[offset++] = 0x00;
    buffer[offset++] = dest->atyp;

    if (dest->atyp == SOCKS5_ATYP_IPV4) {
        memcpy(buffer + offset, &dest->addr.ipv4.s_addr, 4);
        offset += 4;
    } else {
        size_t host_len = strnlen(dest->addr.domain, sizeof(dest->addr.domain));
        if (host_len == 0 || host_len > 255) return false;
        buffer[offset++] = (uint8_t)host_len;
        memcpy(buffer + offset, dest->addr.domain, host_len);
        offset += host_len;
    }
    memcpy(buffer + offset, &dest->port, 2);
    offset += 2;

    if (socks5_send_all(sockfd, buffer, offset) != 0) return false;

    uint8_t header[4];
    if (socks5_recv_all(sockfd, header, sizeof(header)) != 0) return false;
    if (header[0] != SOCKS5_VERSION || header[1] != 0x00) return false;
    uint8_t atyp = header[3];
    size_t addr_len = 0;
    switch (atyp) {
        case SOCKS5_ATYP_IPV4: addr_len = 4; break;
        default: return false;
    }
    uint8_t discard[256];
    if (socks5_recv_all(sockfd, discard, addr_len + 2) != 0) return false;
    return true;
}

static bool establish_udp_association(void) {
    if (g_udp_associated) return true;
    if (!resolve_proxy_addr()) return false;

    if (g_tcp_control_fd < 0) {
        g_tcp_control_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_tcp_control_fd < 0) return false;
        if (orig_connect(g_tcp_control_fd, (const struct sockaddr *)&g_proxy_addr, sizeof(g_proxy_addr)) != 0) {
            close(g_tcp_control_fd);
            g_tcp_control_fd = -1;
            return false;
        }
        if (!perform_socks5_handshake(g_tcp_control_fd)) {
            close(g_tcp_control_fd);
            g_tcp_control_fd = -1;
            return false;
        }
    }

    uint8_t request[10] = {SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    if (socks5_send_all(g_tcp_control_fd, request, sizeof(request)) != 0) return false;

    uint8_t header[4];
    if (socks5_recv_all(g_tcp_control_fd, header, sizeof(header)) != 0) return false;
    if (header[0] != SOCKS5_VERSION || header[1] != 0x00) return false;
    uint8_t atyp = header[3];
    if (atyp != SOCKS5_ATYP_IPV4) return false;

    uint8_t address[6];
    if (socks5_recv_all(g_tcp_control_fd, address, sizeof(address)) != 0) return false;
    g_udp_relay_addr.sin_family = AF_INET;
    memcpy(&g_udp_relay_addr.sin_addr.s_addr, address, 4);
    memcpy(&g_udp_relay_addr.sin_port, address + 4, 2);
    g_udp_associated = 1;
    return true;
}

static ssize_t build_socks5_udp_packet(const struct socks5_dest *dest, const void *buf, size_t len, uint8_t **out_packet, size_t *out_len) {
    if (!dest || !buf || !out_packet || !out_len) return -1;
    size_t header_len = 4;
    if (dest->atyp == SOCKS5_ATYP_IPV4) {
        header_len += 4 + 2;
    } else {
        size_t host_len = strnlen(dest->addr.domain, sizeof(dest->addr.domain));
        if (host_len == 0 || host_len > 255) return -1;
        header_len += 1 + host_len + 2;
    }
    *out_len = header_len + len;
    *out_packet = malloc(*out_len);
    if (!*out_packet) return -1;
    (*out_packet)[0] = 0x00;
    (*out_packet)[1] = 0x00;
    (*out_packet)[2] = 0x00;
    (*out_packet)[3] = dest->atyp;
    size_t offset = 4;
    if (dest->atyp == SOCKS5_ATYP_IPV4) {
        memcpy(*out_packet + offset, &dest->addr.ipv4.s_addr, 4);
        offset += 4;
    } else {
        uint8_t host_len = (uint8_t)strnlen(dest->addr.domain, sizeof(dest->addr.domain));
        (*out_packet)[offset++] = host_len;
        memcpy(*out_packet + offset, dest->addr.domain, host_len);
        offset += host_len;
    }
    memcpy(*out_packet + offset, &dest->port, 2);
    offset += 2;
    memcpy(*out_packet + offset, buf, len);
    return 0;
}

static ssize_t build_and_send_socks5_udp(int sockfd, const struct socks5_dest *dest, const void *buf, size_t len, int flags) {
    if (!dest || !buf || len == 0) return -1;
    if (!establish_udp_association()) return -1;

    uint8_t *packet = NULL;
    size_t packet_len = 0;
    if (build_socks5_udp_packet(dest, buf, len, &packet, &packet_len) != 0) return -1;

    ssize_t sent = orig_sendto(sockfd, packet, packet_len, flags, (const struct sockaddr *)&g_udp_relay_addr, sizeof(g_udp_relay_addr));
    free(packet);
    return sent == -1 ? -1 : len;
}

static ssize_t hooked_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!dest_addr || dest_addr->sa_family != AF_INET) {
        return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    const struct sockaddr_in *dest4 = (const struct sockaddr_in *)dest_addr;
    struct socks5_dest dest_info;
    memset(&dest_info, 0, sizeof(dest_info));

    if (is_proxy_addr(dest4)) {
        return orig_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    struct host_map_entry *entry = find_host_map_entry(dest4);
    if (entry && entry->host[0]) {
        build_socks5_dest(dest4, entry->host, &dest_info);
    } else {
        build_socks5_dest(dest4, NULL, &dest_info);
    }

    return build_and_send_socks5_udp(sockfd, &dest_info, buf, len, flags);
}

static ssize_t parse_socks5_udp_packet(const uint8_t *packet, size_t packet_len, uint8_t **payload, size_t *payload_len, struct sockaddr_in *peer) {
    if (packet_len < 10) return -1;
    if (packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00) return -1;
    if (packet[3] != SOCKS5_ATYP_IPV4) return -1;
    *payload_len = packet_len - 10;
    *payload = (uint8_t *)packet + 10;
    if (peer) {
        peer->sin_family = AF_INET;
        memcpy(&peer->sin_addr.s_addr, packet + 4, 4);
        memcpy(&peer->sin_port, packet + 8, 2);
    }
    return 0;
}

static ssize_t hooked_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!buf) return orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

    size_t temp_len = len + 64;
    uint8_t *temp = malloc(temp_len);
    if (!temp) return -1;
    struct sockaddr_in from = {0};
    socklen_t fromlen = sizeof(from);
    ssize_t recvd = orig_recvfrom(sockfd, temp, temp_len, flags, (struct sockaddr *)&from, &fromlen);
    if (recvd <= 0) {
        free(temp);
        return recvd;
    }

    if (from.sin_family == AF_INET && is_proxy_addr(&from)) {
        uint8_t *payload = NULL;
        size_t payload_len = 0;
        struct sockaddr_in peer = {0};
        if (parse_socks5_udp_packet(temp, recvd, &payload, &payload_len, &peer) == 0) {
            ssize_t ret = payload_len > len ? len : payload_len;
            memcpy(buf, payload, ret);
            if (src_addr && addrlen && *addrlen >= sizeof(peer)) {
                memcpy(src_addr, &peer, sizeof(peer));
                *addrlen = sizeof(peer);
            }
            free(temp);
            return ret;
        }
    }

    if (recvd > (ssize_t)len) recvd = len;
    memcpy(buf, temp, recvd);
    if (src_addr && addrlen && *addrlen >= sizeof(from)) {
        memcpy(src_addr, &from, sizeof(from));
        *addrlen = sizeof(from);
    }
    free(temp);
    return recvd;
}

static int connect_via_proxy(int sockfd, const struct socks5_dest *dest) {
    if (!resolve_proxy_addr()) return -1;
    if (sockfd < 0 || !dest) return -1;

    struct sockaddr_in proxy = g_proxy_addr;
    if (orig_connect(sockfd, (const struct sockaddr *)&proxy, sizeof(proxy)) != 0) {
        return -1;
    }

    if (!perform_socks5_handshake(sockfd)) {
        errno = ECONNABORTED;
        return -1;
    }

    if (!perform_socks5_tcp_connect(sockfd, dest)) {
        errno = ECONNABORTED;
        return -1;
    }
    return 0;
}

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || addr->sa_family != AF_INET) {
        return orig_connect(sockfd, addr, addrlen);
    }

    struct sockaddr_in dest4 = *(const struct sockaddr_in *)addr;
    if (is_proxy_addr(&dest4)) {
        return orig_connect(sockfd, addr, addrlen);
    }

    // If proxy is not reachable, fall back to direct connection
    if (!resolve_proxy_addr()) {
        return orig_connect(sockfd, addr, addrlen);
    }

    struct socks5_dest dest_info;
    memset(&dest_info, 0, sizeof(dest_info));
    build_socks5_dest(&dest4, NULL, &dest_info);

    int result = connect_via_proxy(sockfd, &dest_info);
    // If proxy connection fails, try direct connection as fallback
    if (result != 0) {
        return orig_connect(sockfd, addr, addrlen);
    }
    return result;
}

static int hooked_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // DNS proxying disabled to prevent startup crashes
    // Let the app use normal DNS resolution
    return orig_getaddrinfo(node, service, hints, res);
}

static void hooked_freeaddrinfo(struct addrinfo *res) {
    if (!res) return;
    remove_host_map_entries_for_ai(res);
    orig_freeaddrinfo(res);
}

%ctor {
    struct rebinding rebindings[] = {
        {"connect", (void *)hooked_connect, (void **)&orig_connect},
        {"sendto", (void *)hooked_sendto, (void **)&orig_sendto},
        {"recvfrom", (void *)hooked_recvfrom, (void **)&orig_recvfrom},
        {"getaddrinfo", (void *)hooked_getaddrinfo, (void **)&orig_getaddrinfo},
        {"freeaddrinfo", (void *)hooked_freeaddrinfo, (void **)&orig_freeaddrinfo},
    };
    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));
}
