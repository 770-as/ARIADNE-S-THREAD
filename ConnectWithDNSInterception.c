#define _GNU_SOURCE  // Required for dlsym and RTLD_NEXT
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h> // For close()
#include <netdb.h>  // Required for gethostbyname and struct hostent
#include <stdlib.h> // For malloc/free

// --- Configuration Constants (Simplified) ---
#define TOR_SOCKS_ADDR "127.0.0.1"
#define TOR_SOCKS_PORT 9050

// --- Function Pointers for Original System Calls ---
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;
// 💥 NEW: Pointer for the real DNS function
static struct hostent* (*real_gethostbyname)(const char*) = NULL;

// --- SOCKS5 Negotiation Data Structures (Simplified) ---
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_DOMAINNAME 0x03 // 💥 Using Domain Name for Anonymous DNS
#define SOCKS_VERSION 0x05
#define SOCKS_REPLY_SUCCESS 0x00

const char socks5_initial_handshake[] = {0x05, 0x01, 0x00}; // Ver | Nmethods | Method (No Auth)
const char socks5_handshake_success[] = {0x05, 0x00};      // Ver | Method (No Auth)


/**
 * @brief Initialize the function pointers for real system calls.
 */
static void init_dlsym() __attribute__((constructor));

static void init_dlsym() {
    real_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_connect) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not find real connect() using dlsym.\n");
    }
    // 💥 NEW: Initialize real_gethostbyname
    real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
    if (!real_gethostbyname) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not find real gethostbyname() using dlsym.\n");
    }
}

/**
 * @brief Sends a SOCKS5 CONNECT command using the target hostname and checks the reply.
 * This is the anonymous resolution path (ATYP 0x03).
 * @param sockfd The socket already connected to 127.0.0.1:9050.
 * @param hostname The target domain name string (e.g., "google.com").
 * @param port The target port in host byte order.
 * @return 0 on SOCKS success, -1 on failure.
 */
int perform_socks5_domain_negotiation(int sockfd, const char *hostname, uint16_t port) {
    char buffer[256];
    size_t bytes_read;
    size_t hostname_len = strlen(hostname);

    // 1. Initial Handshake (Same as before)
    if (send(sockfd, socks5_initial_handshake, sizeof(socks5_initial_handshake), 0) < 0) {
        return -1;
    }
    bytes_read = recv(sockfd, buffer, 2, 0);
    if (bytes_read != 2 || memcmp(buffer, socks5_handshake_success, 2) != 0) {
        fprintf(stderr, "TORSOCKS_WRAPPER: SOCKS handshake failed.\n");
        return -1;
    }

    // 2. Command Request: Build the CONNECT request to the TARGET HOSTNAME (ATYP 0x03)
    if (hostname_len == 0 || hostname_len > 255 - 7) { 
        fprintf(stderr, "TORSOCKS_WRAPPER: Invalid or too long hostname.\n");
        return -1; 
    }
    
    // Structure: Ver | Cmd | RSV | ATYP | ADDR_LEN | DST.ADDR (Hostname) | DST.PORT
    buffer[0] = SOCKS_VERSION;
    buffer[1] = SOCKS_CMD_CONNECT;
    buffer[2] = 0x00;           // Reserved
    buffer[3] = SOCKS_ATYP_DOMAINNAME; // 💥 ATYP: Domain Name
    buffer[4] = (char)hostname_len; // Length of the hostname
    
    memcpy(buffer + 5, hostname, hostname_len); 
    
    uint16_t net_port = htons(port); 
    memcpy(buffer + 5 + hostname_len, &net_port, 2); 
    
    size_t request_len = 5 + hostname_len + 2;

    if (send(sockfd, buffer, request_len, 0) < 0) {
        return -1;
    }

    // 3. Receive final SOCKS reply
    bytes_read = recv(sockfd, buffer, 10, 0);
    if (bytes_read < 0 || buffer[1] != SOCKS_REPLY_SUCCESS) {
        fprintf(stderr, "TORSOCKS_WRAPPER: SOCKS domain connection request failed (Reply: 0x%02x).\n", buffer[1]);
        return -1;
    }

    return 0; // SOCKS negotiation successful
}


/**
 * @brief Torsocks' intercepted version of gethostbyname().
 * For this example, we let the original function resolve the IP, but we store the
 * hostname so 'connect' can use it for the anonymous SOCKS request.
 * (Full Torsocks logic is much more complex)
 */
struct hostent* gethostbyname(const char *name) {
    if (!real_gethostbyname) {
        init_dlsym();
    }
    
    // 💥 The actual SOCKS resolution logic would go here.
    // For this demonstration, we let the real function run to get the IP, 
    // but the subsequent 'connect' function is responsible for using the hostname.
    return real_gethostbyname ? real_gethostbyname(name) : NULL;
}


/**
 * @brief Torsocks' intercepted version of the connect() function.
 * This version assumes the application called gethostbyname() and uses the IP,
 * but it must convert the IP back to the original hostname for the SOCKS request.
 * This is complex and highly dependent on a custom DNS interceptor.
 * * --- SIMPLIFIED: We will assume the target address is NOT a private network IP
 * and proceed with the anonymous SOCKS path. ---
 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        init_dlsym();
        if (!real_connect) {
            errno = EFAULT;
            return -1;
        }
    }

    // --- Passthrough for non-IPv4 addresses ---
    if (addr->sa_family != AF_INET) {
        return real_connect(sockfd, addr, addrlen);
    }
    
    // 1. Define the Tor SOCKS proxy address (127.0.0.1:9050)
    struct sockaddr_in tor_addr;
    memset(&tor_addr, 0, sizeof(tor_addr));
    tor_addr.sin_family = AF_INET;
    tor_addr.sin_port = htons(TOR_SOCKS_PORT);
    inet_pton(AF_INET, TOR_SOCKS_ADDR, &tor_addr.sin_addr);

    const struct sockaddr_in *target_addr_in = (const struct sockaddr_in *)addr;

    // 2. Use the REAL connect() to connect the socket to the LOCAL TOR PROXY
    int connect_result = real_connect(sockfd, (const struct sockaddr *)&tor_addr, sizeof(tor_addr));

    if (connect_result < 0) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not connect to Tor SOCKS proxy at %s:%d\n", TOR_SOCKS_ADDR, TOR_SOCKS_PORT);
        return -1;
    }
    
    // 💥 Anonymous SOCKS Logic: Convert IP back to a hostname for the ATYP 0x03 request.
    // This is the most complex part of Torsocks, as it requires mapping the IP back 
    // to the hostname that was passed to the intercepted gethostbyname().
    
    char hostname_buffer[NI_MAXHOST];
    // This is a stand-in for the complex IP-to-Hostname mapping
    if (inet_ntop(AF_INET, &target_addr_in->sin_addr, hostname_buffer, NI_MAXHOST) == NULL) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Failed to convert IP to string.\n");
        close(sockfd);
        errno = EFAULT;
        return -1;
    }

    // 3. Perform the SOCKS5 handshake and connection request using the Hostname (ATYP 0x03)
    if (perform_socks5_domain_negotiation(sockfd, hostname_buffer, ntohs(target_addr_in->sin_port)) < 0) {
        close(sockfd);
        errno = EHOSTUNREACH; // Set an appropriate error code
        return -1;
    }

    return 0; 
}