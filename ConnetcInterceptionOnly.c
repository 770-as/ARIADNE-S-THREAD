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

// --- Configuration Constants (Simplified) ---
#define TOR_SOCKS_ADDR "127.0.0.1"
#define TOR_SOCKS_PORT 9050

// --- Function Pointer for the Original connect() ---
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;

// --- SOCKS5 Negotiation Data Structures (Simplified) ---
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_IPV4 0x01 // Using IP address, assuming local DNS resolution
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
}

/**
 * @brief Sends a SOCKS5 CONNECT command using the target IP and checks the reply.
 * @param sockfd The socket already connected to 127.0.0.1:9050.
 * @param target_addr The extracted target IPv4 address structure.
 * @return 0 on SOCKS success, -1 on failure.
 */
int perform_socks5_negotiation(int sockfd, const struct sockaddr_in *target_addr) {
    char buffer[256];
    size_t bytes_read;

    // 1. Initial Handshake
    if (send(sockfd, socks5_initial_handshake, sizeof(socks5_initial_handshake), 0) < 0) {
        return -1;
    }
    bytes_read = recv(sockfd, buffer, 2, 0);
    if (bytes_read != 2 || memcmp(buffer, socks5_handshake_success, 2) != 0) {
        fprintf(stderr, "TORSOCKS_WRAPPER: SOCKS handshake failed.\n");
        return -1;
    }

    // 2. Command Request: Build the CONNECT request to the TARGET IP (ATYP 0x01)
    if (target_addr->sin_family != AF_INET) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Only IPv4 targets supported in this example.\n");
        return -1;
    }
    
    // SOCKS5 CONNECT request structure: Ver | Cmd | RSV | ATYP | DST.ADDR | DST.PORT
    buffer[0] = SOCKS_VERSION;
    buffer[1] = SOCKS_CMD_CONNECT;
    buffer[2] = 0x00;           // Reserved
    buffer[3] = SOCKS_ATYP_IPV4; // ATYP: IPv4 Address
    memcpy(buffer + 4, &target_addr->sin_addr.s_addr, 4); // Target IP
    memcpy(buffer + 8, &target_addr->sin_port, 2);      // Target Port

    if (send(sockfd, buffer, 10, 0) < 0) {
        return -1;
    }

    // 3. Receive final SOCKS reply
    bytes_read = recv(sockfd, buffer, 10, 0); // Read at least the 10-byte header
    if (bytes_read < 0 || buffer[1] != SOCKS_REPLY_SUCCESS) {
        fprintf(stderr, "TORSOCKS_WRAPPER: SOCKS connection request failed (Reply: 0x%02x).\n", buffer[1]);
        return -1;
    }

    return 0; // SOCKS negotiation successful
}

/**
 * @brief Torsocks' intercepted version of the connect() function.
 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        init_dlsym();
        if (!real_connect) {
            errno = EFAULT;
            return -1;
        }
    }

    // --- Passthrough for non-IPv4 addresses (e.g., AF_UNIX) ---
    if (addr->sa_family != AF_INET) {
        return real_connect(sockfd, addr, addrlen);
    }
    
    // 1. Define the Tor SOCKS proxy address (127.0.0.1:9050)
    struct sockaddr_in tor_addr;
    memset(&tor_addr, 0, sizeof(tor_addr));
    tor_addr.sin_family = AF_INET;
    tor_addr.sin_port = htons(TOR_SOCKS_PORT);
    inet_pton(AF_INET, TOR_SOCKS_ADDR, &tor_addr.sin_addr);

    // 2. Save the intended target address (as IPv4 struct)
    const struct sockaddr_in *target_addr_in = (const struct sockaddr_in *)addr;

    // 3. Use the REAL connect() to connect the socket to the LOCAL TOR PROXY
    int connect_result = real_connect(sockfd, (const struct sockaddr *)&tor_addr, sizeof(tor_addr));

    if (connect_result < 0) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not connect to Tor SOCKS proxy at %s:%d\n", TOR_SOCKS_ADDR, TOR_SOCKS_PORT);
        return -1;
    }

    // 4. Perform the SOCKS5 handshake and connection request
    if (perform_socks5_negotiation(sockfd, target_addr_in) < 0) {
        close(sockfd);
        errno = EHOSTUNREACH; // Set an appropriate error code
        return -1;
    }

    return 0; 
}