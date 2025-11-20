#define _GNU_SOURCE  // Required for dlsym and RTLD_NEXT
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
/*arpa/inet library is a standard header file unix for network programming particularly for IP addresses. To define
functions that allow you to convert between different representations of ip addresses and data types. Functions are
htonl() host to network long, htons() short, ntohl() long, ntohs() network to host short. The sys/socket library is
a crucial standard header file using the berkeley sockets API. The structures are struct sockaddr, socklen_t and 
socket(), bind(), listen(), accept(), connect(), send(), recv(), sendto(), recvfrom(). AF_INET, AF_INET6, AF_UNIX
SOCK_STREAM, SOCK_DGRAM, SOCK_RAW. dlfcn.h library providess a set of functions to perform dynamic loading and 
linking of shared libraries at runtime. Functions are dlopen() load the specified shared object file .so into the 
calling process's memory space and returns a handle to it, dlsym() takes the library handle and a symbol name and 
returns the memory address of that symbol, dlerror() returns a human readable string describing the last error that
occurred during any dlfcn.h function call, dlclose() decrements the reference count of the dynamic library and 
unloads it from memory when the count reaches zero. As seen in previous discussions, the dlfcn.h library is also
the foundation for powerful technique like function interception using the RTLD_NEXT special handle with dlsym().
This allows a loaded wrapper libary to find and call the original system function after performing its own custom
logic. */
// --- Configuration Constants (Simplified) ---
#define TOR_SOCKS_ADDR "127.0.0.1"
#define TOR_SOCKS_PORT 9050
// --- Function Pointer for the Original connect() ---
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;
// --- SOCKS5 Negotiation Data Structures (Simplified) ---
// SOCKS Request Command
#define SOCKS_CMD_CONNECT 0x01
// SOCKS Address Type: Domain Name (to force remote DNS resolution)
#define SOCKS_ATYP_DOMAINNAME 0x03
// SOCKS Version
#define SOCKS_VERSION 0x05
// Simplified SOCKS5 Initial Handshake Packet (Version + 1 Method: No Auth)
//It defines an array of bytes representing the initial handshake message sent by a client to a SOCKS5 proxy server
//(tor daemon), 0x05 specifies the SOCKS protocol version used, 0x01 indicates how many authentication methods the 
//client is offering to the server which is one in this case. 0x00 is the authentication method being offered which
//corresponds to No Authentication Required. 
const char socks5_initial_handshake[] = {0x05, 0x01, 0x00}; // Ver | Nmethods | Method (No Auth)
// Expected SOCKS5 Handshake Success Reply
const char socks5_handshake_success[] = {0x05, 0x00};      // Ver | Method (No Auth)
// Simplified SOCKS5 Reply Code: Success
#define SOCKS_REPLY_SUCCESS 0x00
/**
 * @brief Initialize the function pointers for real system calls.
 */
static void init_dlsym() __attribute__((constructor));//it is a function declaration combined with a GNU compiler
//extension used in .so files on unix-like systems.__attribute__((constructor)) is a gcc function attribute that 
//modifies the standard behavior of the function. The init_dlsym() function is meant to initialize the function 
//pointers using dlsym(RTLD_NEXT,...). The constructor attribute guarantees that init_dlsym() runs at the perfect 
//time: right after the library is loaded but before any other intercepted function is called by the main application.

static void init_dlsym() {
    // Look up the address of the real connect() function in the next loaded library (libc) 
    //LD_PRELOAD environment variable is processed and takes effect very early in a program's execution lifecycle
    //during the phase known as dynamic linking. LD_PRELOAD is read and acted upon by the dynamic linker/loader
    //before the main program starts executing the main() function. 
    real_connect = dlsym(RTLD_NEXT, "connect");
    if (!real_connect) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not find real connect() using dlsym.\n");
        // Exit or handle error gracefully in a real implementation
    }
}
/**
 * @brief Sends a SOCKS5 CONNECT command to the proxy and checks the reply.
 * @param sockfd The socket already connected to 127.0.0.1:9050.
 * @param target_addr The extracted target address structure.
 * @return 0 on SOCKS success, -1 on failure.
 */
int perform_socks5_negotiation(int sockfd, const struct sockaddr_in *target_addr) {
    char buffer[256];
    size_t bytes_read;
    // 1. Initial Handshake: Send SOCKS5 version and No-Auth method
    // In a real implementation, this would use a safer send/recv loop
    if (send(sockfd, socks5_initial_handshake, sizeof(socks5_initial_handshake), 0) < 0) {
        return -1;
    }
    // 2. Initial Handshake: Receive proxy reply
    bytes_read = recv(sockfd, buffer, 2, 0);              
    if (bytes_read != 2 || memcmp(buffer, socks5_handshake_success, 2) != 0) {
        fprintf(stderr, "TORSOCKS_WRAPPER: SOCKS handshake failed.\n");
        return -1;
    }
    // 3. Command Request: Build the CONNECT request to the TARGET (Domain Name or IP)
    // NOTE: This simplified example will only handle IPv4 target addresses.
    if (target_addr->sin_family != AF_INET) {
        fprintf(stderr, "TORSOCKS_WRAPPER: Only IPv4 targets supported in this example.\n");
        return -1;
    }    
    // SOCKS5 CONNECT request structure: Ver | Cmd | RSV | ATYP | DST.ADDR | DST.PORT
    buffer[0] = SOCKS_VERSION;
    buffer[1] = SOCKS_CMD_CONNECT;
    buffer[2] = 0x00; // Reserved
    buffer[3] = 0x01; // ATYP: IPv4 Address (in a real version, DNS would be used here)
    memcpy(buffer + 4, &target_addr->sin_addr.s_addr, 4); // Target IP
    memcpy(buffer + 8, &target_addr->sin_port, 2);      // Target Port

    // Send the CONNECT request
    if (send(sockfd, buffer, 10, 0) < 0) {
        return -1;
    }
    // 4. Receive final SOCKS reply
    // Reply structure: Ver | Rep (Status) | RSV | ATYP | BND.ADDR | BND.PORT
    bytes_read = recv(sockfd, buffer, 10, 0);
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
    // 1. Check if the function pointer is initialized
    if (!real_connect) {
        init_dlsym();
        if (!real_connect) {
            // Fall back to original connect if lookup fails (or fail hard)
            errno = EFAULT;
            return -1;
        }
    }

    // 2. Define the Tor SOCKS proxy address (127.0.0.1:9050)
    //Declares a variable to hold the Tor daemon's local IP and port. This is the address the socket will actually 
    //connect to in Phase 1. The struct sockaddr is defined in the <sys/socket.h> header file and typically looks
    //something like this: sa_family_t sa_family /AF_INET, AF_INET6 and sa_data[14] /protocol-specific address like
    //ip address and port number. The struct sockaddr is used by core socket functions like bind(), connect() and
    //accept() because it allows these functions to remain protocol-agnostic because you don't need to specify what
    //is inside that structure you just need to call the structure. Since sa_data is a blob of bytes you rarely use
    //struct sockaddr directly.  
    struct sockaddr_in tor_addr;
    memset(&tor_addr, 0, sizeof(tor_addr));
    tor_addr.sin_family = AF_INET;
    tor_addr.sin_port = htons(TOR_SOCKS_PORT);
    inet_pton(AF_INET, TOR_SOCKS_ADDR, &tor_addr.sin_addr);

    // 3. Save the intended target address (for SOCKS negotiation)
    if (addr->sa_family != AF_INET) {
        // Torsocks handles IPv6, Unix sockets, etc., but this example skips them.
        errno = EAFNOSUPPORT; // Application requested unsupported family
        return -1;
    }
    const struct sockaddr_in *target_addr_in = (const struct sockaddr_in *)addr;
    // 4. Use the REAL connect() to connect the socket to the LOCAL TOR PROXY
    int connect_result = real_connect(sockfd, (const struct sockaddr *)&tor_addr, sizeof(tor_addr));

    if (connect_result < 0) {
        // Tor daemon is likely not running or inaccessible
        fprintf(stderr, "TORSOCKS_WRAPPER: Could not connect to Tor SOCKS proxy at %s:%d\n", TOR_SOCKS_ADDR, TOR_SOCKS_PORT);
        return -1;
    }

    // 5. Perform the SOCKS5 handshake and connection request
    if (perform_socks5_negotiation(sockfd, target_addr_in) < 0) {
        // The SOCKS negotiation failed (e.g., Tor couldn't reach the target)
        // Clean up the socket (close) and return error
        close(sockfd);
        errno = EHOSTUNREACH; // Set an appropriate error code
        return -1;
    }

    // 6. Success: The application is now connected to the Tor network exit node
    return 0; 
}