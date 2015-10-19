// Client
// Faraz Fallahi [fffaraz@gmail.com]

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <s2n.h>

#define PORT   "5910"
#define BUFFERSIZE 64 * 1024

struct termios saved_attributes;
void reset_input_mode()
{
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_attributes);
}

void sigint_handler(int signum)
{
   printf("\n\nCaught signal: %d\n\n", signum);
   exit(signum);
}

void print_addrinfo(struct addrinfo *input)
{
    int addr_i = 0;
    for(struct addrinfo *p = input; p != NULL; p = p->ai_next)
    {
        char *ipver;
        void *addr;

        // get the pointer to the address itself, different fields in IPv4 and IPv6
        if (p->ai_family == AF_INET)
        {
            ipver = "IPv4";
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        else
        {
            ipver = "IPv6";
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr)); // convert the IP to a string
        printf("%2d. %s: %s\n", ++addr_i, ipver, ipstr);
    }
}

int main(int argc, char **argv)
{
    if(argc != 2)
    {
        fprintf(stderr,"usage: %s hostname\n", argv[0]);
        return 1;
    }

    signal(SIGINT, sigint_handler);

    printf("Looking up addresses for %s ...\n", argv[1]);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *dnsres;
    int status_1 = getaddrinfo(argv[1], PORT, &hints, &dnsres);
    if(status_1 != 0)
    {
        fprintf(stderr, "dns lookup failed: %s\n", gai_strerror(status_1));
        return 2;
    }

    print_addrinfo(dnsres);

    printf("Connecting to %s ...\n", "the server");
    int sockfd = socket(dnsres->ai_family, dnsres->ai_socktype, dnsres->ai_protocol);

    if(connect(sockfd, dnsres->ai_addr, dnsres->ai_addrlen) != 0)
    {
        perror("connect");
        return 3;
    }
    printf("Connected.\n");

    freeaddrinfo(dnsres); // frees the memory that was dynamically allocated for the linked lists by getaddrinfo

    s2n_init();
    
    struct s2n_config *config = s2n_config_new();
    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
    s2n_config_set_status_request_type(config, type);

    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    s2n_connection_set_config(conn, config);
    s2n_connection_set_fd(conn, sockfd);

    s2n_blocked_status blocked;
    do {
        if (s2n_negotiate(conn, &blocked) < 0) {
            fprintf(stderr, "Failed to negotiate: '%s' %d\n", s2n_strerror(s2n_errno, "EN"), s2n_connection_get_alert(conn));
            exit(1);
        }
    } while (blocked);

    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        exit(1);
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        exit(1);
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        exit(1);
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        exit(1);
    }
    printf("Client hello version: %d\n", client_hello_version);
    printf("Client protocol version: %d\n", client_protocol_version);
    printf("Server protocol version: %d\n", server_protocol_version);
    printf("Actual protocol version: %d\n", actual_protocol_version);

    if (s2n_get_server_name(conn)) {
        printf("Server name: %s\n", s2n_get_server_name(conn));
    }
    if (s2n_get_application_protocol(conn)) {
        printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %d\n", length);
    }

    printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    char buf[BUFFERSIZE + 1];
    int bytes_read, bytes_written;

    // Make sure stdin is a terminal.
    if (!isatty(STDIN_FILENO))
    {
        fprintf(stderr, "Not a terminal.\n");
        exit(EXIT_FAILURE);
    }

    // Save the terminal attributes so we can restore them later.
    tcgetattr(STDIN_FILENO, &saved_attributes);
    atexit(reset_input_mode);

    // Set the funny terminal modes.
    struct termios tattr;
    tcgetattr(STDIN_FILENO, &tattr);
    tattr.c_lflag &= ~(ICANON | ECHO); // Clear ICANON and ECHO.
    tattr.c_cc[VMIN] = 1;
    tattr.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);

    fd_set master, readfds;
    FD_ZERO(&master);
    FD_SET(STDIN_FILENO, &master);
    FD_SET(sockfd, &master);

    for(;;)
    {
        readfds = master;
        select(sockfd + 1, &readfds, NULL, NULL, NULL);
        if(FD_ISSET(STDIN_FILENO, &readfds))
        {
            bytes_read = read(STDIN_FILENO, buf, BUFFERSIZE);
            if(bytes_read < 1) break;
            char *buf_ptr = buf;
            int bytes_available = bytes_read;
            do
            {
                bytes_written = s2n_send(conn, buf_ptr, bytes_available, &blocked);
                if(bytes_written < 0) break;
                bytes_available -= bytes_written;
                buf_ptr += bytes_written;
            } while(bytes_available || blocked);
        }
        if(FD_ISSET(sockfd, &readfds))
        {
            do
            {
                bytes_read = s2n_recv(conn, buf, BUFFERSIZE, &blocked);
                if(bytes_read < 1) break;
                write(STDOUT_FILENO, buf, bytes_read);
            } while(blocked);
        }
        //if(nbytes != mbytes) printf("nbytes [%d] != mbytes [%d] \n", nbytes, mbytes);
    }

    close(sockfd);
    s2n_connection_free(conn);
    s2n_config_free(config);
    s2n_cleanup();
    printf("\nBYE!\n");
    return 0;
}
