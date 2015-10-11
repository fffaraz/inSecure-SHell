// Server (fork, select)
// Faraz Fallahi [fffaraz@gmail.com]

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define PORT   "5910"
#define SECRET "<cs591secret>"
#define BUFFERSIZE 64 * 1024

void sigchld_handler(int s)
{
    (void) s;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    printf("Connection closed.\n");
}

void *get_in_addr(struct sockaddr *sa) // get sockaddr, IPv4 or IPv6:
{
    if(sa->sa_family == AF_INET) return &(((struct sockaddr_in*) sa)->sin_addr);
    else return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void handle_client(int sockfd)
{
    const char *hello_msg = "<rembash2>\n";
    int hello_len = strlen(hello_msg);
    int bytes_sent = send(sockfd, hello_msg, hello_len, 0);
    if(bytes_sent == -1 || bytes_sent != hello_len)
    {
        perror("send hello_msg");
        return;
    }

    char shared_key[256];
    int nbytes = recv(sockfd, shared_key, 255, 0); // it's not 100% guaranteed to work! must use readline.
    shared_key[nbytes - 1] = '\0';
    printf("Received %s from [%d]\n", shared_key, sockfd);

    if(strcmp(shared_key, SECRET) != 0)
    {
        printf("Shared key check failed for [%d]\n", sockfd);
        return;
    }

    const char *ok_msg = "<ok>\n";
    send(sockfd, ok_msg, strlen(ok_msg), 0);

    /*
    dup2(sockfd, STDIN_FILENO);
    dup2(sockfd, STDOUT_FILENO);
    dup2(sockfd, STDERR_FILENO);
    */

    int master;
    pid_t pid;

    signal(SIGCHLD, SIG_IGN);
    pid = forkpty(&master, NULL, NULL, NULL);

    if(pid < 0)
    {
        const char *error_msg = "forkpty failed\n";
        perror(error_msg);
        send(sockfd, error_msg, strlen(error_msg), 0);
        return;
    }

    if(pid == 0) // child
    {
        //execl("/bin/bash", "bash", "--noediting", "-i", NULL);
        execl("/bin/bash", "bash", NULL);
    }
    else
    {
        const char *ready_msg = "<ready>\n";
        send(sockfd, ready_msg, strlen(ready_msg), 0);

        /*
        // remove the echo
        struct termios tios;
        tcgetattr(master, &tios);
        tios.c_lflag &= ~(ECHO | ECHONL);
        tcsetattr(master, TCSAFLUSH, &tios);
        */

        int maxfd = master > sockfd ? master : sockfd;

        for(;;)
        {
            char buf[BUFFERSIZE];

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(master, &readfds);
            FD_SET(sockfd, &readfds);

            if(select(maxfd + 1, &readfds, NULL, NULL, NULL) == -1)
            {
                perror("select");
                return;
            }

            if(FD_ISSET(master, &readfds))
            {
                nbytes = read(master, buf, BUFFERSIZE);
                if(nbytes < 1)
                {
                    //perror("master closed");
                    break;
                }
                send(sockfd, buf, nbytes, 0);
            }

            if(FD_ISSET(sockfd, &readfds))
            {
                nbytes = recv(sockfd, buf, BUFFERSIZE, 0);
                if(nbytes < 1)
                {
                    //perror("sockfd closed");
                    break;
                }
                write(master, buf, nbytes);
            }
        }
    }
}

int main(void)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP. "| AI_ADDRCONFIG"
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_family = AF_INET6; // IPv4 addresses will be like ::ffff:127.0.0.1

    struct addrinfo *servinfo;
    getaddrinfo(NULL, PORT, &hints, &servinfo);

#if DEBUG
    for(struct addrinfo *p = servinfo; p != NULL; p = p->ai_next)
    {
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(p->ai_family, get_in_addr(p->ai_addr), ipstr, sizeof(ipstr)); // convert the IP to a string
        printf(" %s\n", ipstr);
    }
#endif

    struct addrinfo *servinfo2 = servinfo; //servinfo->ai_next;
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(servinfo2->ai_family, get_in_addr(servinfo2->ai_addr), ipstr, sizeof(ipstr));
    printf("Waiting for connections on [%s]:%s\n", ipstr, PORT);

    int sockfd = socket(servinfo2->ai_family, servinfo2->ai_socktype, servinfo2->ai_protocol);

#if 1
    int yes_1 = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes_1, sizeof(yes_1));
#endif

#if 0 // disabling the Nagle algorithm  #include <netinet/tcp.h>
    int yes_2 = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &yes_2, sizeof(yes_2));
#endif

#if 0
    if (addr->ai_family == AF_INET6) {
        int yesno = 0;
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &yesno, sizeof(yesno));
    }
#endif

    bind(sockfd, servinfo2->ai_addr, servinfo2->ai_addrlen);

    freeaddrinfo(servinfo); // all done with this structure

    listen(sockfd, 10);

#if 1
    struct sigaction sa;
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
#else
    signal(SIGCHLD, SIG_IGN);
#endif

    for(;;)
    {
        struct sockaddr_storage their_addr; // connector's address information
        socklen_t addr_size = sizeof(their_addr);
        int new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);

        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), ipstr, sizeof(ipstr));
        printf("Got a connection from %s [%d]\n", ipstr, new_fd);

        if(!fork()) // if this is the child process
        {
            close(sockfd); // child doesn't need the listener
            setsid();
            handle_client(new_fd);
            close(new_fd);
            _exit(0);
            return 0;
        }

        close(new_fd);  // parent doesn't need this
    }

    return 0;
}
