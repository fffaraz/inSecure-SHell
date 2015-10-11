// Server (epoll)
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
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define PORT   "5910"
#define SECRET "<cs591secret>"
#define BUFFERSIZE 64 * 1024
#define MAXEVENTS  64

typedef struct
{
    int fd;
    int idx;
} EventData;

typedef union
{
    EventData d;
    __uint64_t u64;
} EventUnion;

typedef struct
{
    _Bool isvalid;
    int state;
    int socket;
    int pty;
    int timer;
    pid_t pid;
    //unsigned long bytes_recv;
    //unsigned long bytes_sent;
} Client;

#define MAXCLIENTS 100000
Client clients[MAXCLIENTS];

int new_client()
{
    static int idx = 0;
    while(clients[idx].isvalid) idx = (idx+1) % MAXCLIENTS; // FIXME
    clients[idx].isvalid = 1;
    clients[idx].state = 0;
    clients[idx].socket = 0;
    clients[idx].pty = 0;
    clients[idx].pid = 0;
    return idx;
}

void *get_in_addr(struct sockaddr *sa) // get sockaddr, IPv4 or IPv6:
{
    if(sa->sa_family == AF_INET) return &(((struct sockaddr_in*) sa)->sin_addr);
    else return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int setnonblocking(int sfd)
{
    int flags, s;
    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) { perror("fcntl"); return -1; }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) { perror("fcntl"); return -1; }
    return 0;
}

int main(void)
{
    memset(clients, 0, sizeof(Client) * MAXCLIENTS);
    signal(SIGCHLD, SIG_IGN);

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

    bind(sockfd, servinfo2->ai_addr, servinfo2->ai_addrlen);
    freeaddrinfo(servinfo); // all done with this structure
    setnonblocking(sockfd);
    listen(sockfd, 10);

    int efd = epoll_create1(0);
    struct epoll_event event;
    event.events = EPOLLIN; // | EPOLLET;
    event.data.fd = sockfd;
    epoll_ctl(efd, EPOLL_CTL_ADD, sockfd, &event);

    struct epoll_event events[MAXEVENTS];

    for(;;)
    {
        int nfd = epoll_wait(efd, events, MAXEVENTS, -1);
        for(int n = 0; n < nfd; ++n)
        {
            if(events[n].data.fd == sockfd) // listener
            {
                int idx = new_client();
                struct sockaddr_storage their_addr; // connector's address information
                socklen_t addr_size = sizeof(their_addr);
                clients[idx].socket = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
                setnonblocking(clients[idx].socket); // maybe try accept4(2)

                char ipstr[INET6_ADDRSTRLEN];
                inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), ipstr, sizeof(ipstr));
                printf("Got a connection from %s [%d]\n", ipstr, clients[idx].socket);

                const char hello_msg[] = "<rembash2>\n";
                send(clients[idx].socket, hello_msg, sizeof(hello_msg) - 1, 0);

                struct itimerspec new_value;
                struct timespec now;

                clock_gettime(CLOCK_REALTIME, &now);
                new_value.it_value.tv_sec = now.tv_sec + 10;
                new_value.it_value.tv_nsec = now.tv_nsec;
                new_value.it_interval.tv_sec = 0;
                new_value.it_interval.tv_nsec = 0;

                clients[idx].timer = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
                timerfd_settime(clients[idx].timer, TFD_TIMER_ABSTIME, &new_value, NULL);

                EventData ed;
                ed.fd = clients[idx].socket;
                ed.idx = idx;
                EventUnion eu;
                eu.d = ed;
                event.events = EPOLLIN; // | EPOLLET;
                event.data.u64 = eu.u64;
                epoll_ctl(efd, EPOLL_CTL_ADD, ed.fd, &event);

                ed.fd = clients[idx].timer;
                eu.d = ed;
                event.events = EPOLLIN | EPOLLET;
                event.data.u64 = eu.u64;
                epoll_ctl(efd, EPOLL_CTL_ADD, ed.fd, &event);
            }
            else // client socket or pty or timer
            {
                char buf[BUFFERSIZE];
                EventUnion eu;
                eu.u64 = events[n].data.u64;
                if(!clients[eu.d.idx].isvalid)
                {
                    printf("Something bad happend on file [%d] for client [%d]\n", eu.d.fd, eu.d.idx);
                    continue;
                }

                if (eu.d.fd == clients[eu.d.idx].timer)
                {
                    printf("Time out for [%d]\n", eu.d.idx);
                    if(clients[eu.d.idx].state == 0)
                    {
                        const char timer_msg[] = "TIMEOUT !\n";
                        send(clients[eu.d.idx].socket, timer_msg, sizeof(timer_msg) - 1, 0);
                        printf("Client [%d] disconnected.\n", eu.d.idx);
                        close(clients[eu.d.idx].socket);
                        clients[eu.d.idx].isvalid = 0;
                    }
                    continue;
                }

                if(clients[eu.d.idx].state == 0)
                {
                    // assert(eu.d.fd == clients[eu.d.idx].socket)
                    int nbytes = recv(eu.d.fd, buf, 255, 0); // it's not 100% guaranteed to work! must use readline.
                    buf[nbytes - 1] = '\0';
                    printf("Received %s from [%d]\n", buf, eu.d.fd);

                    if(strcmp(buf, SECRET) != 0)
                    {
                        const char secret_msg[] = "WRONG SECRET KEY !\n";
                        send(eu.d.fd, secret_msg, sizeof(secret_msg) - 1, 0);
                        printf("Shared key check failed for [%d]\n", eu.d.idx);
                        printf("Client [%d] disconnected.\n", eu.d.idx);
                        close(eu.d.fd);
                        clients[eu.d.idx].isvalid = 0;
                        continue;
                    }

                    const char ok_msg[] = "<ok>\n";
                    send(eu.d.fd, ok_msg, sizeof(ok_msg) - 1, 0);
                    clients[eu.d.idx].state = 1;

                    clients[eu.d.idx].pid = forkpty(&clients[eu.d.idx].pty, NULL, NULL, NULL);

                    if(clients[eu.d.idx].pid == 0) // child
                    {
                        close(sockfd); // child doesn't need the listener
                        close(efd); // child doesn't need epoll
                        setsid();
                        execl("/bin/bash", "bash", NULL);
                        _exit(0);
                        return 0;
                    }
                    else
                    {
                        EventData ed;
                        ed.fd = clients[eu.d.idx].pty;
                        ed.idx = eu.d.idx;
                        EventUnion eu;
                        eu.d = ed;
                        event.events = EPOLLIN; // | EPOLLET;
                        event.data.u64 = eu.u64;
                        epoll_ctl(efd, EPOLL_CTL_ADD, ed.fd, &event);
                        const char ready_msg[] = "<ready>\n";
                        send(clients[eu.d.idx].socket, ready_msg, sizeof(ready_msg) - 1, 0);
                    }
                } // if(client->state == 0)
                else // if(client->state == 1)
                {
                    int nbytes = read(eu.d.fd, buf, BUFFERSIZE);
                    printf("Received [%d] bytes from client [%d] on file [%d] \n", nbytes, eu.d.idx, eu.d.fd);
                    if(nbytes < 1)
                    {
                        printf("Client [%d] disconnected.\n", eu.d.idx);
                        close(clients[eu.d.idx].socket);
                        close(clients[eu.d.idx].pty);
                        kill(clients[eu.d.idx].pid, SIGTERM);
                        clients[eu.d.idx].isvalid = 0;
                        continue;
                    }
                    int mbytes;
                    if(eu.d.fd == clients[eu.d.idx].socket) mbytes = write(clients[eu.d.idx].pty,    buf, nbytes);
                    if(eu.d.fd == clients[eu.d.idx].pty)    mbytes = write(clients[eu.d.idx].socket, buf, nbytes);
                    if(nbytes != mbytes) printf("nbytes [%d] != mbytes [%d] \n", nbytes, mbytes);
                }
            } // if(events[n].data.fd == sockfd)
        } // for(int n = 0; n < nfd; ++n)
    } // for(;;)

    return 0;
}
