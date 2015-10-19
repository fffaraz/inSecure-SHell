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
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <errno.h>

#define PORT   "5910"
#define SECRET "<cs591secret>"
#define BUFFERSIZE 64 * 1024

static char certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n"
    "wEs=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n"
    "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n"
    "-----END RSA PRIVATE KEY-----\n";

static char dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
    "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

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
