/*
Simple server echo the client's message

* Listen to both IPv4 and IPv6
* Listen to 55580 tcp port
* Listen to 55581 udp port
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define PORT "55580"      // TCP port to listen on
#define PORT_UDP "55581"  // UDP port to listen on
#define BACKLOG 10        // Maximum number of pending connections

volatile sig_atomic_t flag = 0;

void handle_sigint(int sig) { flag = 1; }

// Get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void *tcp_server(void *arg) {
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;  // connector's address information
    socklen_t sin_size;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;      // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP
    hints.ai_flags = AI_PASSIVE;      // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return NULL;
    }

    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
            -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==
            -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        return NULL;
    }

    freeaddrinfo(servinfo);  // all done with this structure

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    printf("TCP server: waiting for connections, %s...\n", PORT);

    while (1) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
        printf("server: got connection from %s\n", s);

        // keep receiving message from the client
        // until the client close the connection
        char buf[1024];
        while (1) {
            int len = recv(new_fd, buf, sizeof buf, 0);
            if (len == -1) {
                perror("recv");
                continue;
            } else if (len == 0) {
                printf(
                    "client close the connection gracefully or the connection "
                    "is broken by network error\n\n");
                break;
            } else {
                // break if the client send "quit"
                if (strcmp(buf, "quit\n") == 0) {
                    printf("client quit the connection by sending \"quit\"\n");
                    send(new_fd, "connection quit\n", 16, 0);
                    break;
                }
                buf[len] = '\0';
                printf("received: %s\n", buf);
            }

            if (send(new_fd, buf, len, 0) == -1) {
                // Echo message back to the client
                perror("send");
            }
        }

        close(new_fd);
    }

    return NULL;
}

void *udp_server(void *arg) {
    int sockfd_udp;
    struct addrinfo hints_udp, *servinfo_udp, *p_udp;
    int rv_udp;
    struct sockaddr_storage their_addr_udp;
    socklen_t addr_len;
    int numbytes;
    char buf_udp[1024];
    char s[INET6_ADDRSTRLEN];

    memset(&hints_udp, 0, sizeof hints_udp);
    hints_udp.ai_family = AF_UNSPEC;
    hints_udp.ai_socktype = SOCK_DGRAM;
    hints_udp.ai_flags = AI_PASSIVE;

    if ((rv_udp = getaddrinfo(NULL, PORT_UDP, &hints_udp, &servinfo_udp)) !=
        0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv_udp));
        return NULL;
    }

    // loop through all the results and bind to the first we can
    for (p_udp = servinfo_udp; p_udp != NULL; p_udp = p_udp->ai_next) {
        if ((sockfd_udp = socket(p_udp->ai_family, p_udp->ai_socktype,
                                 p_udp->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd_udp, p_udp->ai_addr, p_udp->ai_addrlen) == -1) {
            close(sockfd_udp);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p_udp == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return NULL;
    }

    freeaddrinfo(servinfo_udp);

    printf("UDP listener: waiting to recvfrom, %s...\n", PORT_UDP);

    while (1) {
        addr_len = sizeof their_addr_udp;
        if ((numbytes = recvfrom(sockfd_udp, buf_udp, sizeof buf_udp, 0,
                                 (struct sockaddr *)&their_addr_udp,
                                 &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        printf("listener: got packet from %s\n",
               inet_ntop(their_addr_udp.ss_family,
                         get_in_addr((struct sockaddr *)&their_addr_udp), s,
                         sizeof s));
        buf_udp[numbytes] = '\0';
        printf("received: %s\n", buf_udp);
        // send back the message to the client
        if ((numbytes = sendto(sockfd_udp, buf_udp, numbytes, 0,
                               (struct sockaddr *)&their_addr_udp, addr_len)) ==
            -1) {
            perror("sendto");
            exit(1);
        }
    }

    return NULL;
}

int main(void) {
    signal(SIGINT, handle_sigint);
    pthread_t tid_tcp, tid_udp;

    // Create a new thread for TCP server
    if (pthread_create(&tid_tcp, NULL, tcp_server, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    // Create a new thread for UDP server
    if (pthread_create(&tid_udp, NULL, udp_server, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    while (1) {
        // sleep for 1 second
        sleep(1);
        if (flag) {
            printf("\nServer stopped by Ctrl+C\n");
            exit(0);
        }
    }

    return 0;
}
