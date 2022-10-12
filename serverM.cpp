#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#define HOST_IP_ADDRESS     "127.0.0.1"
#define HOST_UDP_PORT_NUM   "24082"
#define HOST_TCP_PORT_NUM   "25082"
#define BACKLOG             10

void sigchld_handler(int s){
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;
    
    while(waitpid(-1, NULL, WNOHANG) > 0);
    
    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) { //IPv4
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    //IPv6
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int setupTCP(char *host_port_num){
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sigaction sa;
    int yes=1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((rv = getaddrinfo(HOST_IP_ADDRESS, host_port_num, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
            perror("setsockopt");
            exit(1);
        }
        if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if(p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if(listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }
    
    sa.sa_handler = sigchld_handler; // reap all dead processes sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1); 
    }

    return sockfd;
}

int main(void){
    int tcp_sockfd, tcp_child_fd;
    int udp_sockfd;

    struct sockaddr_storage their_addr; //connector's address information
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];

    //setup tcp socket
    tcp_sockfd = setupTCP(HOST_TCP_PORT_NUM);

    while(1){
        sin_size = sizeof(their_addr);
        tcp_child_fd = accept(tcp_sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if(tcp_child_fd == -1){
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof(s));
        printf("server: got connection from %s\n", s);
/*
        if(!fork()){ //child process here
            close(tcp_sockfd); //child socket doesn't need the parent-socket listener
            
            //This is how we send data over in TCP

            if(send(tcp_child_fd, "Hello, world!", 13, 0) == -1){
                perror("send");
            }
            close(tcp_child_fd);
            exit(0);
        }
*/
        close(tcp_child_fd); //parent continues to listen but child is done.
    }

    return 0;
}

