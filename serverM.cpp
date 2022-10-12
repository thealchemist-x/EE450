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

#define SERVERC_PORT_NUM    "21082"
#define SERVEREE_PORT_NUM   "23082"
#define SERVERCS_PORT_NUM   "22082"
#define MAXBUFLEN           100

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

int setupUDP(char *host_port_num){
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
    int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(HOST_IP_ADDRESS, host_port_num, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);

    return sockfd;
}

//Within tcp child socket
//queryData: data to be forwarded from client to either ServerC, ServerEE or ServerCS
int udpQuery(int sockfd, char *queryData, char *port)
{

}

int main(void){
    int tcp_sockfd, tcp_child_fd;
    int udp_sockfd;

    struct sockaddr_storage their_addr; //connector's address information
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];

    //setup tcp socket
    tcp_sockfd = setupTCP((char *)HOST_TCP_PORT_NUM);

    //setup udp socket
    udp_sockfd = setupUDP((char *)HOST_UDP_PORT_NUM);

    printf("The main server is up and running.\n");

    while(1){
        sin_size = sizeof(their_addr);
        tcp_child_fd = accept(tcp_sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if(tcp_child_fd == -1){
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof(s));
        printf("server: got connection from %s\n", s);

        if(!fork()){ //child process here
/*
            close(tcp_sockfd); //child socket doesn't need the parent-socket listener
            
            //1. This is how we send data over in TCP
            if(send(tcp_child_fd, "Hello, world!", 13, 0) == -1){
                perror("send");
            }

            //2. This is how we receive data over TCP
            recv(.)
*/

/*
            //3. We may have to do some processing from received (TCP) data before relaying

            //4. Use udpQuery(.) to send to UDP Servers (ServerC, ServerEE, ServerCS)
*/
            close(tcp_child_fd);
            exit(0);
        }

        close(tcp_child_fd); //parent continues to listen but child is done.
    }

    close(tcp_sockfd);
    return 0;
}

