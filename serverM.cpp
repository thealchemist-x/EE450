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
#include <string>
#include <iostream>
#include <algorithm>

#define HOST_IP_ADDRESS     "127.0.0.1"
#define HOST_UDP_PORT_NUM   "24082"
#define HOST_TCP_PORT_NUM   "25082"
#define BACKLOG             10

#define SERVERC_PORT_NUM    "21082"
#define SERVEREE_PORT_NUM   "23082"
#define SERVERCS_PORT_NUM   "22082"
#define MAXBUFLEN           1000
#define AUTH_SUCCESS        2
#define COURSE_LEN          5

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

int setupTCP(){
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sigaction sa;
    int yes=1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if((rv = getaddrinfo(HOST_IP_ADDRESS, HOST_TCP_PORT_NUM, &hints, &servinfo)) != 0) {
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

int setupUDP(){
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
    int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(HOST_IP_ADDRESS, HOST_UDP_PORT_NUM, &hints, &servinfo)) != 0) {
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

int findSpaceIndex(std::string data){
    
    for(int i=0; i<data.length(); i++){
        if(data.at(i)==' '){
            return i;
        }
    }
    
    //Else something is bad..
    perror("Invalid user credentials");
    exit(1);
}

char encryptUpperCase(char data){
    char temp = data + 4;

    if(int(temp) <= int('Z')){
        data=temp;
    }
    else{
        data=temp-26;
    }

    return data;
}

char encryptLowerCase(char data){
    char temp = data + 4;

    if(int(temp) <= int('z')){
        data=temp;
    }
    else{
        data=temp-26;
    }

    return data;
}

char encryptDigit(char data){
    char temp = data + 4;

    if(int(temp) <= int('9')){
        data=temp;
    }
    else{
        data=temp-10;
    }

    return data;
}

void implementEncryption(char *data){
    for(int i=0; i<strlen(data); i++){

        if(isupper(data[i])){
            data[i]=encryptUpperCase(data[i]);
        }
        else if(islower(data[i])){
            data[i]=encryptLowerCase(data[i]);
        }
        else if(isdigit(data[i])){
            data[i]=encryptDigit(data[i]);
        }
    }
}

std::string encryptData(std::string data){

    int spaceIdx = findSpaceIndex(data);

    char username[spaceIdx+1];
    char password[data.length()-spaceIdx];
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));
    
    strncpy(username, data.c_str(), spaceIdx);
    std::copy(data.c_str()+spaceIdx+1, data.c_str()+spaceIdx+1+sizeof(password), password);

    implementEncryption(username);
    implementEncryption(password);
    
    return std::string(username) + " " + std::string(password);
}

std::string getUsername(std::string data){
    int spaceIdx = findSpaceIndex(data);
    char username[spaceIdx+1];
    memset(username, 0, sizeof(username));

    strncpy(username, data.c_str(), spaceIdx);

    return std::string(username);
}

//Within tcp child socket
//sendData: data to be forwarded from client to either ServerC, ServerEE or ServerCS
void sendUDPServer(int sockfd, const char *sendData, char *port, char *udp_recv)
{
    int numbytes;
    int rv;
    struct addrinfo hints, *servinfo, *p;
	socklen_t addr_len;
	memset(&hints, 0, sizeof hints);
    char recv_data[MAXBUFLEN];

    //Destination IP and Destination Port (note: ServerC has same IP addr as ServerM)
    if ((rv = getaddrinfo(HOST_IP_ADDRESS, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}

    for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}
        break;
    }

    if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return;
	}

    //UDP send portion
    if ((numbytes = sendto(sockfd, sendData, strlen(sendData), 0,
			 p->ai_addr, p->ai_addrlen)) == -1) {
		perror("talker: sendto");
		exit(1);
	}

    if (strcmp(port, SERVERC_PORT_NUM)==0) {
		printf("The main server sent an authentication request to serverC\n");
    }

    //UDP receive portion
    int recv_bytes;

    recv_bytes = recvfrom(sockfd, recv_data, sizeof(recv_data), 0, NULL, NULL);
    if(recv_bytes == -1) {
        perror("recvfrom");
        exit(1);
    }
    recv_data[recv_bytes] = '\0';

    strncpy(udp_recv, recv_data, strlen(recv_data));

    if(strcmp(port, SERVERC_PORT_NUM) == 0){
        printf("The main server received the result of the authentication request from ServerC using UDP over %s\n", HOST_UDP_PORT_NUM);
    }
}

void convertToLowerKey(char *data, const int sz){
    int i=0;
    while(i<sz){
        if(!islower(data[i])){
            data[i]=tolower(data[i]);
        }
        i++;
        data++;
    }
}

void processQueryRequest(int sockfd, std::string &username, const char *data, const int sz, const char *port, char *udp_recv){
    char courseID[COURSE_LEN+1];
    char courseQueryKey[sz-COURSE_LEN];
    memset(courseID, 0, sizeof(courseID));
    memset(courseQueryKey, 0, sizeof(courseQueryKey));

    strncpy(courseID, data, COURSE_LEN);
    std::copy(data+COURSE_LEN+1, data+COURSE_LEN+1+sizeof(courseQueryKey), courseQueryKey);
    convertToLowerKey(courseQueryKey, sizeof(courseQueryKey));

    printf("The main server received from %s to query course %s about %s using TCP over port %s.\n", username.c_str(), courseID, courseQueryKey, HOST_TCP_PORT_NUM);

    /* Phase 3B from here on*/
}

void initialize(char *s, char *buf, char *udp_recv, char *portstr){
    memset(s, 0, INET6_ADDRSTRLEN);
    memset(buf, 0, MAXBUFLEN);
    memset(udp_recv, 0, MAXBUFLEN);
    memset(portstr, 0, NI_MAXSERV);
}

int main(void){
    int tcp_sockfd, tcp_child_fd, numbytes;
    int udp_sockfd;

    struct sockaddr_storage their_addr; //connector's address information
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    char buf[MAXBUFLEN];
    char udp_recv[MAXBUFLEN];
    char portstr[NI_MAXSERV];
    std::string username="";

    //Initialize buffers
    initialize(s, buf, udp_recv, portstr);

    //setup tcp socket
    tcp_sockfd = setupTCP();

    //setup udp socket
    udp_sockfd = setupUDP();

    printf("The main server is up and running.\n");
    while(1){
        sin_size = sizeof(their_addr);
        tcp_child_fd = accept(tcp_sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if(tcp_child_fd == -1){
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof(s));
        int rc= getnameinfo((struct sockaddr *) &their_addr, sin_size, s, sizeof(s), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
        if(rc!=0){ 
            perror("getnameinfo failed!");
            exit(1);
        }

        if(!fork()){ //child process here
            bool isAuthOk=false;
            close(tcp_sockfd); //child socket doesn't need the parent-socket listener

            while(1){
                memset(buf, 0, sizeof(buf));
                if((numbytes = recv(tcp_child_fd, buf, MAXBUFLEN-1, 0)) == -1){
                    perror("recv");
                    exit(1);
                }

                buf[numbytes]='\0';

                //If Client is exiting and the child-tcp-socket is no longer needed
                if(strcmp(buf, "exit")==0) {printf("Breaking out of ServerM-Child-While(1)\n"); break;}

                if(!isAuthOk){
                    username = getUsername(std::string(buf));
                    printf("The main server received the authentication for %s using TCP over port %s\n", username.c_str(), HOST_TCP_PORT_NUM);

                    //Encrypt and authenticate with ServerC
                    std::string encryptedUserLogin = encryptData(std::string(buf));
                    sendUDPServer(udp_sockfd, encryptedUserLogin.c_str(), SERVERC_PORT_NUM, udp_recv);
                

                    //Update Authentication Status
                    if(std::stoi(udp_recv) == AUTH_SUCCESS){ isAuthOk=true; }

                    //Return status to client
                    memset(buf, 0, sizeof(buf));
                    sprintf(buf, "%s\n", udp_recv);
                    if((numbytes = send(tcp_child_fd, buf, strlen(buf),0)== -1)){
                        perror("send");
                        exit(1);
                    }

                    printf("The main server sent the authentication result to the client\n");
                }
                else{
                    //printf("(auth-success) %s,len=%d\n", buf, strlen(buf));
                    processQueryRequest(udp_sockfd, username, buf, strlen(buf), SERVERC_PORT_NUM, udp_recv);
                }
            }
            close(tcp_child_fd);
            exit(0);
        }

        close(tcp_child_fd); //parent continues to listen but child is done.
    }

    close(tcp_sockfd); //Finally close parent socket
    return 0;
}

