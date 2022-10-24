#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <iostream>
#include <string>

#define SERVERM_IP_ADDRESS      "127.0.0.1"
#define SERVERM_TCP_PORT_NUM    "25082" // the port client will be connecting to 

#define MAXDATASIZE             1000 // max number of bytes we can get at once 
#define AUTH_COUNT              3 // authentication count

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::string getUserCredentials(){
    std::string username="", password="", combined="";
    std::cout << "Please enter the username: ";
    std::getline(std::cin,username);
    std::cout << "Please enter the password: ";
    std::getline(std::cin,password);

    //username and password separated by a space!
    combined=username+" "+password;
    return combined;
}

std::string getUsername(std::string data){
    
    int i;
    for(i=0; i<data.length(); i++){
        if(data.at(i)==' '){
            break;
        }
    }

    char username[i+1];
    memset(username, 0, sizeof(username));
    strncpy(username, data.c_str(), i);

    return std::string(username);
}

bool processAuthStatus(std::string username, char *status, int auth_count){
    int auth_status = std::stoi(status);
    if(auth_status != 2){

        if(auth_status == 0){
            printf("%s received the result of authentication using TCP over port %s. Authentication failed: Username Does not exist\n\n",
                    username.c_str(), SERVERM_TCP_PORT_NUM);
        }
        else{
             printf("%s received the result of authentication using TCP over port %s. Authentication failed: Password does not match\n\n",
                    username.c_str(), SERVERM_TCP_PORT_NUM);           
        }

        int num_tries_left = AUTH_COUNT-auth_count;
        printf("Attempts remaining: %d\n", num_tries_left);

        if(num_tries_left == 0){
            printf("Authentication Failed for 3 attempts. Client will shut down.\n");
        }
        fflush(stdout);
        return false;
    }
    else{
            printf("%s received the result of authentication using TCP over port %s. Authentication is successful\n",
                    username.c_str(), SERVERM_TCP_PORT_NUM);         
    }

    return true;
}

int setupTCP(){
    int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(SERVERM_IP_ADDRESS, SERVERM_TCP_PORT_NUM, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);

	freeaddrinfo(servinfo); // all done with this structure

    return sockfd;
}

int main(int argc, char *argv[])
{
	int tcp_sockfd, numbytes;  
	char buf[MAXDATASIZE];
    int auth_count=AUTH_COUNT;
    bool isAuthOk = false;

    tcp_sockfd = setupTCP();
    printf("The client is up and running\n");

    // 0. Get username and password from user
    for(int i = 0; i < AUTH_COUNT; ++i){
        std::string userLoginDetails = getUserCredentials();

        // 1. Sending username and password to ServerM (use send(.) )
        if((numbytes = send(tcp_sockfd, userLoginDetails.c_str(), userLoginDetails.length(),0)== -1)){
            perror("send");
            exit(1);
        }

        printf("%s sent an authentication request to the main server.\n", getUsername(userLoginDetails).c_str());

        // 2. Receiving from ServerM
        memset(buf, 0, sizeof(buf));
        if ((numbytes = recv(tcp_sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
            perror("recv");
            exit(1);
        }

        buf[numbytes] = '\0';

        isAuthOk = processAuthStatus(getUsername(userLoginDetails), buf, i+1);

        if(isAuthOk){
            break;
        }
    }

    if(!isAuthOk){
        //Inform ServerM to close child-tcp
        sprintf(buf,"exit");
        if((numbytes = send(tcp_sockfd, buf, strlen(buf),0)== -1)){
            perror("send");
            exit(1);
        }
    }

	close(tcp_sockfd);

	return 0;
}
