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
#include <map>
#include <iostream>
#include <algorithm>

#define HOST_IP_ADDRESS         "127.0.0.1"
#define HOST_UDP_PORT_NUM       "21082"

#define SERVERM_UDP_PORT_NUM    "24082"
#define MAXBUFLEN               100

#define CREDENTIALS             "cred.txt"

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int findIndex(char *buf, char target){
    int idx=-1;
    while(*buf!=target){
        idx++;
        buf++;
    }
    
    //Return buf to original index
    buf-=idx;
    return idx;
}

void loadCredentials(std::map<std::string, std::string> &credDB){
    //Open file
    FILE *fp = fopen(CREDENTIALS, "r");
    if(fp == NULL){
        fprintf(stderr, "Error opening %s\n", CREDENTIALS);
        exit(-1);
    }

    //Access file
    char buf[1000];
    memset(buf, 0, sizeof(buf));
    while(fgets(buf, sizeof(buf), fp) != NULL){

        //Remove newline to make sure password length will be matched
        int newLineIdx = strcspn(buf,"\n");
        if(newLineIdx<strlen(buf)){buf[newLineIdx-1]='\0';}

        //Find the index that separates username and password
        int commaIdx = findIndex(buf, ',');
        if(commaIdx==-1){
            fprintf(stderr, "Loading cred failed. Error detected in cred.txt\n");
            exit(-1);
        }

        //Separate buf into username and password
        char username[commaIdx+2];
        char password[strlen(buf)-commaIdx];
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));

        strncpy(username, buf, commaIdx+1);
        std::copy(buf+commaIdx+2, buf+commaIdx+2+sizeof(password), password);

        //Store username and password in map
        credDB[username]=password;
    }
}

int validateUserLogin(std::map<std::string, std::string> &credDB, std::string username, std::string password){
    
    if(credDB.find(username) == credDB.end()){
        return 0; //no username
    }
    else if(strcmp(password.c_str(), credDB.find(username)->second.c_str()) != 0){
        return 1; //password does not match
    }
 
    return 2; //success
}

int authenticateUser(std::map<std::string, std::string> &credDB, std::string data){
    char msg[data.length()+1];
    strncpy(msg, data.c_str(), data.length());
    int spaceIdx = findIndex(msg, ' ');

    char username[spaceIdx+2];
    char password[data.length()-spaceIdx];
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));

    //Copy into username and password
    strncpy(username, data.c_str(), spaceIdx+1);
    std::copy(data.c_str()+spaceIdx+2, data.c_str()+spaceIdx+0+sizeof(password), password);
    
    int status = validateUserLogin(credDB, std::string(username), std::string(password));

    return status;
}

void sendUDPServer(int sockfd, const char *sendData, char *port)
{
    int numbytes;
    int rv;
    struct addrinfo hints, *servinfo, *p;
	socklen_t addr_len;
	memset(&hints, 0, sizeof hints);

    //Destination IP and Destination Port (note: ServerM has same IP addr as ServerC)
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

    printf("The ServerC finished sending the response to the Main Server.\n");
}

int main(void)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	struct sockaddr_storage their_addr;
	char buf[MAXBUFLEN];
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];
    char portstr[NI_MAXSERV];

    std::map<std::string, std::string> credDB;

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

	printf("The ServerC is up and running using UDP on port %s.\n", HOST_UDP_PORT_NUM);

	addr_len = sizeof(their_addr);

    //0. Load credentials
    loadCredentials(credDB);

/*
    for(std::map<std::string, std::string>:: iterator it=credDB.begin(); it!=credDB.end(); ++it){
        std::cout << it->first << " : " << it->second << std::endl;
    }
*/
    while(1){
        
        // 1. Receive data from ServerM
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }
        printf("The ServerC received an authentication request from the Main Server\n");
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof(s));
        int rc= getnameinfo((struct sockaddr *) &their_addr, addr_len, s, sizeof(s), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
        if(rc!=0){ 
            perror("getnameinfo failed!");
            exit(1);
        }

        buf[numbytes] = '\0';

        // 2. Process the data
        int auth_status = authenticateUser(credDB, std::string(buf));
        printf("Data: %s, auth_status = %d\n", buf, auth_status);

        // 3. Send the data back to ServerM ( use sendto(.) )
        memset(buf, 0, sizeof(buf));
        sprintf(buf,"%d",auth_status);
        sendUDPServer(sockfd, buf, SERVERM_UDP_PORT_NUM);
    }

	close(sockfd);

	return 0;
}