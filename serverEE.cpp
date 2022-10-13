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
#include <string>
#include <iostream>

#define HOST_IP_ADDRESS         "127.0.0.1"
#define HOST_UDP_PORT_NUM       "23082"

#define SERVERM_UDP_PORT_NUM    "24082"
#define MAXBUFLEN               100

#define EE_COURSE_CATALOGUE     "ee.txt"
#define COURSE_CODE_LENGTH      5
#define COURSE_CREDIT_IDX       6

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void loadCourseCatalogue(std::map<std::string, std::string> &ee_catalogue){
    
    //Open file
    FILE *fp = fopen(EE_COURSE_CATALOGUE, "r");
    if(fp == NULL){
        fprintf(stderr, "Error opening %s\n", EE_COURSE_CATALOGUE);
        exit(-1);
    }

    //Access file
    char buf[1000];
    char courseCode[6];
    memset(buf, 0, sizeof(buf));
    while(fgets(buf, sizeof(buf), fp) != NULL){
        strncpy(courseCode, buf, COURSE_CODE_LENGTH);

        //Store EE catalogue in a map
        ee_catalogue[courseCode]=buf;
    }
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

    std::map<std::string, std::string> ee_catalogue;

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

	printf("The ServerEE is up and running using UDP on port %s.\n", HOST_UDP_PORT_NUM);

	addr_len = sizeof(their_addr);

    // 0. Load EE course catalogue
    loadCourseCatalogue(ee_catalogue);

    for(std::map<std::string, std::string>::iterator it=ee_catalogue.begin(); it!=ee_catalogue.end(); ++it){
        std::cout << it->first << ": " << it->second << std::endl; 
    }

    while(1){
        
        // 1. Receive data from ServerM
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        buf[numbytes] = '\0';

        // 2. Process the data

        // 3. Send the data back to ServerM ( use sendto(.) )

/*
        printf("listener: got packet from %s\n",
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                s, sizeof(s));
        printf("listener: packet is %d bytes long\n", numbytes);
        buf[numbytes] = '\0';
        printf("listener: packet contains \"%s\"\n", buf);
*/
    }

	close(sockfd);

	return 0;
}
