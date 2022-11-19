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
#include <vector>

#define HOST_IP_ADDRESS         "127.0.0.1"
#define HOST_UDP_PORT_NUM       "23082"

#define SERVERM_UDP_PORT_NUM    "24082"
#define MAXBUFLEN               100

#define EE_COURSE_CATALOGUE     "ee.txt"
#define COURSE_CODE_LENGTH      5
#define COURSE_CREDIT_IDX       6
#define COURSE_DATA_COLUMNS     4

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::vector<std::string> loadCourseData(const char *data, const int sz){
    std::vector<std::string> courseData;
    char str[sz];
    strncpy(str, data, sz);

    char *attribute = strtok(str, ",");

    courseData.push_back(attribute);
    int count = 0;
    while( count < COURSE_DATA_COLUMNS-1){

        attribute = strtok(NULL, ",");

        //Remove newline
        attribute[strcspn(attribute, "\r\n")] = 0;

        courseData.push_back(attribute);
        count++;
    }

    return courseData;
}

void loadCourseCatalogue(std::map<std::string, std::vector<std::string> > &ee_catalogue){
    
    //Open file
    FILE *fp = fopen(EE_COURSE_CATALOGUE, "r");
    if(fp == NULL){
        fprintf(stderr, "Error opening %s\n", EE_COURSE_CATALOGUE);
        exit(-1);
    }

    //Access file
    char buf[1000];
    char courseCode[COURSE_CODE_LENGTH+1];
    char courseData[1000];
    memset(buf, 0, sizeof(buf));
    while(fgets(buf, sizeof(buf), fp) != NULL){
        
        //Copy map-key
        strncpy(courseCode, buf, COURSE_CODE_LENGTH);

        //Copy map-value
        memset(courseData, 0, sizeof(courseData));
        strncpy(courseData, buf+COURSE_CODE_LENGTH+1, sizeof(buf)-(COURSE_CODE_LENGTH+1));

        //Store EE catalogue in a map
        ee_catalogue[courseCode]=loadCourseData(courseData, sizeof(courseData));
    }
}

std::string retrieveInfoFromCourse(std::vector<std::string> &courseInfo, std::string query){
    if(strcmp(query.c_str(), "credit") == 0){
        return courseInfo.at(0);
    }
    else if(strcmp(query.c_str(), "professor") == 0){
        return courseInfo.at(1);
    }
    else if(strcmp(query.c_str(), "days") == 0){
        return courseInfo.at(2);
    }
    else if(strcmp(query.c_str(), "coursename") == 0){
        return courseInfo.at(3);
    }

    return "Incorrect Category!";
}

std::string processCourseCatalogue(std::map<std::string, std::vector<std::string> > &map_ee, char *data, const int len){
    char courseCode[COURSE_CODE_LENGTH+1];
    char courseQuery[1000];

    //Initialize
    memset(courseCode, 0, sizeof(courseCode));
    memset(courseQuery, 0, sizeof(courseQuery));

    //Copy map-key
    strncpy(courseCode, data, COURSE_CODE_LENGTH);

    //Copy map-value
    strncpy(courseQuery, data+COURSE_CODE_LENGTH+1, len-(COURSE_CODE_LENGTH+1));

    printf("The ServerEE received a request from the Main Server about the %s of %s.\n", courseQuery, courseCode);
    
    std::string info = "";

    //Check if courseID exists within map
    std::map<std::string, std::vector<std::string> >::iterator it = map_ee.find(std::string(courseCode));
    if(it == map_ee.end()){
        printf("Didn't find the course: %s.\n", courseCode);
        info = "Didn't find the course: " + std::string(courseCode);
        return info;
    }

    //Else, we found it! Get the vector of course information 
    std::vector<std::string> courseInfo = map_ee[std::string(courseCode)];
    info = retrieveInfoFromCourse(courseInfo,std::string(courseQuery));

    printf("The course information has been found: The %s of %s is %s.\n", courseQuery, courseCode, info.c_str());
    return info;
}

//adapted mostly from beej's guide
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

    printf("The ServerEE finished sending the response to the Main Server.\n");
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

    std::map<std::string, std::vector<std::string> > ee_catalogue;

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

    while(1){
        // 1. Receive data from ServerM
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        buf[numbytes] = '\0';

        // 2. Process the data
        std::string info = processCourseCatalogue(ee_catalogue, buf, strlen(buf));

        // 3. Send the data back to ServerM ( use sendto(.) )
        memset(buf, 0, sizeof(buf));
        memcpy(buf, info.c_str(), info.length());
        sendUDPServer(sockfd, buf, (char *)SERVERM_UDP_PORT_NUM);
    }

	close(sockfd);
	return 0;
}
