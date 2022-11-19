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
#include <algorithm>

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

std::string getUserQuery(std::string &mCourseCode, std::string &mCategory){
    std::string userQueryCourse="", userQueryKey="", combined="";
    std::cout << "Please enter the course code to query: ";
    std::getline(std::cin,userQueryCourse);
    std::cout << "Please enter the category (Credit / Professor / Days / CourseName): ";
    std::getline(std::cin,userQueryKey);

    //Query course separated by comma!
    combined=userQueryCourse + "," + userQueryKey;
    mCourseCode=userQueryCourse;
    mCategory=userQueryKey;

    //Converts mCategory to lower casing
    std::transform(mCategory.begin(), mCategory.end(), mCategory.begin(),[](unsigned char c) {return std::tolower(c);});

    return combined;
}

std::string getUserCredentials(std::string &mUsername){
    std::string username="", password="", combined="";
    std::cout << "Please enter the username: ";
    std::getline(std::cin,username);
    std::cout << "Please enter the password: ";
    std::getline(std::cin,password);

    //username and password separated by a space!
    combined=username+" "+password;
    mUsername=username;
    return combined;
}

bool processAuthStatus(std::string username, char *status, int auth_count, const int local_port){
    int auth_status = std::stoi(status);
    if(auth_status != 2){

        if(auth_status == 0){
            printf("%s received the result of authentication using TCP over port %d. Authentication failed: Username Does not exist\n\n",
                    username.c_str(), local_port);
        }
        else{
             printf("%s received the result of authentication using TCP over port %d. Authentication failed: Password does not match\n\n",
                    username.c_str(), local_port);           
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
            printf("%s received the result of authentication using TCP over port %d. Authentication is successful\n",
                    username.c_str(), local_port);         
    }

    return true;
}

//adapted mostly from beej's guide
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
    std::string username="", courseCode="", category="";
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    tcp_sockfd = setupTCP();
    printf("The client is up and running\n");
    
    //Get client's assigned port number
    getsockname(tcp_sockfd, (struct sockaddr *)&sin, &len);
    unsigned short local_port = ntohs(sin.sin_port);

    // 0. Get username and password from user
    for(int i = 0; i < AUTH_COUNT; ++i){
        std::string userLoginDetails = getUserCredentials(username);

        // 1. Sending username and password to ServerM (use send(.) )
        if((numbytes = send(tcp_sockfd, userLoginDetails.c_str(), userLoginDetails.length(),0)== -1)){
            perror("send");
            exit(1);
        }

        printf("%s sent an authentication request to the main server.\n", username.c_str());

        // 2. Receiving from ServerM
        memset(buf, 0, sizeof(buf));
        if ((numbytes = recv(tcp_sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
            perror("recv");
            exit(1);
        }

        buf[numbytes] = '\0';

        isAuthOk = processAuthStatus(username, buf, i+1, local_port);

        if(isAuthOk){
            break;
        }
    }

    //Authentication success
    if(isAuthOk){
        while(1){
            std::string userQuery = getUserQuery(courseCode, category);

            if((numbytes = send(tcp_sockfd, userQuery.c_str(), userQuery.length(),0)== -1)){
                perror("send");
                exit(1);
            }

            printf("%s sent a request to the main server.\n", username.c_str());

            //Receiving from ServerM
            memset(buf, 0, sizeof(buf));
            if ((numbytes = recv(tcp_sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
                perror("recv");
                exit(1);
            }
            
            buf[numbytes] = '\0';
            buf[strcspn(buf, "\r\n")] = 0;

            printf("The client received the response from the Main server using TCP over port %d.\n", local_port);
            
            //Phase 4B - Looping
            if(strstr(buf,"Didn't")==NULL){
                printf("The %s of %s is %s.\n\n", category.c_str(), courseCode.c_str(), buf);
            }
            else{
                printf("%s.\n\n", buf);
            }
            printf("-----Start a new request-----\n");
        }
    }

	close(tcp_sockfd);

	return 0;
}
