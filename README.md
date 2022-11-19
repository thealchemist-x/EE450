# EE450
a) Full Name: Kenny Low

b) StudentID: 5331-5480-82

c) Fulfill requirements of project except bonus section

d) The functionalities of the various files are as follows:

   serverC.cpp = Establish credential server and communicate with main server
   serverM.cpp = The central server that interacts with client and other servers
   serverEE.cpp = The EE dept server that interacts with main server
   serverCS.cpp = The CS dept server that interacts with main server
   Client.cpp = Client that interacts with USC servers to retrieve information
   cred.txt = Credentials to be stored in serverC
   ee.txt = Course information to be stored in serverEE
   cs.txt = Course information to be stored in serverCS
   
e) The format of all messages exchanged are as per requirements and expressed in c-string

g) It is assumed that once authentication is established, the client will always be prompted to query a course.
   
   In order to terminate, the user has to press CTRL+C to exit the Client program.

h) Functions that are adapted mostly from beej's guide:
   int setupTCP(): Client.cpp and serverM.cpp
   int setupUDP(): serverM.cpp
   void sendUDPServer(): serverM.cpp, serverC.cpp, serverCS.cpp and serverEE.cpp
   

