all: serverM.cpp serverC.cpp serverEE.cpp serverCS.cpp Client.cpp
	g++ -g -std=c++11 -o serverM serverM.cpp
	g++ -g -std=c++11 -o serverC serverC.cpp
	g++ -g -std=c++11 -o serverEE serverEE.cpp
	g++ -g -std=c++11 -o serverCS serverCS.cpp
	g++ -g -std=c++11 -o Client Client.cpp

clean:
	rm -f *.o serverM serverC serverEE serverCS Client
