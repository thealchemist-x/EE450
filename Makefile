all: serverM.cpp serverC.cpp serverEE.cpp serverCS.cpp Client.cpp
	g++ -g -o serverM serverM.cpp
	g++ -g -o serverC serverC.cpp
	g++ -g -o serverEE serverEE.cpp
	g++ -g -o serverCS serverCS.cpp
	g++ -g -o Client Client.cpp

clean:
	rm -f *.o serverM serverC serverEE serverCS Client
