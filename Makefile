all: serverM.cpp
	g++ -g -o serverM serverM.cpp

clean:
	rm -f *.o serverM
