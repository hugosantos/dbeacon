CXX ?= g++
CXXFLAGS ?= -g -Wall

dbeacon: dbeacon.cpp
	$(CXX) $(CXXFLAGS) -o dbeacon dbeacon.cpp

clean:
	rm dbeacon

