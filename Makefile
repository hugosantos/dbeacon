CXX ?= g++
CXXFLAGS ?= -g -Wall

PREFIX ?= /usr/local

dbeacon: dbeacon.cpp
	$(CXX) $(CXXFLAGS) -o dbeacon dbeacon.cpp

install: dbeacon
	install -D dbeacon $(DESTDIR)$(PREFIX)/bin/dbeacon

clean:
	rm dbeacon

