CXX ?= g++
CXXFLAGS ?= -g -Wall

PREFIX ?= /usr/local

OBJS = dbeacon.o address_posix.o msocket_posix.o protocol.o

all: dbeacon

dbeacon: $(OBJS)
	g++ $(CXXFLAGS) -o dbeacon $(OBJS) $(LDFLAGS)

dbeacon.o: dbeacon.cpp dbeacon.h address.h msocket.h protocol.h

address_posix.o: address_posix.cpp dbeacon.h address.h

msocket_posix.o: msocket_posix.cpp dbeacon.h msocket.h

msocket.h: address.h

install: dbeacon
	install -D dbeacon $(DESTDIR)$(PREFIX)/bin/dbeacon

clean:
	rm -f dbeacon

