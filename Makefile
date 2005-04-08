CXX ?= g++
CXXFLAGS ?= -g -Wall

PREFIX ?= /usr/local

OBJS = dbeacon.o dbeacon_posix.o protocol.o

OS = $(shell uname -s)

ifeq ($(OS), SunOS)
	CXXFLAGS += -DSOLARIS
	LDFLAGS = -lnsl -lsocket
endif

all: dbeacon

dbeacon: $(OBJS)
	g++ $(CXXFLAGS) -o dbeacon $(OBJS) $(LDFLAGS)

dbeacon.o: dbeacon.cpp dbeacon.h address.h msocket.h protocol.h

dbeacon.h: address.h ptime.h

msocket.h: address.h

protocol.h: address.h

dbeacon_posix.o: dbeacon_posix.cpp dbeacon.h msocket.h address.h ptime.h

protocol.o: protocol.cpp dbeacon.h protocol.h

install: dbeacon
	install -D dbeacon $(DESTDIR)$(PREFIX)/bin/dbeacon

clean:
	rm -f dbeacon $(OBJS)

