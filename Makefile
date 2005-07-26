CXX ?= g++
CXX_SUN = $(shell $(CXX) -V 2>&1 | grep 'Sun C++' >/dev/null && echo yes)
ifeq ($(CXX_SUN),yes)
	CXXFLAGS += -g -xs
else
	CXXFLAGS += -g -Wall -ansi
endif

PREFIX ?= /usr/local

OBJS = dbeacon.o dbeacon_posix.o protocol.o ssmping.o

OS = $(shell uname -s)

ifeq ($(OS), SunOS)
	CXXFLAGS += -DSOLARIS
	ifeq ($(CXX_SUN), yes)
		CXXFLAGS += -D_XPG4_2 -D__EXTENSIONS__
	endif
	LDFLAGS = -lnsl -lsocket
endif

all: dbeacon

dbeacon: $(OBJS)
	$(CXX) $(CXXFLAGS) -o dbeacon $(OBJS) $(LDFLAGS)

dbeacon.o: dbeacon.cpp dbeacon.h address.h msocket.h protocol.h

dbeacon.h: address.h

msocket.h: address.h

protocol.h: address.h

dbeacon_posix.o: dbeacon_posix.cpp dbeacon.h msocket.h address.h

protocol.o: protocol.cpp dbeacon.h protocol.h

ssmping.o: dbeacon.h address.h msocket.h

install: dbeacon
	install -D dbeacon $(DESTDIR)$(PREFIX)/bin/dbeacon

install_mans:
	install -D docs/dbeacon.1 $(DESTDIR)$(PREFIX)/share/man/man1/dbeacon.1

clean:
	rm -f dbeacon $(OBJS)

