/*
 * Copyright 2005-2010, Hugo Santos <hugo@fivebits.net>
 * Distributed under the terms of the MIT License.
 */

#ifndef _address_h_
#define _address_h_

#include <sys/types.h>
#include <sys/socket.h>

#include <string>

struct sockaddr_in;
struct sockaddr_in6;

struct address {
	address();
	address(int family);
	address(const address &address);

	sockaddr_in *v4();
	sockaddr_in6 *v6();

	const sockaddr_in *v4() const;
	const sockaddr_in6 *v6() const;

	sockaddr *saddr();
	const sockaddr *saddr() const;

	int family() const;
	bool set_family(int);

	int optlevel() const;
	int addrlen() const;

	bool parse(const char *, bool multicast = true, bool addport = true);
	bool set_addr(const char *);
	bool set_port(int);

	bool is_multicast() const;
	bool is_unspecified() const;

	int port() const;

	bool is_equal(const address &) const;
	int compare(const address &) const;

	bool copy_address(const address &source);

	void set(const sockaddr *);

	int fromsocket(int sock);

	char *to_string(char *, size_t, bool port = true) const;
	std::string to_string(bool port = true) const;

	friend bool operator== (const address &a1, const address &a2) {
		return a1.is_equal(a2);
	}

	friend bool operator < (const address &a1, const address &a2) {
		return a1.compare(a2) < 0;
	}

// #ifdef POSIX
	sockaddr_storage stor;
// #endif
};

#endif

