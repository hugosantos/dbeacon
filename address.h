/*
 * dbeacon, a Multicast Beacon
 *   address.h
 *
 * Copyright (C) 2005 Hugo Santos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:	Hugo Santos <hsantos@av.it.pt>
 */

#ifndef _address_h_
#define _address_h_

#include <sys/types.h>
#include <sys/socket.h>

struct sockaddr_in;
struct sockaddr_in6;

struct address {
	address();

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

	bool is_multicast() const;
	bool is_unspecified() const;

	bool is_equal(const address &) const;
	int compare(const address &) const;

	void set(const sockaddr *);

	void print(char *, size_t, bool port = true) const;

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

