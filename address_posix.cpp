/*
 * dbeacon, a Multicast Beacon
 *   address_posix.cpp
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

#include "dbeacon.h"
#include "address.h"

#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

address::address() {
	memset(&stor, 0, sizeof(stor));
}

sockaddr_in *address::v4() { return (sockaddr_in *)&stor; }
sockaddr_in6 *address::v6() { return (sockaddr_in6 *)&stor; }

const sockaddr_in *address::v4() const { return (const sockaddr_in *)&stor; }
const sockaddr_in6 *address::v6() const { return (const sockaddr_in6 *)&stor; }

sockaddr *address::saddr() { return (sockaddr *)&stor; }
const sockaddr *address::saddr() const { return (const sockaddr *)&stor; }

int address::family() const {
	return stor.ss_family;
}

bool address::set_family(int family) {
	if (family != AF_INET && family != AF_INET6)
		return false;
	stor.ss_family = family;
	return true;
}

int address::optlevel() const {
	return stor.ss_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
}

int address::addrlen() const {
	return stor.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

bool address::parse(const char *str, bool multicast, bool addport) {
	char tmp[128];
	strncpy(tmp, str, sizeof(tmp));

	char *port = strchr(tmp, '/');
	if (port) {
		*port = 0;
		port ++;
	} else if (addport) {
		port = (char *)defaultPort;
	}

	int cres;
	addrinfo hint, *res;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = forceFamily;
	hint.ai_socktype = SOCK_DGRAM;

	if ((cres = getaddrinfo(tmp, port, &hint, &res)) != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(cres));
		return false;
	}

	for (; res; res = res->ai_next) {
		set(res->ai_addr);
		if (multicast) {
			if (is_multicast())
				break;
		} else if (!is_unspecified())
			break;
	}

	if (!res) {
		fprintf(stderr, "No usable records for %s\n", tmp);
		return false;
	}

	return true;
}

bool address::is_multicast() const {
	if (stor.ss_family == AF_INET6)
		return IN6_IS_ADDR_MULTICAST(&v6()->sin6_addr);
	else if (stor.ss_family == AF_INET)
		return IN_CLASSD(htonl(v4()->sin_addr.s_addr));
	return false;
}

bool address::is_unspecified() const {
	if (stor.ss_family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(&v6()->sin6_addr);
	else if (stor.ss_family == AF_INET)
		return v4()->sin_addr.s_addr == 0;
	return true;
}

void address::print(char *str, size_t len, bool printport) const {
	uint16_t port;

	if (stor.ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &v6()->sin6_addr, str, len);
		port = ntohs(v6()->sin6_port);
	} else if (stor.ss_family == AF_INET) {
		inet_ntop(AF_INET, &v4()->sin_addr, str, len);
		port = ntohs(v4()->sin_port);
	} else {
		return;
	}

	if (printport)
		snprintf(str + strlen(str), len - strlen(str), "/%u", port);
}

bool address::is_equal(const address &a) const {
	if (stor.ss_family != a.stor.ss_family)
		return false;
	if (stor.ss_family == AF_INET6)
		return memcmp(&v6()->sin6_addr, &a.v6()->sin6_addr, sizeof(in6_addr)) == 0;
	else if (stor.ss_family == AF_INET)
		return v4()->sin_addr.s_addr == a.v4()->sin_addr.s_addr;
	return false;
}

bool address::compare(const address &a) const {
	return memcmp(&stor, &a.stor, sizeof(stor));
}

void address::set(const sockaddr *sa) {
	stor.ss_family = sa->sa_family;
	if (stor.ss_family == AF_INET6) {
		v6()->sin6_addr = ((const sockaddr_in6 *)sa)->sin6_addr;
		v6()->sin6_port = ((const sockaddr_in6 *)sa)->sin6_port;
	} else {
		v4()->sin_addr = ((const sockaddr_in *)sa)->sin_addr;
		v4()->sin_port = ((const sockaddr_in *)sa)->sin_port;
	}
}

