/*
 * dbeacon, a Multicast Beacon
 *   msocket.cpp
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
#include "msocket.h"

#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#if __linux__ || (__FreeBSD_version > 500042)

#if !defined(MCAST_JOIN_GROUP)
#define MCAST_JOIN_GROUP 42
struct group_req {
	uint32_t gr_interface;
	struct sockaddr_storage gr_group;
};
#endif

#if defined(MCAST_JOIN_GROUP) && !defined(MCAST_JOIN_SOURCE_GROUP)
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47
struct group_source_req {
	uint32_t gsr_interface;
	struct sockaddr_storage gsr_group;
	struct sockaddr_storage gsr_source;
};
#endif

#endif

static bool set_address(sockaddr_storage &t, const address &addr) {
	if (addr.family() == AF_INET)
		memcpy(&t, addr.v4(), addr.addrlen());
	else if (addr.family() == AF_INET6)
		memcpy(&t, addr.v6(), addr.addrlen());
	else
		return false;
	return true;
}

int MulticastListen(int sock, const address &grpaddr) {
#ifdef MCAST_JOIN_GROUP
	struct group_req grp;

	memset(&grp, 0, sizeof(grp));
	grp.gr_interface = mcastInterface;

	set_address(grp.gr_group, grpaddr);

	return setsockopt(sock, grpaddr.optlevel(), MCAST_JOIN_GROUP, &grp, sizeof(grp));
#else
	if (grpaddr.family() == AF_INET6) {
		ipv6_mreq mreq;
		mreq.ipv6mr_interface = mcastInterface;
		mreq.ipv6mr_multiaddr = grpaddr.v6()->sin6_addr;

		return setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
	} else {
		ip_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		// Specifying the interface doesn't work, there's ip_mreqn in linux..
		// but what about other OSs? -hugo
		mreq.imr_multiaddr = grpaddr.v4()->sin_addr;

		return setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	}
#endif
}

#ifdef MCAST_JOIN_SOURCE_GROUP
static int SSMJoinLeave(int sock, int type, const address &grpaddr, const address &srcaddr) {
	struct group_source_req req;
	memset(&req, 0, sizeof(req));

	req.gsr_interface = mcastInterface;

	set_address(req.gsr_group, grpaddr);
	set_address(req.gsr_source, srcaddr);

	return setsockopt(sock, srcaddr.optlevel(), type, &req, sizeof(req));
}

int SSMJoin(int sock, const address &grpaddr, const address &srcaddr) {
	return SSMJoinLeave(sock, MCAST_JOIN_SOURCE_GROUP, grpaddr, srcaddr);
}

int SSMLeave(int sock, const address &grpaddr, const address &srcaddr) {
	return SSMJoinLeave(sock, MCAST_LEAVE_SOURCE_GROUP, grpaddr, srcaddr);
}

#else

int SSMJoin(int sock, const address &grpaddr, const address &srcaddr) {
	errno = ENOPROTOOPT;
	return -1;
}

int SSMLeave(int sock, const address &grpaddr, const address &srcaddr) {
	errno = ENOPROTOOPT;
	return -1;
}

#endif

int SetupSocket(const address &addr, bool shouldbind, bool ssm) {
	int af_family = addr.family();
	int level = addr.optlevel();

	int sock = socket(af_family, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("Failed to create multicast socket");
		return -1;
	}

	int on = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	if (shouldbind) {
		if (bind(sock, addr.saddr(), addr.addrlen()) != 0) {
			perror("Failed to bind multicast socket");
			return -1;
		}
	}

#ifdef SO_TIMESTAMP
	if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
		perror("setsockopt(SO_TIMESTAMP)");
		return -1;
	}
#endif

	int type = IPPROTO_IPV6 ? IPV6_HOPLIMIT :
#ifdef IP_RECVTTL
				IP_RECVTTL;
#else
				IP_TTL;
#endif

	if (setsockopt(sock, level, type, &on, sizeof(on)) != 0) {
		perror("receiving hop limit/ttl setsockopt()");
		return -1;
	}

	TTLType ttl = defaultTTL;

	if (setsockopt(sock, level, level == IPPROTO_IPV6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
		perror(level == IPPROTO_IPV6 ?
			"setsockopt(IPV6_MULTICAST_HOPS)"
			: "setsockopt(IP_MULTICAST_TTL)");
		return -1;
	}

	if (!ssm && addr.is_multicast()) {
		if (MulticastListen(sock, addr) != 0) {
			perror("Failed to join multicast group");
			return -1;
		}
	}

	return sock;
}

int RecvMsg(int sock, address &from, uint8_t *buffer, int buflen, int &ttl, uint64_t &ts) {
	int len;
	struct msghdr msg;
	struct iovec iov;
	uint8_t ctlbuf[64];

	from.set_family(beaconUnicastAddr.family());

	msg.msg_name = (char *)from.saddr();
	msg.msg_namelen = from.addrlen();
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (char *)ctlbuf;
	msg.msg_controllen = sizeof(ctlbuf);
	msg.msg_flags = 0;

	iov.iov_base = (char *)buffer;
	iov.iov_len = buflen;

	len = recvmsg(sock, &msg, 0);
	if (len < 0)
		return len;

	ts = 0;
	ttl = -1;

	if (msg.msg_controllen > 0) {
		for (cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
			if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_HOPLIMIT) {
				ttl = *(int *)CMSG_DATA(hdr);
			} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_RECVTTL) {
				ttl = *(uint8_t *)CMSG_DATA(hdr);
			} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_TTL) {
				ttl = *(int *)CMSG_DATA(hdr);
#ifdef SO_TIMESTAMP
			} else if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SO_TIMESTAMP) {
				timeval *tv = (timeval *)CMSG_DATA(hdr);
				ts = tv->tv_sec;
				ts *= 1000;
				ts += tv->tv_usec / 1000;
#endif
			}
		}
	}

	if (!ts) {
		ts = get_timestamp();
	}

	return len;
}

