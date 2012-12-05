/*
 * Copyright 2005-2010, Hugo Santos <hugo@fivebits.net>
 * Distributed under the terms of the MIT License.
 */

#include "dbeacon.h"
#include "msocket.h"
#include "address.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdlib>

#ifndef CMSG_LEN
#define CMSG_LEN(size)	(sizeof(struct cmsghdr) + (size))
#endif

#ifndef CMSG_SPACE
#define CMSG_SPACE(size)	(sizeof(struct cmsghdr) + (size))
#endif

#if defined(SOLARIS) || defined(__NetBSD__)
#define TTLType         uint8_t
#else
#define TTLType         int
#endif

int _McastListenNewAPI(int sock, const address &grpaddr);
int _McastListenOldAPI(int sock, const address &grpaddr);

static int (*_McastListen)(int, const address &) = _McastListenOldAPI;

#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP 42
#endif

#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47
#endif

#ifndef MCAST_FILTER
#define MCAST_FILTER	48
#endif

// Since some GLIBCs include this definitions, and others don't (i'm not even
// talking about BSDs) we instead define them localy to avoid definition colisions

struct _loc_group_req {
	uint32_t gr_interface;
	struct sockaddr_storage gr_group;
};

struct _loc_group_source_req {
	uint32_t gsr_interface;
	struct sockaddr_storage gsr_group;
	struct sockaddr_storage gsr_source;
};

struct _loc_group_filter {
	uint32_t gf_interface;
	struct sockaddr_storage gf_group;
	uint32_t gf_fmode;
	uint32_t gf_numsrc;
	struct sockaddr_storage gf_slist[1];
};

static bool set_address(sockaddr_storage &t, const address &addr) {
	if (addr.family() == AF_INET)
		memcpy(&t, addr.v4(), addr.addrlen());
	else if (addr.family() == AF_INET6)
		memcpy(&t, addr.v6(), addr.addrlen());
	else
		return false;
	return true;
}

void MulticastStartup() {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock > 0) {
		_loc_group_filter flt;
		memset(&flt, 0, sizeof(flt));
		socklen_t fltlen = sizeof(flt);

		// Check if OS supports MCAST_FILTER

		if (getsockopt(sock, IPPROTO_IP, MCAST_FILTER, &flt, &fltlen) == 0
				&& errno != ENOPROTOOPT) {
			if (verbose)
				info("Using new Multicast Filter API");

			_McastListen = _McastListenNewAPI;
		}

		close(sock);
	}
}

int _McastListenNewAPI(int sock, const address &grpaddr) {
	_loc_group_req grp;

	memset(&grp, 0, sizeof(grp));
	grp.gr_interface = mcastInterface;

	set_address(grp.gr_group, grpaddr);

	return setsockopt(sock, grpaddr.optlevel(), MCAST_JOIN_GROUP, &grp, sizeof(grp));
}

int _McastListenOldAPI(int sock, const address &grpaddr) {
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
}

int MulticastListen(int sock, const address &grpaddr) {
	return (*_McastListen)(sock, grpaddr);
}

static int SSMJoinLeave(int sock, int type, const address &grpaddr, const address &srcaddr) {
	_loc_group_source_req req;
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

	int type = level == IPPROTO_IPV6 ?
#ifdef IPV6_RECVHOPLIMIT
				IPV6_RECVHOPLIMIT
#else
				IPV6_HOPLIMIT
#endif
				:
#ifdef IP_RECVTTL
				IP_RECVTTL;
#else
				IP_TTL;
#endif

	if (setsockopt(sock, level, type, &on, sizeof(on)) != 0) {
		perror("receiving hop limit/ttl setsockopt()");
		return -1;
	}

	if (!SetHops(sock, addr, defaultTTL)) {
		perror("SetHops");
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

bool SetHops(int sock, const address &addr, int ttl) {
	if (addr.optlevel() == IPPROTO_IPV6) {
		if (setsockopt(sock, addr.optlevel(), IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0) {
			return false;
		}
	} else {
		TTLType _ttl = ttl;

		if (setsockopt(sock, addr.optlevel(), IP_MULTICAST_TTL, &_ttl, sizeof(_ttl)) != 0) {
			return false;
		}
	}

	return true;
}

bool RequireToAddress(int sock, const address &addr) {
#ifdef IPV6_PKTINFO
	if (addr.family() == AF_INET6) {
		int on = 1;
		return setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on)) == 0;
	}
#endif

	return true;
}

int RecvMsg(int sock, address &from, address &to, uint8_t *buffer, int buflen, int &ttl, uint64_t &ts) {
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
	ttl = 127;

	to = beaconUnicastAddr;

	if (msg.msg_controllen > 0) {
		for (cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
			if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_HOPLIMIT) {
				ttl = *(uint8_t *)CMSG_DATA(hdr);
#ifdef IPV6_PKTINFO
			} else if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_PKTINFO) {
				if (hdr->cmsg_len == CMSG_LEN(sizeof(in6_pktinfo))) {
					in6_pktinfo *pktinfo = (in6_pktinfo *)CMSG_DATA(hdr);
					to.set_family(AF_INET6);
					to.v6()->sin6_addr = pktinfo->ipi6_addr;
				}
#endif
#ifdef IP_RECVTTL
			} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_RECVTTL) {
				ttl = *(uint8_t *)CMSG_DATA(hdr);
#endif
			} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_TTL) {
				ttl = *(uint8_t *)CMSG_DATA(hdr);
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
		ts = get_time_of_day();
	}

	return len;
}

int SendTo(int sock, const uint8_t *buffer, int len, const address &from, const address &to) {
#ifdef IPV6_PKTINFO
	if (from.family() == AF_INET6) {
		uint8_t ctlbuf[CMSG_SPACE(sizeof(in6_pktinfo))];

		cmsghdr *chdr = (cmsghdr *)ctlbuf;
		chdr->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
		chdr->cmsg_level = IPPROTO_IPV6;
		chdr->cmsg_type = IPV6_PKTINFO;

		in6_pktinfo *info = (in6_pktinfo *)CMSG_DATA(chdr);
		info->ipi6_addr = from.v6()->sin6_addr;
		info->ipi6_ifindex = 0;

		msghdr msg;
		iovec iov;

		msg.msg_name = (char *)to.saddr();
		msg.msg_namelen = to.addrlen();
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = (char *)ctlbuf;
		msg.msg_controllen = sizeof(ctlbuf);
		msg.msg_flags = 0;

		iov.iov_base = (char *)buffer;
		iov.iov_len = len;

		return sendmsg(sock, &msg, 0);
	}
#endif
	return sendto(sock, buffer, len, 0, to.saddr(), to.addrlen());
}

address::address() {
	memset(&stor, 0, sizeof(stor));
}

address::address(int family) {
	memset(&stor, 0, sizeof(stor));
	stor.ss_family = family;
}

address::address(const address &original)
	: stor(original.stor) {
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
	addrinfo hint, *rres, *res;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = forceFamily;
	hint.ai_socktype = SOCK_DGRAM;

	if ((cres = getaddrinfo(*tmp ? tmp : 0, port, &hint, &rres)) != 0) {
		info("getaddrinfo failed: %s", gai_strerror(cres));
		return false;
	}

	for (res = rres; res; res = res->ai_next) {
		set(res->ai_addr);
		if (multicast) {
			if (is_multicast())
				break;
		} else if (!is_unspecified())
			break;
	}

	freeaddrinfo(rres);

	if (!res) {
		info("Failed to resolve %s", tmp);
		return false;
	}

	return true;
}

bool address::set_addr(const char *addr) {
	if (stor.ss_family == AF_INET) {
		if (inet_pton(AF_INET, addr, &v4()->sin_addr) <= 0)
			return false;
	} else if (stor.ss_family == AF_INET6) {
		if (inet_pton(AF_INET6, addr, &v6()->sin6_addr) <= 0)
			return false;
	} else {
		return false;
	}

	return true;
}

bool address::set_port(int port) {
	if (stor.ss_family == AF_INET) {
		v4()->sin_port = htons(port);
	} else if (stor.ss_family == AF_INET6) {
		v6()->sin6_port = htons(port);
	} else {
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

int address::port() const {
	if (stor.ss_family == AF_INET6)
		return ntohs(v6()->sin6_port);
	else if (stor.ss_family == AF_INET)
		return ntohs(v4()->sin_port);
	return -1;
}

char *address::to_string(char *str, size_t len, bool printport) const {
	uint16_t port;

	if (stor.ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &v6()->sin6_addr, str, len);
		port = ntohs(v6()->sin6_port);
	} else if (stor.ss_family == AF_INET) {
		inet_ntop(AF_INET, &v4()->sin_addr, str, len);
		port = ntohs(v4()->sin_port);
	} else {
		return NULL;
	}

	if (printport)
		snprintf(str + strlen(str), len - strlen(str), "/%u", port);

	return str;
}

std::string address::to_string(bool printport) const {
	char tmp[128];
	return std::string(to_string(tmp, sizeof(tmp), printport));
}

int address::fromsocket(int sock)
{
	socklen_t addrlen = this->addrlen();
	return getsockname(sock, this->saddr(), &addrlen);
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

int address::compare(const address &a) const {
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

bool address::copy_address(const address &source) {
	if (family() != source.family())
		return false;

	if (stor.ss_family == AF_INET6)
		v6()->sin6_addr = source.v6()->sin6_addr;
	else
		v4()->sin_addr = source.v4()->sin_addr;

	return true;
}

uint64_t get_timestamp() {
	struct tms tmp;

	uint64_t v = times(&tmp);

	return (v * 1000) / sysconf(_SC_CLK_TCK);
}

uint64_t get_time_of_day() {
	struct timeval tv;
	uint64_t timestamp;

	if (gettimeofday(&tv, 0) != 0)
		return 0;

	timestamp = tv.tv_sec;
	timestamp *= 1000;
	timestamp += tv.tv_usec / 1000;

	return timestamp;
}

int
dbeacon_daemonize(const char *pidfile)
{
	if (chdir("/") < 0)
		return -1;

	int ch = fork();
	if (ch < 0)
		return -1;

	/* exit parent */
	if (ch != 0)
		_exit(0);

	/* child, lets prepare for daemonizing */

	int null = open("/dev/null", O_RDWR);
	if (null >= 0) {
		dup2(null, 0);
		dup2(null, 1);
		dup2(null, 2);
	}

	umask(022);
	setsid();

	if (pidfile) {
		FILE *f = fopen(pidfile, "w");
		if (f) {
			fprintf(f, "%u\n", getpid());
			fclose(f);
		} else {
			d_log(LOG_ERR, "Failed to open PID file to write.");
		}
	}

	return 0;
}

address get_local_address_for(const address &remote)
{
	int tmpSock = socket(remote.family(), SOCK_DGRAM, 0);
	if (tmpSock < 0) {
		perror("Failed to create socket to discover local addr");
		exit(-1);
	}

	if (connect(tmpSock, remote.saddr(), remote.addrlen()) != 0) {
		perror("Failed to connect multicast socket");
		exit(-1);
	}

	address result(remote.family());
	if (result.fromsocket(tmpSock) < 0) {
		perror("getsockname");
		exit(-1);
	}

	close(tmpSock);
	return result;
}
