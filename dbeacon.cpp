#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <vector>

// not everyone have this
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47

struct group_source_req {
	uint32_t gsr_interface;
	struct sockaddr_storage gsr_group;
	struct sockaddr_storage gsr_source;
};
#endif

using namespace std;

/*
 * The new beacon protocol is very simple. Consisted of 2 types of messages:
 *  Probes and Reports
 * The smaller and more frequent are Probes, which consist only of a sequence
 * number and a timestamp. Report messages include beacon info, TTL info and
 * local beacon state (known sources and stats)
 *
 * One of the problems with the original protocol was the high usage of
 * bandwidth. In the new protocol, a burst of Probes (10 pps) are sent each
 * X seconds. X follows a exponential distribution with mean 5 seconds.
 *
 */

#define NEW_BEAC_INT	5
#define NEW_BEAC_PCOUNT	10
#define NEW_BEAC_VER	1

static const char *magicString = "beacon0600";
static const int magicLen = 10;
static char sessionName[256] = "";
static char beaconName[256];
static char probeName[256] = "";
static int mcastInterface = 0;
static string adminContact;
static struct sockaddr_in6 probeAddr;
static struct sockaddr_in6 beaconUnicastAddr;
static struct sockaddr_in6 ssmProbeAddr;
static int mcastSock, ssmMcastSock = 0;
static int largestSock = 0;
static fd_set readSet;
static int verbose = 0;
static bool newProtocol = false;

static uint64_t startTime = 0;

static string dumpFile = "dump.xml";

enum content_type {
	JREPORT,
	JPROBE,

	NPROBE,
	NSSMPROBE,
	NREPORT
};

enum {
	T_BEAC_NAME = 'n',
	T_ADMIN_CONTACT = 'a',
	T_SOURCE_INFO = 'I',
	T_ASM_STATS = 'A',
	T_SSM_STATS = 'S'
};

static vector<pair<sockaddr_in6, content_type> > mcastListen;
static vector<pair<int, content_type> > mcastSocks;

static vector<sockaddr_in6> redist;

enum {
	REPORT_EVENT,
	SEND_EVENT,
	GARBAGE_COLLECT_EVENT,
	DUMP_EVENT,
	DUMP_BW_EVENT,
	DUMP_BIG_BW_EVENT,

	SENDING_EVENT,
	WILLSEND_EVENT,
	MAPREPORT_EVENT
};

#define PACKETS_PERIOD 40
#define PACKETS_VERY_OLD 150

typedef pair<in6_addr, uint16_t> beaconSourceAddr;

struct beaconExternalStats;

struct Stats {
	Stats() : valid(false) {}

	bool valid;
	uint64_t timestamp;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
	uint8_t rttl;
};

struct beaconMcastState {
	uint32_t lastseq;
	uint64_t lasttimestamp;

	uint32_t packetcount, packetcountreal;
	uint32_t pointer;

	int lastdelay, lastjitter, lastloss, lastdup, lastooo;

	Stats s;

	uint32_t cacheseqnum[PACKETS_PERIOD+1];

	void refresh(uint32_t, uint64_t);
	void update(uint8_t, uint32_t, uint64_t, uint64_t);
};

struct beaconSource {
	beaconSource();

	bool identified;
	string name;
	string adminContact;
	struct in6_addr addr;

	uint64_t creation;

	int sttl;

	uint64_t lastevent;

	beaconMcastState ASM, SSM;

	void setName(const string &);
	void update(uint8_t, uint32_t, uint64_t, uint64_t, bool);

	typedef map<beaconSourceAddr, beaconExternalStats> ExternalSources;
	ExternalSources externalSources;

	beaconExternalStats &getExternal(const in6_addr &, uint16_t, uint64_t);
};

typedef map<beaconSourceAddr, beaconSource> Sources;

static Sources sources;

struct beaconExternalStats {
	beaconExternalStats() : identified(false) {}

	uint64_t lastlocalupdate;
	uint32_t age;

	Stats ASM, SSM;

	bool identified;
	string name, contact;
};

struct externalBeacon {
	in6_addr addr;
	uint64_t lastupdate;

	typedef map<beaconSourceAddr, beaconExternalStats> Sources;
	Sources sources;

	map<string, beaconExternalStats> jsources;
};

typedef map<string, externalBeacon> ExternalBeacons;
ExternalBeacons externalBeacons;

static void next_event(struct timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_probe(int, content_type);
static void handle_jprobe(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len);
static void handle_nmsg(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len, bool);
static void handle_jreport(int);
static int parse_jreport(uint8_t *buffer, int len, uint64_t, string &session, string &probe, externalBeacon &rpt);
static void handle_mcast(int, content_type);
static void handle_event();
static void handle_gc();
static int send_jprobe();
static int send_nprobe();
static int send_report(bool);
static int build_jprobe(uint8_t *, int, uint32_t, uint64_t);
static int build_nprobe(uint8_t *, int, uint32_t, uint64_t);

static void do_dump();
static void do_bw_dump(bool);
static void dumpBigBwStats(int);

static uint32_t bytesReceived = 0;
static uint32_t bytesSent = 0;

static uint64_t bigBytesReceived = 0;
static uint64_t bigBytesSent = 0;
static uint64_t lastDumpBwTS = 0;

static uint64_t get_timestamp();

static inline void updateStats(const char *, const sockaddr_in6 *, int, uint32_t, uint64_t, uint64_t);

static int SetupSocket(sockaddr_in6 *, bool, bool);
static int IPv6MulticastListen(int, struct in6_addr *);

static int IPv6SSMJoin(int, const struct in6_addr *);
static int IPv6SSMLeave(int, const struct in6_addr *);

static inline double Rand() {
	return rand() / (double)RAND_MAX;
}

static inline double Exprnd(double mean) {
	return -mean * log(1 - Rand());
}

static inline bool operator < (const in6_addr &a1, const in6_addr &a2) {
	return memcmp(&a1, &a2, sizeof(in6_addr)) < 0;
}

static uint8_t buffer[2048];

extern char *optarg;

void usage() {
	fprintf(stderr, "Usage: dbeacon [OPTIONS...]\n\n");
	fprintf(stderr, "  -n NAME                Specifies the beacon name\n");
	fprintf(stderr, "  -a MAIL                Supply administration contact (new protocol only)\n");
	fprintf(stderr, "  -i INTFNAME            Use INTFNAME instead of the default interface for multicast\n");
	fprintf(stderr, "  -b BEACON_ADDR/PORT    Multicast group address to send probes to\n");
	fprintf(stderr, "  -r REDIST_ADDR/PORT    Redistribute reports to the supplied host/port. Multiple may be supplied\n");
	fprintf(stderr, "  -M REDIST_ADDR/PORT    Redistribute and listen for reports in multicast addr\n");
	fprintf(stderr, "  -S GROUP_ADDR/PORT     Enables SSM reception/sending on GROUP_ADDR\n");
	fprintf(stderr, "  -d                     Dump reports to xml each 5 secs\n");
	fprintf(stderr, "  -D FILE                Specifies dump file (default is dump.xml)\n");
	fprintf(stderr, "  -l LOCAL_ADDR/PORT     Listen for reports from other probes\n");
	fprintf(stderr, "  -L REPORT_ADDR/PORT    Listen to reports from other probs in multicast group REPORT_ADDR\n");
	fprintf(stderr, "  -P                     Use new protocol\n");
	fprintf(stderr, "  -v                     be (very) verbose\n");
	fprintf(stderr, "  -U                     Dump periodic bandwidth usage reports to stdout\n");
	fprintf(stderr, "\n");
}

static bool parse_addr_port(const char *str, sockaddr_in6 *addr) {
	char tmp[64];

	memset(addr, 0, sizeof(sockaddr_in6));
	addr->sin6_family = AF_INET6;

	strcpy(tmp, str);

	char *p = strchr(tmp, '/');
	if (p) {
		char *end;
		addr->sin6_port = htons(strtoul(p + 1, &end, 10));
		if (*end)
			return false;
		*p = 0;
	} else {
		return false;
	}

	if (inet_pton(AF_INET6, tmp, &addr->sin6_addr) <= 0)
		return false;

	return true;
}

int main(int argc, char **argv) {
	int res;

	srand(time(NULL));

	memset(&probeAddr, 0, sizeof(probeAddr));
	probeAddr.sin6_family = AF_INET6;

	memset(&ssmProbeAddr, 0, sizeof(ssmProbeAddr));
	ssmProbeAddr.sin6_family = AF_INET6;

	bool dump = false;
	bool force = false;
	bool dump_bw = false;

	const char *intf = 0;

	while (1) {
		res = getopt(argc, argv, "n:a:b:r:M:S:l:L:dD:i:hvPfU");
		if (res == 'n') {
			if (strlen(probeName) > 0) {
				fprintf(stderr, "Already have a name.\n");
				return -1;
			}
			char tmp[256];
			if (gethostname(tmp, sizeof(tmp)) != 0) {
				perror("Failed to get hostname");
				return -1;
			}
			if ((strlen(optarg) + strlen(tmp)) > 254) {
				fprintf(stderr, "Name is too large.\n");
				return -1;
			}
			snprintf(probeName, sizeof(probeName), "%s@%s", optarg, tmp);

			strcpy(beaconName, optarg);
		} else if (res == 'a') {
			if (!strchr(optarg, '@')) {
				fprintf(stderr, "Not a valid email address.\n");
				return -1;
			}
			adminContact = optarg;
		} else if (res == 'b') {
			if (!parse_addr_port(optarg, &probeAddr)) {
				fprintf(stderr, "Invalid beacon addr.\n");
				return -1;
			}

			if (!IN6_IS_ADDR_MULTICAST(&probeAddr.sin6_addr)) {
				fprintf(stderr, "Beacon group address is not a multicast address.\n");
				return -1;
			}
		} else if (res == 'r' || res == 'M') {
			struct sockaddr_in6 addr;
			if (!parse_addr_port(optarg, &addr)) {
				fprintf(stderr, "Bad address format.\n");
				return -1;
			}
			if (res == 'M') {
				if (!IN6_IS_ADDR_MULTICAST(&addr.sin6_addr)) {
					fprintf(stderr, "Specified address is not a multicast group.\n");
					return -1;
				}
				mcastListen.push_back(make_pair(addr, JREPORT));
			}
			redist.push_back(addr);
		} else if (res == 'S') {
			if (!parse_addr_port(optarg, &ssmProbeAddr) || !IN6_IS_ADDR_MULTICAST(&ssmProbeAddr.sin6_addr)) {
				fprintf(stderr, "Bad address format for SSM channel.\n");
				return -1;
			}
		} else if (res == 'd' || res == 'D') {
			dump = true;
			if (res == 'D')
				dumpFile = optarg;
		} else if (res == 'l' || res == 'L') {
			struct sockaddr_in6 addr;
			if (!parse_addr_port(optarg, &addr)) {
				fprintf(stderr, "Bad address format.\n");
				return -1;
			}
			if (res == 'L' && !IN6_IS_ADDR_MULTICAST(&addr.sin6_addr)) {
				fprintf(stderr, "Specified address is not a multicast group.\n");
				return -1;
			}
			mcastListen.push_back(make_pair(addr, JREPORT));
		} else if (res == 'i') {
			intf = optarg;
		} else if (res == 'h') {
			usage();
			return -1;
		} else if (res == 'v') {
			verbose++;
		} else if (res == 'P') {
			newProtocol = true;
		} else if (res == 'f') {
			force = true;
		} else if (res == 'U') {
			dump_bw = true;
		} else if (res == -1) {
			break;
		}
	}

	if (intf) {
		mcastInterface = if_nametoindex(intf);
		if (mcastInterface <= 0) {
			fprintf(stderr, "Specified interface doesn't exist.\n");
			return -1;
		}
	}

	if (strlen(probeName) == 0) {
		fprintf(stderr, "No name supplied.\n");
		return -1;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		inet_ntop(AF_INET6, &probeAddr.sin6_addr, sessionName, sizeof(sessionName));

		if (!newProtocol) {
			mcastListen.push_back(make_pair(probeAddr, JPROBE));

			insert_event(SEND_EVENT, 100);
			insert_event(REPORT_EVENT, 4000);

			sprintf(sessionName + strlen(sessionName), ":%u", 10000);
		} else {
			if (!force && adminContact.empty()) {
				fprintf(stderr, "No administration contact supplied.\n");
				return -1;
			}

			mcastListen.push_back(make_pair(probeAddr, NPROBE));

			insert_event(SENDING_EVENT, 100);
			insert_event(REPORT_EVENT, 10000);
			insert_event(MAPREPORT_EVENT, 30000);

			redist.push_back(probeAddr);

			sprintf(sessionName + strlen(sessionName), "/%u", 10000);

			if (!IN6_IS_ADDR_UNSPECIFIED(&ssmProbeAddr.sin6_addr)) {
				mcastListen.push_back(make_pair(ssmProbeAddr, NSSMPROBE));
			}
		}
	} else {
		strcpy(sessionName, probeName);
	}

	FD_ZERO(&readSet);

	sockaddr_in6 local;
	memset(&local, 0, sizeof(local));
	local.sin6_family = AF_INET6;

	mcastSock = SetupSocket(&local, false, false);
	if (mcastSock < 0)
		return -1;

	// connect the socket to probeAddr, so the source address can be determined

	socklen_t addrlen = sizeof(probeAddr);

	if (connect(mcastSock, (struct sockaddr *)&probeAddr, addrlen) != 0) {
		perror("Failed to connect multicast socket");
		return -1;
	}

	if (getsockname(mcastSock, (struct sockaddr *)&beaconUnicastAddr, &addrlen) != 0) {
		perror("getsockname");
		return -1;
	}

	for (vector<pair<sockaddr_in6, content_type> >::iterator i = mcastListen.begin(); i != mcastListen.end(); i++) {
		int sock = SetupSocket(&i->first, i->second == JPROBE || i->second == NPROBE || i->second == NSSMPROBE, i->second == NSSMPROBE);
		if (sock < 0)
			return -1;
		mcastSocks.push_back(make_pair(sock, i->second));
		if (i->second == NSSMPROBE)
			ssmMcastSock = sock;
	}

	fprintf(stdout, "Local name is %s\n", probeName);

	insert_event(GARBAGE_COLLECT_EVENT, 120000);

	if (dump)
		insert_event(DUMP_EVENT, 5000);

	if (dump_bw) {
		insert_event(DUMP_BW_EVENT, 10000);
		insert_event(DUMP_BW_EVENT, 600000);
	}

	if (newProtocol)
		send_report(false);

	signal(SIGUSR1, dumpBigBwStats);

	startTime = lastDumpBwTS = get_timestamp();

	while (1) {
		fd_set readset;
		struct timeval eventm;

		memcpy(&readset, &readSet, sizeof(fd_set));

		next_event(&eventm);

		res = select(largestSock + 1, &readset, 0, 0, &eventm);

		if (verbose > 3) {
			fprintf(stderr, "select(): res = %i\n", res);
		}

		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("Select failed");
			return -1;
		} else if (res == 0) {
			handle_event();
		} else {
			for (vector<pair<int, content_type> >::const_iterator i = mcastSocks.begin(); i != mcastSocks.end(); i++)
				if (FD_ISSET(i->first, &readset))
					handle_mcast(i->first, i->second);
		}
	}

	return 0;
}

struct timer {
	uint32_t type, interval;
	struct timeval target;
};

void tv_diff(struct timeval *l, struct timeval *r) {
	if (l->tv_usec >= r->tv_usec) {
		l->tv_sec -= r->tv_sec;
		l->tv_usec -= r->tv_usec;
	} else {
		l->tv_sec -= (r->tv_sec + 1);
		l->tv_usec = r->tv_usec - l->tv_usec;
	}
}

list<timer> timers;

void next_event(struct timeval *eventm) {
	timeval now;
	gettimeofday(&now, 0);

	*eventm = timers.begin()->target;

	if (timercmp(eventm, &now, <)) {
		eventm->tv_sec = 0;
		eventm->tv_usec = 1;
	} else {
		tv_diff(eventm, &now);
	}
}

void insert_sorted_event(timer &t) {
	gettimeofday(&t.target, 0);
	t.target.tv_usec += t.interval * 1000;
	while (t.target.tv_usec > 1000000) {
		t.target.tv_usec -= 1000000;
		t.target.tv_sec++;
	}

	list<timer>::iterator i = timers.begin();

	while (i != timers.end() && timercmp(&i->target, &t.target, <))
		i++;

	timers.insert(i, t);
}

void insert_event(uint32_t type, uint32_t interval) {
	timer t;
	t.type = type;
	t.interval = interval;

	insert_sorted_event(t);
}

static int send_count = 0;

void handle_event() {
	timer t = *timers.begin();
	timers.erase(timers.begin());

	if (verbose > 1)
		fprintf(stderr, "Event %i\n", t.type);

	switch (t.type) {
	case SEND_EVENT:
		send_jprobe();
		break;
	case SENDING_EVENT:
		send_nprobe();
		send_count ++;
		break;
	case REPORT_EVENT:
	case MAPREPORT_EVENT:
		send_report(t.type == MAPREPORT_EVENT);
		break;
	case GARBAGE_COLLECT_EVENT:
		handle_gc();
		break;
	case DUMP_EVENT:
		do_dump();
		break;
	case DUMP_BW_EVENT:
	case DUMP_BIG_BW_EVENT:
		do_bw_dump(t.type == DUMP_BIG_BW_EVENT);
		break;
	}

	if (t.type == WILLSEND_EVENT) {
		insert_event(SENDING_EVENT, 100);
		send_count = 0;
	} else if (t.type == SENDING_EVENT && send_count == NEW_BEAC_PCOUNT) {
		insert_event(WILLSEND_EVENT, (uint32_t)ceil(Exprnd(NEW_BEAC_INT) * 1000));
	} else {
		insert_sorted_event(t);
	}
}

void handle_gc() {
	Sources::iterator i = sources.begin();

	uint64_t now = get_timestamp();

	while (i != sources.end()) {
		bool remove = false;
		if ((now - i->second.lastevent) > 60000) {
			if (i->second.ASM.s.valid) {
				i->second.ASM.s.valid = false;
				i->second.lastevent = now;
			} else {
				remove = true;
			}
		}
		if (!remove) {
			beaconSource::ExternalSources::iterator j = i->second.externalSources.begin();
			while (j != i->second.externalSources.end()) {
				if ((now - j->second.lastlocalupdate) > 120000) {
					beaconSource::ExternalSources::iterator k = j;
					j++;
					i->second.externalSources.erase(k);
				} else {
					j++;
				}
			}

			i++;
		} else {
			Sources::iterator j = i;
			i++;

			if (ssmMcastSock) {
				IPv6SSMLeave(ssmMcastSock, &j->first.first);
			}

			sources.erase(j);
		}
	}

	ExternalBeacons::iterator k = externalBeacons.begin();

	while (k != externalBeacons.end()) {
		if ((now - k->second.lastupdate) > 120000) {
			ExternalBeacons::iterator j = k;
			k++;
			externalBeacons.erase(j);
		} else {
			for (map<string, beaconExternalStats>::iterator m = k->second.jsources.begin(); m != k->second.jsources.end();) {
				if ((now - m->second.lastlocalupdate) > 120000) {
					map<string, beaconExternalStats>::iterator n = m;
					m++;
					k->second.jsources.erase(n);
				} else {
					m++;
				}
			}

			k++;
		}
	}
}

void handle_probe(int sock, content_type type) {
	int len;
	struct sockaddr_in6 from;
	struct msghdr msg;
	struct iovec iov;
	uint8_t ctlbuf[64];

	msg.msg_name = (char *)&from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (char *)ctlbuf;
	msg.msg_controllen = sizeof(ctlbuf);
	msg.msg_flags = 0;

	iov.iov_base = (char *)buffer;
	iov.iov_len = sizeof(buffer);

	len = recvmsg(sock, &msg, 0);
	if (len < 0)
		return;

	if (verbose > 3) {
		char tmp[64];
		inet_ntop(AF_INET6, &from.sin6_addr, tmp, sizeof(tmp));
		fprintf(stderr, "recvmsg(%s): len = %u\n", tmp, len);
	}

	bytesReceived += len;

	uint64_t recvdts = 0;
	int ttl = 0;

	for (cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
		if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SO_TIMESTAMP) {
			timeval *tv = (timeval *)CMSG_DATA(hdr);
			recvdts = tv->tv_sec;
			recvdts *= 1000;
			recvdts += tv->tv_usec / 1000;
		} else if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_HOPLIMIT) {
			ttl = *(int *)CMSG_DATA(hdr);
		}
	}

	if (!recvdts)
		return;

	if (type == JPROBE) {
		handle_jprobe(&from, recvdts, ttl, buffer, len);
	} else if (type == NPROBE) {
		handle_nmsg(&from, recvdts, ttl, buffer, len, false);
	} else if (type == NSSMPROBE) {
		handle_nmsg(&from, recvdts, ttl, buffer, len, true);
	}
}

struct jbuffer {
	jbuffer(uint8_t *, int);

	uint8_t *buff;
	int len, pointer;

	bool eob() { return pointer >= len; }
	uint8_t top() const { return buff[pointer]; }

	bool skip_string();
	bool read(void *, int);
	bool read_string(string &);
	bool read_long(uint32_t &);
	bool read_longlong(uint64_t &);
	bool read_float(float &);

	bool write(const void *, int);
	bool write_string(const string &);
	bool write_long(uint32_t);
	bool write_longlong(uint64_t);
	bool write_float(float);
	bool write_char(char);
};

void handle_jprobe(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len) {
	jbuffer buf(buffer, len);

	uint8_t tmp[magicLen];
	if (!buf.read(tmp, sizeof(tmp)) || memcmp(tmp, magicString, magicLen))
		return;

	string name;
	if (!buf.read_string(name))
		return;

	uint32_t seqnum;
	if (!buf.read_long(seqnum))
		return;

	uint64_t timestamp;
	if (!buf.read_longlong(timestamp))
		return;

	updateStats(name.c_str(), from, ttl, seqnum, timestamp, recvdts);
}

static inline beaconSource &getSource(const in6_addr &addr, uint16_t port, const char *name, uint64_t now) {
	beaconSourceAddr baddr(addr, port);

	Sources::iterator i = sources.find(baddr);
	if (i != sources.end()) {
		i->second.lastevent = now;
		return i->second;
	}

	beaconSource &src = sources[baddr];

	if (name)
		src.setName(name);

	src.creation = now;
	src.lastevent = now;

	if (ssmMcastSock) {
		IPv6SSMJoin(ssmMcastSock, &addr);
	}

	return src;
}

static inline uint8_t *tlv_begin(uint8_t *hd, int &len) {
	if (len < 2 || hd[1] > len)
		return 0;
	return hd;
}

static inline uint8_t *tlv_next(uint8_t *hd, int &len) {
	len -= hd[1];
	return tlv_begin(hd + hd[1] + 2, len);
}

static bool read_tlv_stats(uint8_t *tlv, beaconExternalStats &extb, Stats &st) {
	if (tlv[1] != 20)
		return false;

	st.timestamp = ntohl(*(uint32_t *)(tlv + 2));
	extb.age = ntohl(*(uint32_t *)(tlv + 6));
	st.rttl = tlv[10];

	uint32_t tmp = ntohl(*(uint32_t *)(tlv + 11));
	st.avgdelay = *(float *)&tmp;
	tmp = ntohl(*(uint32_t *)(tlv + 15));
	st.avgjitter = *(float *)&tmp;

	st.avgloss = tlv[19] / 255.;
	st.avgdup = tlv[20] / 255.;
	st.avgooo = tlv[21] / 255.;

	st.valid = true;

	return true;
}

void handle_nmsg(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buff, int len, bool ssm) {
	if (len < 4)
		return;

	if (ntohs(*((uint16_t *)buff)) != 0xbeac)
		return;

	if (buff[2] != NEW_BEAC_VER)
		return;

	if (buff[3] == 0) {
		if (len == 12) {
			uint32_t seq = ntohl(*((uint32_t *)(buff + 4)));
			uint32_t ts = ntohl(*((uint32_t *)(buff + 8)));
			getSource(from->sin6_addr, ntohs(from->sin6_port), 0, recvdts).update(ttl, seq, ts, (uint32_t)recvdts, ssm);
		}
		return;
	}

	// We only accept probes via SSM
	if (ssm)
		return;

	if (buff[3] == 1) {
		if (len < 5)
			return;

		beaconSource &src = getSource(from->sin6_addr, ntohs(from->sin6_port), 0, recvdts);

		src.sttl = buff[4];

		len -= 5;

		for (uint8_t *hd = tlv_begin(buff + 5, len); hd; hd = tlv_next(hd, len)) {
			if (hd[0] == T_BEAC_NAME) {
				string name((char *)hd + 2, hd[1]);
				src.setName(name);
			} else if (hd[0] == T_ADMIN_CONTACT) {
				src.adminContact = string((char *)hd + 2, hd[1]);
			} else if (hd[0] == T_SOURCE_INFO) {
				if (hd[1] < 18)
					continue;
				in6_addr addr;
				memcpy(&addr, hd + 2, sizeof(in6_addr));
				uint16_t port = ntohs(*(uint16_t *)(hd + 18));

				beaconExternalStats &stats = src.getExternal(addr, port, recvdts);

				int plen = hd[1] - 18;
				for (uint8_t *pd = tlv_begin(hd + 2 + 18, plen); pd; pd = tlv_next(pd, plen)) {
					if (pd[0] == T_BEAC_NAME) {
						stats.name = string((char *)pd + 2, pd[1]);
						stats.identified = !stats.name.empty();
					} else if (pd[0] == T_ADMIN_CONTACT) {
						stats.contact = string((char *)pd + 2, pd[1]);
					} else if (pd[0] == T_ASM_STATS || pd[0] == T_SSM_STATS) {
						Stats *st = (pd[0] == T_ASM_STATS ? &stats.ASM : &stats.SSM);

						if (!read_tlv_stats(pd, stats, *st))
							break;
					}
				}
			}
		}
	}
}

void handle_jreport(int sock) {
	sockaddr_in6 from;
	socklen_t fromlen = sizeof(from);
	int len;

	len = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&from, &fromlen);

	if (len < 0)
		return;

	bytesReceived += len;

	string session, name;
	externalBeacon beac;

	if (parse_jreport(buffer, len, get_timestamp(), session, name, beac) < 0)
		return;

	ExternalBeacons::iterator i = externalBeacons.find(name);
	if (i == externalBeacons.end()) {
		externalBeacons.insert(make_pair(name, beac));
		i = externalBeacons.find(name);
	} else {
		for (map<string, beaconExternalStats>::const_iterator j = beac.jsources.begin(); j != beac.jsources.end(); j++)
			i->second.jsources[j->first] = j->second;
	}

	i->second.lastupdate = get_timestamp();
	i->second.addr = from.sin6_addr;
}

int parse_jreport(uint8_t *buffer, int len, uint64_t recvdts, string &session, string &probe, externalBeacon &rpt) {
	jbuffer buf(buffer, len);

	if (!buf.read_string(session))
		return -1;
	if (!buf.read_string(probe))
		return -1;

	for (int i = 0; i < 6; i++) {
		if (!buf.skip_string())
			return -1;
	}

	while (!buf.eob() && buf.top() != '#') {
		string name;
		beaconExternalStats stats;

		stats.lastlocalupdate = recvdts;

		if (!buf.read_string(name))
			return -1;
		if (!buf.read_longlong(stats.ASM.timestamp))
			return -1;
		if (!buf.read_float(stats.ASM.avgdelay))
			return -1;
		if (!buf.read_float(stats.ASM.avgjitter))
			return -1;
		if (!buf.read_float(stats.ASM.avgloss))
			return -1;
		if (!buf.read_float(stats.ASM.avgooo))
			return -1;
		if (!buf.read_float(stats.ASM.avgdup))
			return -1;
		stats.ASM.rttl = 0;
		stats.ASM.valid = true;
		stats.age = 0;

		rpt.jsources[name] = stats;
	}

	return 0;
}

void handle_mcast(int sock, content_type cnt) {
	if (cnt == JPROBE || cnt == NPROBE || cnt == NSSMPROBE) {
		handle_probe(sock, cnt);
	} else if (cnt == JREPORT) {
		handle_jreport(sock);
	}
}

uint64_t get_timestamp() {
	struct timeval tv;
	uint64_t timestamp;

	if (gettimeofday(&tv, 0) != 0)
		return 0;

	timestamp = tv.tv_sec;
	timestamp *= 1000;
	timestamp += tv.tv_usec / 1000;

	return timestamp;
}

beaconSource::beaconSource()
	: identified(false) {
	sttl = 0;
}

void beaconSource::setName(const string &n) {
	name = n;
	identified = true;
}

beaconExternalStats &beaconSource::getExternal(const in6_addr &addr, uint16_t port, uint64_t ts) {
	beaconSourceAddr baddr(addr, port);

	ExternalSources::iterator k = externalSources.find(baddr);
	if (k == externalSources.end()) {
		externalSources.insert(make_pair(baddr, beaconExternalStats()));
		k = externalSources.find(baddr);
	}

	beaconExternalStats &stats = k->second;

	stats.lastlocalupdate = ts;

	return stats;
}

template<typename T> T udiff(T a, T b) { if (a > b) return a - b; return b - a; }

void beaconSource::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now, bool ssm) {
	if (verbose > 2)
		fprintf(stderr, "beacon(%s%s) update %u, %llu, %llu\n", name.c_str(), (ssm ? "/SSM" : ""), seqnum, timestamp, now);

	beaconMcastState *st = ssm ? &SSM : &ASM;

	st->update(ttl, seqnum, timestamp, now);

	// if (verbose && st->s.avgloss < 1) {
	//	cout << "Updating " << name << (ssm ? " (SSM)" : "") << ": " << st->s.avgdelay << ", " << st->s.avgloss << ", " << st->s.avgooo << ", " << st->s.avgdup << endl;
	// }
}

void beaconMcastState::refresh(uint32_t seq, uint64_t now) {
	lastseq = seq;
	lasttimestamp = 0;

	packetcount = packetcountreal = 0;
	pointer = 0;

	lastdelay = lastjitter = lastloss = lastdup = lastooo = 0;
	s.avgdelay = s.avgjitter = s.avgloss = s.avgdup = s.avgooo = 0;
	s.valid = false;
}

void beaconMcastState::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now) {
	int64_t diff = udiff(now, timestamp);

	if (udiff(seqnum, lastseq) > PACKETS_VERY_OLD) {
		refresh(seqnum - 1, now);
	}

	if (seqnum < lastseq && (lastseq - seqnum) >= packetcount)
		return;

	lasttimestamp = timestamp;

	bool dup = false;

	uint32_t expectseq = lastseq + 1;

	if (seqnum < expectseq) {
		for (uint32_t i = 0; i < pointer; i++) {
			if (cacheseqnum[i] == seqnum) {
				dup = true;
				break;
			}
		}
	}

	s.rttl = ttl;

	if (dup) {
		lastdup ++;
	} else {
		packetcountreal++;

		cacheseqnum[pointer++] = seqnum;

		lastdelay += diff;

		int newjitter = diff - lastjitter;
		lastjitter = diff;
		if (newjitter < 0)
			newjitter = -newjitter;
		s.avgjitter = 15/16. * s.avgjitter + 1/16. * newjitter;

		if (expectseq == seqnum) {
			packetcount ++;
		} else if (seqnum > expectseq) {
			packetcount += seqnum - lastseq;

			lastloss += seqnum - lastseq - 1;
		} else {
			lastloss --;
			lastooo ++;
		}

		if (expectseq <= seqnum) {
			lastseq = seqnum;
		}
	}

	if (packetcount >= PACKETS_PERIOD) {
		s.avgdelay = lastdelay / (float)packetcountreal;
		s.avgloss = lastloss / (float)packetcount;
		s.avgooo = lastooo / (float)packetcount;
		s.avgdup = lastdup / (float)packetcount;

		s.valid = true;

		lastdelay = 0;
		lastloss = 0;
		lastooo = 0;
		lastdup = 0;
		packetcount = 0;
		packetcountreal = 0;
		pointer = 0;
	}
}

void updateStats(const char *name, const sockaddr_in6 *from, int ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now) {
	beaconSource &src = getSource(from->sin6_addr, ntohs(from->sin6_port), name, now);

	src.addr = from->sin6_addr;
	src.sttl = 127; // we assume jbeacons use TTL 127, which is usually true

	src.update(ttl, seqnum, timestamp, now, false);
}

int send_jprobe() {
	static uint32_t seq = rand();
	int len;

	len = build_jprobe(buffer, sizeof(buffer), seq, get_timestamp());
	seq++;

	len = sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&probeAddr, sizeof(probeAddr));
	if (len > 0)
		bytesSent += len;
	return len;
}

int send_nprobe() {
	static uint32_t seq = rand();
	int len;

	len = build_nprobe(buffer, sizeof(buffer), seq, get_timestamp());
	seq++;

	len = sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&probeAddr, sizeof(probeAddr));
	if (len > 0)
		bytesSent += len;
	if (ssmMcastSock) {
		int len2 = sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&ssmProbeAddr, sizeof(ssmProbeAddr));
		if (len2 > 0)
			bytesSent += len2;
	}
	return len;
}

static inline bool write_tlv_string(uint8_t *buf, int maxlen, int &pointer, uint8_t type, const char *str) {
	int len = strlen(str);
	if ((pointer + 2 + len) > maxlen)
		return false;
	buf[pointer + 0] = type;
	buf[pointer + 1] = len;
	memcpy(buf + pointer + 2, str, len);
	pointer += len + 2;
	return true;
}

bool write_tlv_start(uint8_t *buff, int maxlen, int &ptr, uint8_t type, int len) {
	if ((ptr + len + 2) > maxlen)
		return false;

	buff[ptr] = type;
	buff[ptr+1] = len;

	ptr += 2;

	return true;
}

bool write_tlv_stats(uint8_t *buff, int maxlen, int &ptr, uint8_t type, uint32_t age, int sttl, const beaconMcastState &st) {
	if (!write_tlv_start(buff, maxlen, ptr, type, 20))
		return false;

	uint8_t *b = buff + ptr;

	*((uint32_t *)(b + 0)) = htonl((uint32_t)st.lasttimestamp);
	*((uint32_t *)(b + 4)) = htonl(age);
	b[8] = sttl - st.s.rttl;

	uint32_t *stats = (uint32_t *)(b + 9);
	stats[0] = htonl(*((uint32_t *)&st.s.avgdelay));
	stats[1] = htonl(*((uint32_t *)&st.s.avgjitter));

	b[17] = (uint8_t)(st.s.avgloss * 0xff);
	b[18] = (uint8_t)(st.s.avgdup * 0xff);
	b[19] = (uint8_t)(st.s.avgooo * 0xff);

	ptr += 20;

	return true;
}

int build_nreport(uint8_t *buff, int maxlen, bool map) {
	if (maxlen < 4)
		return -1;

	// 0-2 magic
	*((uint16_t *)buff) = htons(0xbeac);

	// 3 version
	buff[2] = NEW_BEAC_VER;

	// 4 packet type
	buff[3] = 1; // Report

	buff[4] = 127; // Original Hop Limit

	int ptr = 5;

	if (!write_tlv_string(buff, maxlen, ptr, T_BEAC_NAME, beaconName))
		return -1;
	if (!write_tlv_string(buff, maxlen, ptr, T_ADMIN_CONTACT, adminContact.c_str()))
		return -1;

	uint64_t now = get_timestamp();

	for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.identified)
			continue;

		if (!map && !i->second.ASM.s.valid && !i->second.SSM.s.valid)
			continue;

		int len = 18;

		if (map) {
			int namelen = i->second.name.size();
			int contactlen = i->second.adminContact.size();
			len += 2 + namelen + 2 + contactlen;
		} else {
			len += (i->second.ASM.s.valid ? 22 : 0) + (i->second.SSM.s.valid ? 22 : 0);
		}

		if (!write_tlv_start(buff, maxlen, ptr, T_SOURCE_INFO, len))
			break;

		memcpy(buff + ptr, &i->first.first, sizeof(in6_addr));
		*((uint16_t *)(buff + ptr + 16)) = htons(i->first.second);
		ptr += 18;

		if (map) {
			write_tlv_string(buff, maxlen, ptr, T_BEAC_NAME, i->second.name.c_str());
			write_tlv_string(buff, maxlen, ptr, T_ADMIN_CONTACT, i->second.adminContact.c_str());
		} else {
			uint32_t age = (now - i->second.creation) / 1000;

			if (i->second.ASM.s.valid)
				write_tlv_stats(buff, maxlen, ptr, T_ASM_STATS, age, i->second.sttl, i->second.ASM);
			if (i->second.SSM.s.valid)
				write_tlv_stats(buff, maxlen, ptr, T_SSM_STATS, age, i->second.sttl, i->second.SSM);
		}
	}

	return ptr;
}

int build_jreport(uint8_t *buffer, int maxlen) {
	jbuffer buf(buffer, maxlen);

	if (!buf.write_string(sessionName))
		return -1;
	if (!buf.write_string(probeName))
		return -1;

	if (!buf.write_string("")) // host ip
		return -1;
	if (!buf.write_string("")) // host ip 2nd part
		return -1;
	if (!buf.write_string("")) // OS name
		return -1;
	if (!buf.write_string("")) // OS version
		return -1;
	if (!buf.write_string("")) // machine arch
		return -1;
	if (!buf.write_string("")) // java vm shitness
		return -1;

	for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.ASM.s.valid)
			continue;
		if (!buf.write_string(i->second.name))
			return -1;
		if (!buf.write_longlong(i->second.ASM.lasttimestamp))
			return -1;
		if (!buf.write_float(i->second.ASM.s.avgdelay)) // 0
			return -1;
		if (!buf.write_float(i->second.ASM.s.avgjitter)) // 1
			return -1;
		if (!buf.write_float(i->second.ASM.s.avgloss)) // 2
			return -1;
		if (!buf.write_float(i->second.ASM.s.avgooo)) // 3
			return -1;
		if (!buf.write_float(i->second.ASM.s.avgdup)) // 3
			return -1;
	}

	if (!buf.write_char('#'))
		return -1;

	return buf.pointer;
}

int send_report(bool map) {
	int len;

	if (newProtocol) {
		len = build_nreport(buffer, sizeof(buffer), map);
	} else {
		len = build_jreport(buffer, sizeof(buffer));
	}
	if (len < 0)
		return len;

	for (vector<sockaddr_in6>::const_iterator i = redist.begin(); i != redist.end(); i++) {
		const sockaddr_in6 *to = &(*i);

		char tmp[64];
		inet_ntop(AF_INET6, &to->sin6_addr, tmp, sizeof(tmp));

		if (verbose) {
			cerr << "Sending Report to " << tmp << "/" << ntohs(to->sin6_port) << endl;
		}

		int res;
		if ((res = sendto(mcastSock, buffer, len, 0, (struct sockaddr *)to, sizeof(struct sockaddr_in6))) < 0) {
			cerr << "Failed to send report to " << tmp << "/" << ntohs(to->sin6_port) << ": " << strerror(errno) << endl;
		} else {
			bytesSent += res;
		}
	}

	return 0;
}

int build_jprobe(uint8_t *buff, int maxlen, uint32_t sn, uint64_t ts) {
	jbuffer buf(buff, maxlen);

	if (!buf.write(magicString, strlen(magicString)))
		return -1;

	if (!buf.write_string(probeName))
		return -1;

	if (!buf.write_long(sn))
		return -1;

	if (!buf.write_longlong(ts))
		return -1;

	return buf.pointer;
}

int build_nprobe(uint8_t *buff, int maxlen, uint32_t sn, uint64_t ts) {
	if (maxlen < (int)(4 + 4 + 4))
		return -1;

	// 0-2 magic
	*((uint16_t *)buff) = htons(0xbeac);

	// 3 version
	buff[2] = NEW_BEAC_VER;

	// 4 packet type
	buff[3] = 0; // Probe

	*((uint32_t *)(buff + 4)) = htonl(sn);
	*((uint32_t *)(buff + 8)) = htonl((uint32_t)ts);

	return 4 + 4 + 4;
}

void dumpStats(FILE *fp, const Stats &s, int sttl, bool diff) {
	if (!diff)
		fprintf(fp, " ttl=\"%i\"", s.rttl);
	else if (sttl)
		fprintf(fp, " ttl=\"%i\"", sttl - s.rttl);
	fprintf(fp, " loss=\"%.1f\"", s.avgloss);
	fprintf(fp, " delay=\"%.3f\"", s.avgdelay);
	fprintf(fp, " jitter=\"%.3f\"", s.avgjitter);
	fprintf(fp, " ooo=\"%.3f\"", s.avgooo);
	fprintf(fp, " dup=\"%.3f\"", s.avgdup);
}

void do_dump() {
	FILE *fp = fopen(dumpFile.c_str(), "w");
	if (!fp)
		return;

	char tmp[64];

	fprintf(fp, "<beacons>\n");

	uint64_t now = get_timestamp();

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		inet_ntop(AF_INET6, &beaconUnicastAddr.sin6_addr, tmp, sizeof(tmp));
		fprintf(fp, "\t<beacon name=\"%s\" group=\"%s\" addr=\"%s/%d\"",
				(newProtocol ? beaconName : probeName), sessionName, tmp, ntohs(beaconUnicastAddr.sin6_port));
		if (ssmMcastSock) {
			inet_ntop(AF_INET6, &ssmProbeAddr.sin6_addr, tmp, sizeof(tmp));
			fprintf(fp, " ssmgroup=\"%s/%d\"", tmp, ntohs(ssmProbeAddr.sin6_port));
		}
		fprintf(fp, " age=\"%llu\">\n", (now - startTime) / 1000);
		fprintf(fp, "\t\t<sources>\n");

		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			if (i->second.ASM.s.valid && i->second.identified) {
				inet_ntop(AF_INET6, &i->first.first, tmp, sizeof(tmp));
				fprintf(fp, "\t\t\t<source");
				fprintf(fp, " name=\"%s\"", i->second.name.c_str());
				if (!i->second.adminContact.empty())
					fprintf(fp, " contact=\"%s\"", i->second.adminContact.c_str());
				fprintf(fp, " addr=\"%s/%d\"", tmp, i->first.second);
				fprintf(fp, " age=\"%llu\"\n\t\t\t\t", (now - i->second.creation) / 1000);
				if (i->second.ASM.s.valid)
					dumpStats(fp, i->second.ASM.s, i->second.sttl, true);
				if (i->second.SSM.s.valid) {
					fprintf(fp, ">\n");

					fprintf(fp, "\t\t\t\t\t<ssm");
					dumpStats(fp, i->second.SSM.s, i->second.sttl, true);
					fprintf(fp, " /></source>\n");
				} else {
					fprintf(fp, " />\n");
				}
			}
		}

		fprintf(fp, "\t\t</sources>\n");

		fprintf(fp, "\t</beacon>\n");

		fprintf(fp, "\n");
	}

	if (newProtocol) {
		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			fprintf(fp, "\t<beacon");
			if (i->second.identified) {
				fprintf(fp, " name=\"%s\"", i->second.name.c_str());
				if (!i->second.adminContact.empty())
					fprintf(fp, " contact=\"%s\"", i->second.adminContact.c_str());
			}
			inet_ntop(AF_INET6, &i->first.first, tmp, sizeof(tmp));
			fprintf(fp, " addr=\"%s/%d\"", tmp, i->first.second);
			fprintf(fp, " age=\"%llu\"", (now - i->second.creation) / 1000);
			fprintf(fp, ">\n");
			fprintf(fp, "\t\t<sources>\n");

			for (beaconSource::ExternalSources::const_iterator j = i->second.externalSources.begin();
					j != i->second.externalSources.end(); j++) {
				fprintf(fp, "\t\t\t<source");
				if (j->second.identified) {
					fprintf(fp, " name=\"%s\"", j->second.name.c_str());
					fprintf(fp, " contact=\"%s\"", j->second.contact.c_str());
				}
				inet_ntop(AF_INET6, &j->first.first, tmp, sizeof(tmp));
				fprintf(fp, " addr=\"%s/%d\"", tmp, j->first.second);
				fprintf(fp, " age=\"%u\"\n\t\t\t\t", j->second.age);
				if (j->second.ASM.valid) {
					dumpStats(fp, j->second.ASM, i->second.sttl, false);
				}
				if (j->second.SSM.valid) {
					fprintf(fp, ">\n");
					fprintf(fp, "\t\t\t\t\t<ssm");
					dumpStats(fp, j->second.SSM, i->second.sttl, false);
					fprintf(fp, " /></source>\n");
				} else {
					fprintf(fp, " />\n");
				}
			}

			fprintf(fp, "\t\t</sources>\n");
			fprintf(fp, "\t</beacon>\n");
		}
	} else {
		for (map<string, externalBeacon>::const_iterator i = externalBeacons.begin(); i != externalBeacons.end(); i++) {
			inet_ntop(AF_INET6, &i->second.addr, tmp, sizeof(tmp));
			fprintf(fp, "\t<beacon name=\"%s\" addr=\"%s\">\n", i->first.c_str(), tmp);
			fprintf(fp, "\t\t<sources>\n");

			for (map<string, beaconExternalStats>::const_iterator j = i->second.jsources.begin();
					j != i->second.jsources.end(); j++) {
				fprintf(fp, "\t\t\t<source");
				fprintf(fp, " name=\"%s\"", j->first.c_str());
				dumpStats(fp, j->second.ASM, 0, true);
				fprintf(fp, " />\n");
			}

			fprintf(fp, "\t\t</sources>\n");
			fprintf(fp, "\t</beacon>\n");
		}
	}

	fprintf(fp, "</beacons>\n");

	fclose(fp);
}

void do_bw_dump(bool big) {
	if (big) {
		fprintf(stdout, "BW Usage for 600 secs: Received %llu bytes (%.2lf Kb/s) Sent %llu bytes (%.2lf Kb/s)\n",
				bigBytesReceived, bigBytesReceived * 8 / (1000. * 600), bigBytesSent, bigBytesSent * 8 / (1000. * 600));
		bigBytesReceived = 0;
		bigBytesSent = 0;
		lastDumpBwTS = get_timestamp();
	} else {
		fprintf(stdout, "BW: Received %u bytes (%.2f Kb/s) Sent %u bytes (%.2f Kb/s)\n",
				bytesReceived, bytesReceived * 8 / 10000., bytesSent, bytesSent * 8 / 10000.);
		bigBytesReceived += bytesReceived;
		bigBytesSent += bytesSent;
		bytesReceived = 0;
		bytesSent = 0;
	}
}

void dumpBigBwStats(int) {
	uint64_t diff = (get_timestamp() - lastDumpBwTS) / 1000;
	fprintf(stdout, "BW Usage for %llu secs: Received %llu bytes (%.2lf Kb/s) Sent %llu bytes (%.2lf Kb/s)\n", diff,
			bigBytesReceived, bigBytesReceived * 8 / (1000. * diff), bigBytesSent, bigBytesSent * 8 / (1000. * diff));
}

int IPv6MulticastListen(int sock, struct in6_addr *grpaddr) {
	struct ipv6_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.ipv6mr_interface = mcastInterface;
	memcpy(&mreq.ipv6mr_multiaddr, grpaddr, sizeof(struct in6_addr));

	return setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
}

static int IPv6SSMJoinLeave(int sock, int type, const struct in6_addr *srcaddr) {
	struct group_source_req req;
	memset(&req, 0, sizeof(req));

	req.gsr_interface = mcastInterface;

	*((sockaddr_in6 *)&req.gsr_group) = ssmProbeAddr;
	((sockaddr_in6 *)&req.gsr_source)->sin6_family = AF_INET6;
	((sockaddr_in6 *)&req.gsr_source)->sin6_addr = *srcaddr;

	return setsockopt(sock, IPPROTO_IPV6, type, &req, sizeof(req));
}

int IPv6SSMJoin(int sock, const struct in6_addr *srcaddr) {
	return IPv6SSMJoinLeave(sock, MCAST_JOIN_SOURCE_GROUP, srcaddr);
}

int IPv6SSMLeave(int sock, const struct in6_addr *srcaddr) {
	return IPv6SSMJoinLeave(sock, MCAST_LEAVE_SOURCE_GROUP, srcaddr);
}

int SetupSocket(sockaddr_in6 *addr, bool needTSHL, bool ssm) {
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("Failed to create multicast socket");
		return -1;
	}

	int on = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)addr, sizeof(*addr)) != 0) {
		perror("Failed to bind multicast socket");
		return -1;
	}

	if (needTSHL) {
		if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
			perror("setsockopt(SO_TIMESTAMP)");
			return -1;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on)) != 0) {
			perror("setsockopt(IPV6_HOPLIMIT)");
			return -1;
		}
	}

	on = 0;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) != 0) {
		perror("setsockopt(IPV6_MULTICAST_LOOP)");
		return -1;
	}

	int ttl = 127;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0) {
		perror("setsockopt(IPV6_MULTICAST_HOPS)");
		return -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&addr->sin6_addr) && !ssm) {
		if (IPv6MulticastListen(sock, &addr->sin6_addr) != 0) {
			perror("Failed to join multicast group");
			return -1;
		}
	}

	if (sock > largestSock)
		largestSock = sock;

	FD_SET(sock, &readSet);

	return sock;
}

jbuffer::jbuffer(uint8_t *buffer, int maxlen)
	: buff(buffer), len(maxlen), pointer(0) {}

bool jbuffer::read(void *ptr, int ptrlen) {
	if ((pointer + ptrlen) > len)
		return false;
	memcpy(ptr, buff + pointer, ptrlen);
	pointer += ptrlen;
	return true;
}

bool jbuffer::skip_string() {
	string foo;
	return read_string(foo);
}

bool jbuffer::read_string(string &str) {
	if ((pointer + 1) >= len)
		return false;
	if ((pointer + 1 + buff[pointer]) > len)
		return false;
	str = string((char *)buff + pointer + 1, (int)buff[pointer]);
	pointer += 1 + buffer[pointer];
	return true;
}

bool jbuffer::read_long(uint32_t &l) {
	string str;
	if (!read_string(str))
		return false;
	char *end;
	l = strtoul(str.c_str(), &end, 10);
	if (*end)
		return false;
	return true;
}

bool jbuffer::read_longlong(uint64_t &ll) {
	string str;
	if (!read_string(str))
		return false;
	if (sscanf(str.c_str(), "%llu", &ll) != 1)
		return false;
	return true;
}

bool jbuffer::read_float(float &f) {
	string str;
	if (!read_string(str))
		return false;
	char *end;
	f = strtof(str.c_str(), &end);
	if (*end)
		return false;
	return true;
}

bool jbuffer::write(const void *ptr, int ptrlen) {
	if ((pointer + ptrlen) > len)
		return false;
	memcpy(buff + pointer, ptr, ptrlen);
	pointer += ptrlen;
	return true;
}

bool jbuffer::write_string(const string &str) {
	if (str.size() > 255 || (pointer + (int)str.size() + 1) > len)
		return false;

	buffer[pointer] = str.size();
	memcpy(buff + pointer + 1, str.c_str(), str.size());

	pointer += 1 + str.size();

	return true;
}

bool jbuffer::write_long(uint32_t d) {
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%u", d);

	return write_string(tmp);
}

bool jbuffer::write_float(float f) {
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%f", f);

	return write_string(tmp);
}

bool jbuffer::write_longlong(uint64_t d) {
	char tmp[64];

	snprintf(tmp, sizeof(tmp), "%llu", d);

	return write_string(tmp);
}

bool jbuffer::write_char(char c) {
	if ((pointer + 1) >= len)
		return false;
	buff[pointer++] = c;
	return true;
}


