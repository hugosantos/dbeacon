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

#include <libgen.h>

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <vector>

// not everyone have this
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#define MCAST_LEAVE_SOURCE_GROUP 47

#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP 42
#endif

struct group_req
{
       uint32_t gr_interface;
       struct sockaddr_storage gr_group;
};

struct group_source_req {
	uint32_t gsr_interface;
	struct sockaddr_storage gsr_group;
	struct sockaddr_storage gsr_source;
};
#endif

using namespace std;

struct address : sockaddr_storage {
	address();

	sockaddr_in *v4() { return (sockaddr_in *)this; }
	sockaddr_in6 *v6() { return (sockaddr_in6 *)this; }

	static int family(const char *);

	bool parse(const char *);

	bool is_multicast() const;
	bool is_unspecified() const;

	bool is_equal(const address &) const;

	void print(char *, size_t) const;
};

address::address() {
	memset(this, 0, sizeof(*this));
}

int address::family(const char *addr) {
	if (strchr(addr, ':') != NULL)
		return AF_INET6;
	else if (strchr(addr, '.') != NULL)
		return AF_INET;
	return -1;
}

bool address::parse(const char *str) {
	char tmp[64];

	int family = address::family(str);
	if (family == -1)
		return false;

	ss_family = family;

	strcpy(tmp, str);

	char *p = strchr(tmp, '/');
	if (p) {
		char *end;
		if (family == AF_INET6) {
			v6()->sin6_port = htons(strtoul(p + 1, &end, 10));
		} else if (family == AF_INET) {
			v4()->sin_port = htons(strtoul(p + 1, &end, 10));
		}
		if (*end)
			return false;
		*p = 0;
	} else {
		return false;
	}

	if (family == AF_INET6) {
		if (inet_pton(family, tmp, &v6()->sin6_addr) <= 0)
			return false;
	} else if (family == AF_INET) {
		if (inet_pton(family, tmp, &v4()->sin_addr) <= 0)
			return false;
	}

	return true;
}

bool address::is_multicast() const {
	if (ss_family == AF_INET6)
		return IN6_IS_ADDR_MULTICAST(&((sockaddr_in6 *)this)->sin6_addr);
	else if (ss_family == AF_INET)
		return IN_CLASSD(&((sockaddr_in *)this)->sin_addr.s_addr);
	return false;
}

bool address::is_unspecified() const {
	if (ss_family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(&((sockaddr_in6 *)this)->sin6_addr);
	else if (ss_family == AF_INET)
		return ((sockaddr_in *)this)->sin_addr.s_addr == 0;
	return true;
}

void address::print(char *str, size_t len) const {
	uint16_t port;

	if (ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6src = (struct sockaddr_in6 *)this;
		inet_ntop(AF_INET6, &sin6src->sin6_addr, str, len);
		port = ntohs(sin6src->sin6_port);
	} else if (ss_family == AF_INET) {
		struct sockaddr_in *sinsrc = (struct sockaddr_in *)this;
		inet_ntop(AF_INET, &sinsrc->sin_addr, str, len);
		port = ntohs(sinsrc->sin_port);
	} else {
		return;
	}

	snprintf(str + strlen(str), len - strlen(str), "/%u", port);
}

bool address::is_equal(const address &a) const {
	if (ss_family != a.ss_family)
		return false;
	if (ss_family == AF_INET6)
		return memcmp(&((sockaddr_in6 *)this)->sin6_addr, &((sockaddr_in6 *)&a)->sin6_addr, sizeof(in6_addr)) == 0;
	else if (ss_family == AF_INET)
		return ((sockaddr_in *)this)->sin_addr.s_addr == ((sockaddr_in *)&a)->sin_addr.s_addr;
	return false;
}

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

#define NEW_BEAC_PCOUNT	10
#define NEW_BEAC_VER	1

static char sessionName[256] = "";
static char beaconName[256];
static char probeName[256] = "";
static int mcastInterface = 0;
static string adminContact;
static address probeAddr;
static address beaconUnicastAddr;
static address ssmProbeAddr;
static int mcastSock, ssmMcastSock = 0;
static int largestSock = 0;
static fd_set readSet;
static int verbose = 0;
static bool dumpBwReport = false;

static double beacInt = 5.;

static uint64_t startTime = 0;

static string dumpFile = "dump.xml";

enum content_type {
	NPROBE,
	NSSMPROBE,
	NREPORT
};

enum {
	T_BEAC_NAME = 'n',
	T_ADMIN_CONTACT = 'a',
	T_SOURCE_INFO_IPv4 = 'i',
	T_SOURCE_INFO = 'I',
	T_ASM_STATS = 'A',
	T_SSM_STATS = 'S',

	T_WEBSITE_GENERIC = 'G',
	T_WEBSITE_MATRIX = 'M',
	T_WEBSITE_LG = 'L'
};

static vector<pair<address, content_type> > mcastListen;
static vector<pair<int, content_type> > mcastSocks;

typedef map<int, string> WebSites;
static WebSites webSites;

static vector<address> redist;

enum {
	REPORT_EVENT,
	GARBAGE_COLLECT_EVENT,
	DUMP_EVENT,
	DUMP_BW_EVENT,
	DUMP_BIG_BW_EVENT,

	SENDING_EVENT,
	WILLSEND_EVENT,
	MAP_REPORT_EVENT,
	WEBSITE_REPORT_EVENT
};

#define PACKETS_PERIOD 40
#define PACKETS_VERY_OLD 150

typedef address beaconSourceAddr;

struct beaconExternalStats;

struct Stats {
	Stats() : valid(false) {}

	bool valid;
	uint64_t timestamp, lastupdate;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
	uint8_t rttl;

	void check_validity(uint64_t);
};

struct beaconMcastState {
	uint32_t lastseq;

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
	address addr;

	uint64_t creation;

	int sttl;

	uint64_t lastevent;

	beaconMcastState ASM, SSM;

	void setName(const string &);
	void update(uint8_t, uint32_t, uint64_t, uint64_t, bool);

	typedef map<beaconSourceAddr, beaconExternalStats> ExternalSources;
	ExternalSources externalSources;

	beaconExternalStats &getExternal(const beaconSourceAddr &, uint64_t);

	WebSites webSites;
};

typedef map<beaconSourceAddr, beaconSource> Sources;

static Sources sources;

struct beaconExternalStats {
	beaconExternalStats() : identified(false) {}

	uint64_t lastupdate;
	uint32_t age;

	Stats ASM, SSM;

	bool identified;
	string name, contact;
};

static void next_event(struct timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_probe(int, content_type);
static void handle_nmsg(address *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len, bool);
static void handle_mcast(int, content_type);
static void handle_event();
static void handle_gc();
static int send_nprobe();
static int send_report(int);
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

static int SetupSocket(address *, bool, bool);
static int MulticastListen(int, address *);

static int SSMJoin(int, const address *);
static int SSMLeave(int, const address *);

static inline double Rand() {
	return rand() / (double)RAND_MAX;
}

static inline double Exprnd(double mean) {
	return -mean * log(1 - Rand());
}

static inline bool operator < (const address &a1, const address &a2) {
	return memcmp(&a1, &a2, sizeof(address)) < 0;
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
	fprintf(stderr, "  -S GROUP_ADDR/PORT     Enables SSM reception/sending on GROUP_ADDR\n");
	fprintf(stderr, "  -d                     Dump reports to xml each 5 secs\n");
	fprintf(stderr, "  -D FILE                Specifies dump file (default is dump.xml)\n");
	fprintf(stderr, "  -l LOCAL_ADDR/PORT     Listen for reports from other probes\n");
	fprintf(stderr, "  -L REPORT_ADDR/PORT    Listen to reports from other probs in multicast group REPORT_ADDR\n");
	fprintf(stderr, "  -W type$url            Specify a website to announce. type is one of lg, matrix\n");
	fprintf(stderr, "  -P                     Use new protocol\n");
	fprintf(stderr, "  -v                     be (very) verbose\n");
	fprintf(stderr, "  -U                     Dump periodic bandwidth usage reports to stdout\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
	int res;

	srand(time(NULL));

	bool dump = false;
	bool force = false;

	const char *intf = 0;

	while (1) {
		res = getopt(argc, argv, "n:a:b:r:S:l:L:dD:i:W:hvfU");
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
			if (!probeAddr.parse(optarg)) {
				fprintf(stderr, "Invalid beacon addr.\n");
				return -1;
			}

			if (!probeAddr.is_multicast()) {
				fprintf(stderr, "Beacon group address is not a multicast address.\n");
				return -1;
			}
		} else if (res == 'r') {
			address addr;
			if (!addr.parse(optarg)) {
				fprintf(stderr, "Bad address format.\n");
				return -1;
			}
			redist.push_back(addr);
		} else if (res == 'S') {
			if (!ssmProbeAddr.parse(optarg) || !ssmProbeAddr.is_multicast()) {
				fprintf(stderr, "Bad address format for SSM channel.\n");
				return -1;
			}
		} else if (res == 'd' || res == 'D') {
			dump = true;
			if (res == 'D')
				dumpFile = optarg;
		} else if (res == 'l' || res == 'L') {
			address addr;
			if (!addr.parse(optarg)) {
				fprintf(stderr, "Bad address format.\n");
				return -1;
			}
			if (res == 'L' && !addr.is_multicast()) {
				fprintf(stderr, "Specified address is not a multicast group.\n");
				return -1;
			}
			mcastListen.push_back(make_pair(addr, NREPORT));
		} else if (res == 'W') {
			int type = T_WEBSITE_GENERIC;
			if (strncmp(optarg, "lg$", 3) == 0) {
				type = T_WEBSITE_LG;
				optarg += 3;
			} else if (strncmp(optarg, "matrix$", 7) == 0) {
				type = T_WEBSITE_MATRIX;
				optarg += 7;
			}
			webSites[type] = optarg;
		} else if (res == 'i') {
			intf = optarg;
		} else if (res == 'h') {
			usage();
			return -1;
		} else if (res == 'v') {
			verbose++;
		} else if (res == 'f') {
			force = true;
		} else if (res == 'U') {
			dumpBwReport = true;
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

	if (!probeAddr.is_unspecified()) {
		probeAddr.print(sessionName, sizeof(sessionName));

		if (!force && adminContact.empty()) {
			fprintf(stderr, "No administration contact supplied.\n");
			return -1;
		}

		mcastListen.push_back(make_pair(probeAddr, NPROBE));

		insert_event(SENDING_EVENT, 100);
		insert_event(REPORT_EVENT, 10000);
		insert_event(MAP_REPORT_EVENT, 30000);
		insert_event(WEBSITE_REPORT_EVENT, 120000);

		redist.push_back(probeAddr);

		if (!ssmProbeAddr.is_unspecified()) {
			mcastListen.push_back(make_pair(ssmProbeAddr, NSSMPROBE));
		}
	} else {
		strcpy(sessionName, probeName);
	}

	FD_ZERO(&readSet);

	address local;
	local.ss_family = probeAddr.ss_family;

	mcastSock = SetupSocket(&local, false, false);
	if (mcastSock < 0)
		return -1;

	// connect the socket to probeAddr, so the source address can be determined

	socklen_t addrlen = sizeof(probeAddr);

	if (connect(mcastSock, (sockaddr *)&probeAddr, addrlen) != 0) {
		perror("Failed to connect multicast socket");
		return -1;
	}

	if (getsockname(mcastSock, (sockaddr *)&beaconUnicastAddr, &addrlen) != 0) {
		perror("getsockname");
		return -1;
	}

	for (vector<pair<address, content_type> >::iterator i = mcastListen.begin(); i != mcastListen.end(); i++) {
		int sock = SetupSocket(&i->first, i->second == NPROBE || i->second == NSSMPROBE, i->second == NSSMPROBE);
		if (sock < 0)
			return -1;
		mcastSocks.push_back(make_pair(sock, i->second));
		if (i->second == NSSMPROBE)
			ssmMcastSock = sock;
	}

	fprintf(stdout, "Local name is %s\n", probeName);

	insert_event(GARBAGE_COLLECT_EVENT, 30000);

	if (dump)
		insert_event(DUMP_EVENT, 5000);

	insert_event(DUMP_BW_EVENT, 10000);

	if (dumpBwReport) {
		insert_event(DUMP_BIG_BW_EVENT, 600000);
	}

	send_report(WEBSITE_REPORT_EVENT);

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
	case SENDING_EVENT:
		send_nprobe();
		send_count ++;
		break;
	case REPORT_EVENT:
	case MAP_REPORT_EVENT:
	case WEBSITE_REPORT_EVENT:
		send_report(t.type);
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
		insert_event(WILLSEND_EVENT, (uint32_t)ceil(Exprnd(beacInt) * 1000));
	} else if (t.type == REPORT_EVENT) {
		insert_event(REPORT_EVENT, (uint32_t)ceil(2 * beacInt * 1000));
	} else if (t.type == MAP_REPORT_EVENT) {
		insert_event(MAP_REPORT_EVENT, (uint32_t)ceil(6 * beacInt * 1000));
	} else if (t.type == WEBSITE_REPORT_EVENT) {
		insert_event(WEBSITE_REPORT_EVENT, (uint32_t)ceil(24 * beacInt * 1000));
	} else {
		insert_sorted_event(t);
	}
}

void Stats::check_validity(uint64_t now) {
	if ((now - lastupdate) > 30000)
		valid = false;
}

void handle_gc() {
	Sources::iterator i = sources.begin();

	uint64_t now = get_timestamp();

	while (i != sources.end()) {
		bool remove = false;
		if ((now - i->second.lastevent) > 30000) {
			remove = true;
		}
		if (!remove) {
			i->second.ASM.s.check_validity(now);
			i->second.SSM.s.check_validity(now);

			beaconSource::ExternalSources::iterator j = i->second.externalSources.begin();
			while (j != i->second.externalSources.end()) {
				if ((now - j->second.lastupdate) > 30000) {
					beaconSource::ExternalSources::iterator k = j;
					j++;
					i->second.externalSources.erase(k);
				} else {
					j->second.ASM.check_validity(now);
					j->second.SSM.check_validity(now);

					j++;
				}
			}

			i++;
		} else {
			Sources::iterator j = i;
			i++;

			if (ssmMcastSock) {
				SSMLeave(ssmMcastSock, &j->first);
			}

			sources.erase(j);
		}
	}
}

void handle_probe(int sock, content_type type) {
	int len;
	address from;
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
		from.print(tmp, sizeof(tmp));
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
		} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_RECVTTL) {
			ttl = *(uint8_t *)CMSG_DATA(hdr);
		} else if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_TTL) {
			ttl = *(int *)CMSG_DATA(hdr);
		}
	}

	if (!recvdts)
		return;

	if (type != NPROBE && type != NSSMPROBE)
		return;

	handle_nmsg(&from, recvdts, ttl, buffer, len, type == NSSMPROBE);
}

static inline beaconSource &getSource(const beaconSourceAddr &baddr, const char *name, uint64_t now) {
	Sources::iterator i = sources.find(baddr);
	if (i != sources.end()) {
		i->second.lastevent = now;
		return i->second;
	}

	beaconSource &src = sources[baddr];

	if (verbose) {
		char tmp[64];

		baddr.print(tmp, sizeof(tmp));

		if (name) {
			fprintf(stderr, "Adding source %s [%s]\n", tmp, name);
		} else {
			fprintf(stderr, "Adding source %s\n", tmp);
		}
	}

	if (name)
		src.setName(name);

	src.creation = now;
	src.lastevent = now;

	if (ssmMcastSock) {
		SSMJoin(ssmMcastSock, &baddr);
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

void handle_nmsg(address *from, uint64_t recvdts, int ttl, uint8_t *buff, int len, bool ssm) {
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
			getSource(*from, 0, recvdts).update(ttl, seq, ts, recvdts, ssm);
		}
		return;
	}

	// We only accept probes via SSM
	if (ssm)
		return;

	if (buff[3] == 1) {
		if (len < 5)
			return;

		beaconSource &src = getSource(*from, 0, recvdts);

		src.sttl = buff[4];

		len -= 5;

		for (uint8_t *hd = tlv_begin(buff + 5, len); hd; hd = tlv_next(hd, len)) {
			if (hd[0] == T_BEAC_NAME) {
				string name((char *)hd + 2, hd[1]);
				src.setName(name);
			} else if (hd[0] == T_ADMIN_CONTACT) {
				src.adminContact = string((char *)hd + 2, hd[1]);
			} else if (hd[0] == T_SOURCE_INFO || hd[0] == T_SOURCE_INFO_IPv4) {
				int blen = hd[0] == T_SOURCE_INFO ? 18 : 6;

				if (hd[1] < blen)
					continue;

				address addr;

				if (hd[0] == T_SOURCE_INFO) {
					sockaddr_in6 *a6 = (sockaddr_in6 *)&addr;

					a6->sin6_family = AF_INET6;

					memcpy(&a6->sin6_addr, hd + 2, sizeof(in6_addr));
					a6->sin6_port = *(uint16_t *)(hd + 18);
				} else {
					sockaddr_in *a4 = (sockaddr_in *)&addr;

					a4->sin_family = AF_INET;

					memcpy(&a4->sin_addr, hd + 2, sizeof(in_addr));
					a4->sin_port = *(uint16_t *)(hd + 6);
				}

				beaconExternalStats &stats = src.getExternal(addr, recvdts);

				int plen = hd[1] - blen;
				for (uint8_t *pd = tlv_begin(hd + 2 + blen, plen); pd; pd = tlv_next(pd, plen)) {
					if (pd[0] == T_BEAC_NAME) {
						stats.name = string((char *)pd + 2, pd[1]);
						stats.identified = !stats.name.empty();
					} else if (pd[0] == T_ADMIN_CONTACT) {
						stats.contact = string((char *)pd + 2, pd[1]);
					} else if (pd[0] == T_ASM_STATS || pd[0] == T_SSM_STATS) {
						Stats *st = (pd[0] == T_ASM_STATS ? &stats.ASM : &stats.SSM);

						if (!read_tlv_stats(pd, stats, *st))
							break;
						st->lastupdate = recvdts;
					}
				}

				// trigger local SSM join
				if (!addr.is_equal(beaconUnicastAddr))
					getSource(addr, stats.identified ? stats.name.c_str() : 0, recvdts).adminContact = stats.contact;
			} else if (hd[0] == T_WEBSITE_GENERIC || hd[0] == T_WEBSITE_LG || hd[0] == T_WEBSITE_MATRIX) {
				src.webSites[hd[0]] = string((char *)hd + 2, hd[1]);
			}
		}
	}
}

void handle_mcast(int sock, content_type cnt) {
	if (cnt == NPROBE || cnt == NSSMPROBE) {
		handle_probe(sock, cnt);
	}
}

static inline uint64_t get_timestamp() {
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

beaconExternalStats &beaconSource::getExternal(const address &baddr, uint64_t ts) {
	ExternalSources::iterator k = externalSources.find(baddr);
	if (k == externalSources.end()) {
		externalSources.insert(make_pair(baddr, beaconExternalStats()));
		k = externalSources.find(baddr);

		k->second.age = 0;

		char tmp[64];
		baddr.print(tmp, sizeof(tmp));

		if (verbose)
			fprintf(stderr, "Adding external source (%s) %s\n", name.c_str(), tmp);
	}

	beaconExternalStats &stats = k->second;

	stats.lastupdate = ts;

	return stats;
}

template<typename T> T udiff(T a, T b) { if (a > b) return a - b; return b - a; }

void beaconSource::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now, bool ssm) {
	if (verbose > 2)
		fprintf(stderr, "beacon(%s%s) update %u, %llu, %llu\n", name.c_str(), (ssm ? "/SSM" : ""), seqnum, timestamp, now);

	beaconMcastState *st = ssm ? &SSM : &ASM;

	st->update(ttl, seqnum, timestamp, now);
}

void beaconMcastState::refresh(uint32_t seq, uint64_t now) {
	lastseq = seq;
	s.timestamp = 0;
	s.lastupdate = now;

	packetcount = packetcountreal = 0;
	pointer = 0;

	lastdelay = lastjitter = lastloss = lastdup = lastooo = 0;
	s.avgdelay = s.avgjitter = s.avgloss = s.avgdup = s.avgooo = 0;
	s.valid = false;
}

void beaconMcastState::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t _now) {
	uint64_t now = (uint32_t)_now;

	int64_t diff = udiff(now, timestamp);

	if (udiff(seqnum, lastseq) > PACKETS_VERY_OLD) {
		refresh(seqnum - 1, now);
	}

	if (seqnum < lastseq && (lastseq - seqnum) >= packetcount)
		return;

	s.timestamp = timestamp;
	s.lastupdate = _now;

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

	*((uint32_t *)(b + 0)) = htonl((uint32_t)st.s.timestamp);
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

int build_nreport(uint8_t *buff, int maxlen, int type) {
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

	if (type == WEBSITE_REPORT_EVENT) {
		for (WebSites::const_iterator j = webSites.begin(); j != webSites.end(); j++)
			if (!write_tlv_string(buff, maxlen, ptr, j->first, j->second.c_str()))
				return -1;
		return ptr;
	}

	uint64_t now = get_timestamp();

	for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.identified)
			continue;

		if (!i->second.ASM.s.valid && !i->second.SSM.s.valid)
			continue;

		int len = 18;

		if (i->first.ss_family == AF_INET)
			len = 6;

		if (type == MAP_REPORT_EVENT) {
			int namelen = i->second.name.size();
			int contactlen = i->second.adminContact.size();
			len += 2 + namelen + 2 + contactlen;
		} else {
			len += (i->second.ASM.s.valid ? 22 : 0) + (i->second.SSM.s.valid ? 22 : 0);
		}

		if (!write_tlv_start(buff, maxlen, ptr, i->first.ss_family == AF_INET6 ? T_SOURCE_INFO : T_SOURCE_INFO_IPv4, len))
			break;

		if (i->first.ss_family == AF_INET6) {
			sockaddr_in6 *addr = (sockaddr_in6 *)&i->first;

			memcpy(buff + ptr, &addr->sin6_addr, sizeof(in6_addr));
			*((uint16_t *)(buff + ptr + 16)) = addr->sin6_port;

			ptr += 18;
		} else {
			sockaddr_in *addr = (sockaddr_in *)&i->first;

			memcpy(buff + ptr, &addr->sin_addr, sizeof(in_addr));
			*((uint16_t *)(buff + ptr + 4)) = addr->sin_port;

			ptr += 6;
		}

		if (type == MAP_REPORT_EVENT) {
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

int send_report(int type) {
	int len;

	len = build_nreport(buffer, sizeof(buffer), type);
	if (len < 0)
		return len;

	for (vector<address>::const_iterator i = redist.begin(); i != redist.end(); i++) {
		const address *to = &(*i);

		char tmp[64];
		to->print(tmp, sizeof(tmp));

		if (verbose) {
			cerr << "Sending Report to " << tmp << endl;
		}

		int res;
		if ((res = sendto(mcastSock, buffer, len, 0, (struct sockaddr *)to, sizeof(struct sockaddr_in6))) < 0) {
			cerr << "Failed to send report to " << tmp << ": " << strerror(errno) << endl;
		} else {
			bytesSent += res;
		}
	}

	return 0;
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

void dumpStats(FILE *fp, const Stats &s, uint64_t now, int sttl, bool diff) {
	if (!diff)
		fprintf(fp, " ttl=\"%i\"", s.rttl);
	else if (sttl)
		fprintf(fp, " ttl=\"%i\"", sttl - s.rttl);
	fprintf(fp, " rptage=\"%u\"", (uint32_t)((now - s.lastupdate) / 1000));
	fprintf(fp, " loss=\"%.1f\"", s.avgloss);
	fprintf(fp, " delay=\"%.3f\"", s.avgdelay);
	fprintf(fp, " jitter=\"%.3f\"", s.avgjitter);
	fprintf(fp, " ooo=\"%.3f\"", s.avgooo);
	fprintf(fp, " dup=\"%.3f\"", s.avgdup);
}

void do_dump() {
	char tmpd[256], tmpn[256];

	strncpy(tmpd, dumpFile.c_str(), sizeof(tmpd));
	strncpy(tmpn, dumpFile.c_str(), sizeof(tmpn));

	char *basen = basename(tmpn);
	char *dirn = dirname(tmpd);

	string tmpf = dirn;
	tmpf += "/.working.";
	tmpf += basen;

	FILE *fp = fopen(tmpf.c_str(), "w");
	if (!fp)
		return;

	char tmp[64];

	fprintf(fp, "<beacons int=\"%.2lf\">\n", beacInt);

	uint64_t now = get_timestamp();

	if (!probeAddr.is_unspecified()) {
		beaconUnicastAddr.print(tmp, sizeof(tmp));

		fprintf(fp, "\t<beacon name=\"%s\" group=\"%s\" addr=\"%s\"",
				beaconName, sessionName, tmp);
		if (!adminContact.empty())
			fprintf(fp, " contact=\"%s\"", adminContact.c_str());
		if (ssmMcastSock) {
			ssmProbeAddr.print(tmp, sizeof(tmp));
			fprintf(fp, " ssmgroup=\"%s\"", tmp);
		}
		fprintf(fp, " age=\"%llu\" lastupdate=\"0\">\n", (now - startTime) / 1000);

		for (WebSites::const_iterator j = webSites.begin(); j != webSites.end(); j++) {
			const char *typnam = j->first == T_WEBSITE_GENERIC ? "generic" : (j->first == T_WEBSITE_LG ? "lg" : "matrix");
			fprintf(fp, "\t\t<website type=\"%s\" url=\"%s\" />\n", typnam, j->second.c_str());
		}

		fprintf(fp, "\t\t<sources>\n");

		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			if (i->second.ASM.s.valid && i->second.identified) {
				i->first.print(tmp, sizeof(tmp));
				fprintf(fp, "\t\t\t<source");
				fprintf(fp, " name=\"%s\"", i->second.name.c_str());
				if (!i->second.adminContact.empty())
					fprintf(fp, " contact=\"%s\"", i->second.adminContact.c_str());
				fprintf(fp, " addr=\"%s\"", tmp);
				fprintf(fp, " age=\"%llu\"\n\t\t\t\t", (now - i->second.creation) / 1000);
				if (i->second.ASM.s.valid)
					dumpStats(fp, i->second.ASM.s, now, i->second.sttl, true);
				fprintf(fp, ">\n");

				for (WebSites::const_iterator j = i->second.webSites.begin(); j != i->second.webSites.end(); j++) {
					const char *typnam = j->first == T_WEBSITE_GENERIC ? "generic" : (j->first == T_WEBSITE_LG ? "lg" : "matrix");
					fprintf(fp, "\t\t\t\t<website type=\"%s\" url=\"%s\" />\n", typnam, j->second.c_str());
				}

				if (i->second.SSM.s.valid) {
					fprintf(fp, "\t\t\t\t<ssm");
					dumpStats(fp, i->second.SSM.s, now, i->second.sttl, true);
					fprintf(fp, " />\n");
				}
				fprintf(fp, "\t\t\t</source>\n");
			}
		}

		fprintf(fp, "\t\t</sources>\n");

		fprintf(fp, "\t</beacon>\n");

		fprintf(fp, "\n");
	}

	for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
		fprintf(fp, "\t<beacon");
		if (i->second.identified) {
			fprintf(fp, " name=\"%s\"", i->second.name.c_str());
			if (!i->second.adminContact.empty())
				fprintf(fp, " contact=\"%s\"", i->second.adminContact.c_str());
		}
		i->first.print(tmp, sizeof(tmp));
		fprintf(fp, " addr=\"%s\"", tmp);
		fprintf(fp, " age=\"%llu\"", (now - i->second.creation) / 1000);
		fprintf(fp, " lastupdate=\"%llu\"", (now - i->second.lastevent) / 1000);
		fprintf(fp, ">\n");
		fprintf(fp, "\t\t<sources>\n");

		for (beaconSource::ExternalSources::const_iterator j = i->second.externalSources.begin();
				j != i->second.externalSources.end(); j++) {
			fprintf(fp, "\t\t\t<source");
			if (j->second.identified) {
				fprintf(fp, " name=\"%s\"", j->second.name.c_str());
				fprintf(fp, " contact=\"%s\"", j->second.contact.c_str());
			}
			j->first.print(tmp, sizeof(tmp));
			fprintf(fp, " addr=\"%s\"", tmp);
			fprintf(fp, " age=\"%u\"\n\t\t\t\t", j->second.age);
			if (j->second.ASM.valid) {
				dumpStats(fp, j->second.ASM, now, i->second.sttl, false);
			}
			if (j->second.SSM.valid) {
				fprintf(fp, ">\n");
				fprintf(fp, "\t\t\t\t\t<ssm");
				dumpStats(fp, j->second.SSM, now, i->second.sttl, false);
				fprintf(fp, " /></source>\n");
			} else {
				fprintf(fp, " />\n");
			}
		}

		fprintf(fp, "\t\t</sources>\n");
		fprintf(fp, "\t</beacon>\n");
	}

	fprintf(fp, "</beacons>\n");

	fclose(fp);

	rename(tmpf.c_str(), dumpFile.c_str());
}

void do_bw_dump(bool big) {
	if (big) {
		fprintf(stdout, "BW Usage for 600 secs: Received %llu bytes (%.2lf Kb/s) Sent %llu bytes (%.2lf Kb/s)\n",
				bigBytesReceived, bigBytesReceived * 8 / (1000. * 600), bigBytesSent, bigBytesSent * 8 / (1000. * 600));
		bigBytesReceived = 0;
		bigBytesSent = 0;
		lastDumpBwTS = get_timestamp();
	} else {
		double incomingRate = bytesReceived * 8 / 10000.;

		if (dumpBwReport) {
			fprintf(stdout, "BW: Received %u bytes (%.2f Kb/s) Sent %u bytes (%.2f Kb/s)\n",
					bytesReceived, incomingRate, bytesSent, bytesSent * 8 / 10000.);
		}

		bigBytesReceived += bytesReceived;
		bigBytesSent += bytesSent;
		bytesReceived = 0;
		bytesSent = 0;

		// adjust beacInt
		if (incomingRate < 4.)
			incomingRate = 4.;

		// Increase traffic will result in a larger interval between probe sending events
		beacInt = 4 * (log(incomingRate) / 1.38);
	}
}

void dumpBigBwStats(int) {
	uint64_t diff = (get_timestamp() - lastDumpBwTS) / 1000;
	fprintf(stdout, "BW Usage for %llu secs: Received %llu bytes (%.2lf Kb/s) Sent %llu bytes (%.2lf Kb/s)\n", diff,
			bigBytesReceived, bigBytesReceived * 8 / (1000. * diff), bigBytesSent, bigBytesSent * 8 / (1000. * diff));
}

int MulticastListen(int sock, address *grpaddr) {
	struct group_req grp;

	memset(&grp, 0, sizeof(grp));
	grp.gr_interface = mcastInterface;
	grp.gr_group = *grpaddr;

	return setsockopt(sock, grpaddr->ss_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP, MCAST_JOIN_GROUP, &grp, sizeof(grp));
}

static int SSMJoinLeave(int sock, int type, const address *srcaddr) {
	struct group_source_req req;
	memset(&req, 0, sizeof(req));

	req.gsr_interface = mcastInterface;

	req.gsr_group = ssmProbeAddr;
	req.gsr_source = *srcaddr;

	return setsockopt(sock, IPPROTO_IPV6, type, &req, sizeof(req));
}

int SSMJoin(int sock, const address *srcaddr) {
	return SSMJoinLeave(sock, MCAST_JOIN_SOURCE_GROUP, srcaddr);
}

int SSMLeave(int sock, const address *srcaddr) {
	return SSMJoinLeave(sock, MCAST_LEAVE_SOURCE_GROUP, srcaddr);
}

int SetupSocket(address *addr, bool needTSHL, bool ssm) {
	if (verbose) {
		char tmp[64];
		addr->print(tmp, sizeof(tmp));
		fprintf(stderr, "SetupSocket(%s)\n", tmp);
	}

	int af_family = addr->ss_family;
	int level = af_family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;

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

	if (bind(sock, (sockaddr *)addr, af_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in)) != 0) {
		perror("Failed to bind multicast socket");
		return -1;
	}

	if (needTSHL) {
		if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
			perror("setsockopt(SO_TIMESTAMP)");
			return -1;
		}

		if (setsockopt(sock, level, level == IPPROTO_IPV6 ? IPV6_HOPLIMIT : IP_RECVTTL, &on, sizeof(on)) != 0) {
			perror("receiving hop limit/ttl setsockopt()");
			return -1;
		}
	}

	on = 0;

	if (setsockopt(sock, level, level == IPPROTO_IPV6 ? IPV6_MULTICAST_LOOP : IP_MULTICAST_LOOP, &on, sizeof(on)) != 0) {
		perror("setting multicast loop setsockopt()");
		return -1;
	}

	int ttl = 127;

	if (setsockopt(sock, level, level == IPPROTO_IPV6 ? IPV6_MULTICAST_HOPS : IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
		perror("setsockopt(IPV6_MULTICAST_HOPS)");
		return -1;
	}

	if (!ssm && addr->is_multicast()) {
		if (MulticastListen(sock, addr) != 0) {
			perror("Failed to join multicast group");
			return -1;
		}
	}

	if (sock > largestSock)
		largestSock = sock;

	FD_SET(sock, &readSet);

	return sock;
}

