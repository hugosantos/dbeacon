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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <vector>

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
#define NEW_BEAC_VER	0

static const char *magicString = "beacon0600";
static const int magicLen = 10;
static char sessionName[256] = "";
static char beaconName[256];
static char probeName[256] = "";
static string adminContact;
static struct sockaddr_in6 probeAddr;
static int mcastSock;
static int largestSock = 0;
static fd_set readSet;
static bool verbose = false;
static bool newProtocol = false;

enum content_type {
	JREPORT,
	JPROBE,

	NPROBE,
	NREPORT
};

static vector<pair<sockaddr_in6, content_type> > mcastListen;
static vector<pair<int, content_type> > mcastSocks;

static vector<sockaddr_in6> redist;

enum {
	REPORT_EVENT,
	SEND_EVENT,
	GARBAGE_COLLECT_EVENT,
	DUMP_EVENT,

	SENDING_EVENT,
	WILLSEND_EVENT
};

#define PACKETS_PERIOD 40
#define PACKETS_VERY_OLD 150

struct beaconSource {
	beaconSource();

	bool identified;
	string name;
	string adminContact;
	struct in6_addr addr;

	uint64_t creation;

	uint64_t lastevent;

	uint32_t lastseq;
	uint64_t lasttimestamp;

	int lastttl;

	uint32_t packetcount, packetcountreal;
	uint32_t pointer;

	int lastdelay, lastjitter, lastloss, lastdup, lastooo;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;

	bool hasstats;

	uint32_t cacheseqnum[PACKETS_PERIOD+1];

	void setName(const string &);
	void refresh(uint32_t, uint64_t);
	void update(uint32_t, uint64_t, uint64_t);
};

typedef pair<in6_addr, uint16_t> beaconSourceAddr;
typedef map<beaconSourceAddr, beaconSource> Sources;

static Sources sources;

struct beaconExternalStats {
	uint64_t timestamp;
	uint64_t lastlocalupdate;
	uint32_t age, ttl;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
};

struct externalBeacon {
	in6_addr addr;
	uint64_t lastupdate;
	map<string, beaconExternalStats> sources;
};

typedef map<string, externalBeacon> ExternalBeacons;
ExternalBeacons externalBeacons;

static void next_event(struct timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_probe(int, content_type);
static void handle_jprobe(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len);
static void handle_nmsg(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buffer, int len);
static void handle_jreport(int);
static int parse_jreport(uint8_t *buffer, int len, uint64_t, string &session, string &probe, externalBeacon &rpt);
static void handle_mcast(int, content_type);
static void handle_event();
static void handle_gc();
static int send_jprobe();
static int send_nprobe();
static int send_report();
static int build_jprobe(uint8_t *, int, uint32_t, uint64_t);
static int build_nprobe(uint8_t *, int, uint32_t, uint64_t);

static void do_dump();

static uint64_t get_timestamp();

static inline void updateStats(const char *, const sockaddr_in6 *, int, uint32_t, uint64_t, uint64_t);

static int SetupSocket(sockaddr_in6 *, bool);
static int IPv6MulticastListen(int, struct in6_addr *);

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
	fprintf(stderr, "  -b BEACON_ADDR/PORT    Multicast group address to send probes to\n");
	fprintf(stderr, "  -r REDIST_ADDR/PORT    Redistribute reports to the supplied host/port. Multiple may be supplied\n");
	fprintf(stderr, "  -M REDIST_ADDR/PORT    Redistribute and listen for reports in multicast addr\n");
	fprintf(stderr, "  -d                     Dump reports to dump.xml each 5 secs\n");
	fprintf(stderr, "  -l LOCAL_ADDR/PORT     Listen for reports from other probes\n");
	fprintf(stderr, "  -L REPORT_ADDR/PORT    Listen to reports from other probs in multicast group REPORT_ADDR\n");
	fprintf(stderr, "  -P                     Use new protocol\n");
	fprintf(stderr, "  -v                     be (very) verbose\n");
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

	bool dump = false;
	bool force = false;

	while (1) {
		res = getopt(argc, argv, "n:a:b:r:M:l:L:dhvPf");
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
		} else if (res == 'd') {
			dump = true;
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
		} else if (res == 'h') {
			usage();
			return -1;
		} else if (res == 'v') {
			verbose = true;
		} else if (res == 'P') {
			newProtocol = true;
		} else if (res == 'f') {
			force = true;
		} else if (res == -1) {
			break;
		}
	}

	if (strlen(probeName) == 0) {
		fprintf(stderr, "No name supplied.\n");
		return -1;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		if (!newProtocol) {
			mcastListen.push_back(make_pair(probeAddr, JPROBE));
	
			insert_event(SEND_EVENT, 100);
			insert_event(REPORT_EVENT, 4000);
		} else {
			if (!force && adminContact.empty()) {
				fprintf(stderr, "No administration contact supplied.\n");
				return -1;
			}

			mcastListen.push_back(make_pair(probeAddr, NPROBE));

			insert_event(SENDING_EVENT, 100);
			insert_event(REPORT_EVENT, 10000);

			redist.push_back(probeAddr);
		}

		inet_ntop(AF_INET6, &probeAddr.sin6_addr, sessionName, sizeof(sessionName));
		sprintf(sessionName + strlen(sessionName), ":%u", 10000);
	} else {
		strcpy(sessionName, probeName);
	}

	FD_ZERO(&readSet);

	for (vector<pair<sockaddr_in6, content_type> >::iterator i = mcastListen.begin(); i != mcastListen.end(); i++) {
		int sock = SetupSocket(&i->first, i->second == JPROBE || i->second == NPROBE);
		if (sock < 0)
			return -1;
		mcastSocks.push_back(make_pair(sock, i->second));
		if (i->second == JPROBE || i->second == NPROBE)
			mcastSock = sock;
	}

	fprintf(stdout, "Local name is %s\n", probeName);

	insert_event(GARBAGE_COLLECT_EVENT, 120000);

	if (dump)
		insert_event(DUMP_EVENT, 5000);

	if (newProtocol)
		send_report();

	while (1) {
		fd_set readset;
		struct timeval eventm;

		memcpy(&readset, &readSet, sizeof(fd_set));

		next_event(&eventm);

		res = select(largestSock + 1, &readset, 0, 0, &eventm);
		if (res < 0) {
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
		eventm->tv_usec = 0;
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

	switch (t.type) {
	case SEND_EVENT:
		send_jprobe();
		break;
	case SENDING_EVENT:
		send_nprobe();
		send_count ++;
		break;
	case REPORT_EVENT:
		send_report();
		break;
	case GARBAGE_COLLECT_EVENT:
		handle_gc();
		break;
	case DUMP_EVENT:
		do_dump();
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
			if (i->second.hasstats) {
				i->second.hasstats = false;
				i->second.lastevent = now;
			} else {
				remove = true;
			}
		}
		if (!remove) {
			i++;
		} else {
			Sources::iterator j = i;
			i++;
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
			for (map<string, beaconExternalStats>::iterator m = k->second.sources.begin(); m != k->second.sources.end();) {
				if ((now - m->second.lastlocalupdate) > 120000) {
					map<string, beaconExternalStats>::iterator n = m;
					m++;
					k->second.sources.erase(n);
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
		handle_nmsg(&from, recvdts, ttl, buffer, len);
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

	return src;
}

void handle_nmsg(sockaddr_in6 *from, uint64_t recvdts, int ttl, uint8_t *buff, int len) {
	if (len < 4)
		return;

	if (ntohs(*((uint16_t *)buff)) != 0xbeac)
		return;

	if (buff[2] != NEW_BEAC_VER)
		return;

	if (buff[3] == 0) {
		if (len == 12) {
			uint32_t seq = ntohl(*((uint32_t *)(buff + 4)));
			uint32_t ts = ntohl(*((uint32_t *)(buff + 4)));
			getSource(from->sin6_addr, ntohs(from->sin6_port), 0, recvdts).update(seq, ts, recvdts);
		}
	} else if (buff[3] == 1) {
		if (len < 7 || (7 + buff[5]) > len || (7 + buff[5] + buff[6 + buff[5]]) > len)
			return;

		beaconSource &src = getSource(from->sin6_addr, ntohs(from->sin6_port), 0, recvdts);

		src.lastttl = buff[4] - ttl;

		string beacName((char *)buff + 5, buff[5]);

		src.setName(beacName);
		src.adminContact = string((char *)buff + 6 + buff[5], buff[6 + buff[5]]);

		int hlen = 7 + buff[5] + buff[6 + buff[5]];
		uint8_t *ptr = buff + hlen;
		int plen = hlen;

		uint32_t tmp;

		externalBeacon beac;

		while (plen < len) {
			int namelen = ptr[0];
			int elen = 4 + 4 + 1 + 4 * 2 + 3;
			if ((plen + 1 + namelen + elen) > len)
				break;

			string name((char *)ptr + 1, namelen);
			ptr += 1 + namelen;

			beaconExternalStats stats;

			stats.lastlocalupdate = recvdts;

			stats.timestamp = ntohl(*(uint32_t *)ptr);
			stats.age = ntohl(*(uint32_t *)(ptr + 4));
			stats.ttl = ptr[8];
			tmp = ntohl(*(uint32_t *)(ptr + 9));
			stats.avgdelay = *(float *)&tmp;
			tmp = ntohl(*(uint32_t *)(ptr + 13));
			stats.avgjitter = *(float *)&tmp;

			stats.avgloss = ptr[17] / 255.;
			stats.avgdup = ptr[18] / 255.;
			stats.avgooo = ptr[19] / 255.;

			ptr += 20;

			plen += 1 + namelen + elen;

			beac.sources[name] = stats;
		}

		ExternalBeacons::iterator i = externalBeacons.find(beacName);
		if (i == externalBeacons.end()) {
			externalBeacons.insert(make_pair(beacName, beac));
			i = externalBeacons.find(beacName);
		} else {
			for (map<string, beaconExternalStats>::const_iterator j = beac.sources.begin(); j != beac.sources.end(); j++)
				i->second.sources[j->first] = j->second;
		}

		i->second.lastupdate = recvdts;
		i->second.addr = from->sin6_addr;
	}
}

void handle_jreport(int sock) {
	sockaddr_in6 from;
	socklen_t fromlen = sizeof(from);
	int len;

	len = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&from, &fromlen);

	if (len < 0)
		return;

	string session, name;
	externalBeacon beac;

	if (parse_jreport(buffer, len, get_timestamp(), session, name, beac) < 0)
		return;

	ExternalBeacons::iterator i = externalBeacons.find(name);
	if (i == externalBeacons.end()) {
		externalBeacons.insert(make_pair(name, beac));
		i = externalBeacons.find(name);
	} else {
		for (map<string, beaconExternalStats>::const_iterator j = beac.sources.begin(); j != beac.sources.end(); j++)
			i->second.sources[j->first] = j->second;
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
		if (!buf.read_longlong(stats.timestamp))
			return -1;
		if (!buf.read_float(stats.avgdelay))
			return -1;
		if (!buf.read_float(stats.avgjitter))
			return -1;
		if (!buf.read_float(stats.avgloss))
			return -1;
		if (!buf.read_float(stats.avgooo))
			return -1;
		if (!buf.read_float(stats.avgdup))
			return -1;
		stats.age = 0;
		stats.ttl = 0;

		rpt.sources[name] = stats;
	}

	return 0;
}

void handle_mcast(int sock, content_type cnt) {
	if (cnt == JPROBE) {
		handle_probe(sock, JPROBE);
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
	refresh(0, 0);
}

void beaconSource::setName(const string &n) {
	name = n;
	identified = true;
}

void beaconSource::refresh(uint32_t seq, uint64_t now) {
	lastseq = seq;
	lasttimestamp = 0;
	lastevent = now;

	lastttl = 0;

	packetcount = packetcountreal = 0;
	pointer = 0;

	lastdelay = lastjitter = lastloss = lastdup = lastooo = 0;
	avgdelay = avgjitter = avgloss = avgdup = avgooo = 0;

	hasstats = false;
}

template<typename T> T udiff(T a, T b) { if (a > b) return a - b; return b - a; }

void beaconSource::update(uint32_t seqnum, uint64_t timestamp, uint64_t now) {
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
		avgjitter = 15/16. * avgjitter + 1/16. * newjitter;

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
		avgdelay = lastdelay / (float)packetcountreal;
		avgloss = lastloss / (float)packetcount;
		avgooo = lastooo / (float)packetcount;
		avgdup = lastdup / (float)packetcount;

		hasstats = true;

		lastdelay = 0;
		lastloss = 0;
		lastooo = 0;
		lastdup = 0;
		packetcount = 0;
		packetcountreal = 0;
		pointer = 0;

		if (verbose && avgloss < 1) {
			cout << "Updating " << name << ": " << avgdelay << ", " << avgloss << ", " << avgooo << ", " << avgdup << endl;
		}
	}
}

void updateStats(const char *name, const sockaddr_in6 *from, int ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now) {
	beaconSource &src = getSource(from->sin6_addr, ntohs(from->sin6_port), name, now);

	src.addr = from->sin6_addr;
	src.lastttl = 127 - ttl; // we assume jbeacons use TTL 127, which is usually true
	
	src.update(seqnum, timestamp, now);
}

int send_jprobe() {
	static uint32_t seq = rand();
	int len;

	len = build_jprobe(buffer, sizeof(buffer), seq, get_timestamp());
	seq++;

	return sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&probeAddr, sizeof(probeAddr));
}

int send_nprobe() {
	static uint32_t seq = rand();
	int len;

	len = build_nprobe(buffer, sizeof(buffer), seq, get_timestamp());
	seq++;

	return sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&probeAddr, sizeof(probeAddr));
}

int build_nreport(uint8_t *buff, int maxlen) {
	int nl = strlen(beaconName);
	int cl = adminContact.size();

	int len = 4 + 1 + 1 + nl + 1 + cl;

	if (maxlen < len)
		return -1;

	// 0-2 magic
	*((uint16_t *)buff) = htons(0xbeac);

	// 3 version
	buff[2] = NEW_BEAC_VER;

	// 4 packet type
	buff[3] = 1; // Report

	buff[4] = 127; // Original Hop Limit

	buff[5] = nl;
	memcpy(buff + 6, beaconName, nl);

	buff[6 + nl] = cl;
	memcpy(buff + 7 + nl, adminContact.c_str(), cl);

	uint8_t *ptr = buff + 7 + nl + cl;

	uint64_t now = get_timestamp();

	for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.hasstats || !i->second.identified)
			continue;

		int namelen = i->second.name.size();
		int plen = 4 + 4 + 1 + 4 * 2 + 3;
		if ((len + namelen + 1 + plen) > maxlen)
			return -1;

		ptr[0] = namelen;
		memcpy(ptr + 1, i->second.name.c_str(), namelen);

		ptr += 1 + namelen;

		*((uint32_t *)ptr) = htonl((uint32_t)i->second.lasttimestamp);
		*((uint32_t *)(ptr + 4)) = htonl((uint32_t)((i->second.creation - now) / 1000));
		ptr[8] = i->second.lastttl;

		uint32_t *stats = (uint32_t *)(ptr + 9);
		stats[0] = htonl(*((uint32_t *)&i->second.avgdelay));
		stats[1] = htonl(*((uint32_t *)&i->second.avgjitter));

		ptr[17] = (uint8_t)(i->second.avgloss * 0xff);
		ptr[18] = (uint8_t)(i->second.avgdup * 0xff);
		ptr[19] = (uint8_t)(i->second.avgooo * 0xff);

		ptr += plen;
		len += plen + 1 + namelen;
	}
	
	return len;
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
		if (!i->second.hasstats)
			continue;
		if (!buf.write_string(i->second.name))
			return -1;
		if (!buf.write_longlong(i->second.lasttimestamp))
			return -1;
		if (!buf.write_float(i->second.avgdelay)) // 0
			return -1;
		if (!buf.write_float(i->second.avgjitter)) // 1
			return -1;
		if (!buf.write_float(i->second.avgloss)) // 2
			return -1;
		if (!buf.write_float(i->second.avgooo)) // 3
			return -1;
		if (!buf.write_float(i->second.avgdup)) // 3
			return -1;
	}

	if (!buf.write_char('#'))
		return -1;

	return buf.pointer;
}

int send_report() {
	int len;

	if (newProtocol)
		len = build_nreport(buffer, sizeof(buffer));
	else
		len = build_jreport(buffer, sizeof(buffer));
	if (len < 0)
		return len;

	for (vector<sockaddr_in6>::const_iterator i = redist.begin(); i != redist.end(); i++) {
		const sockaddr_in6 *to = &(*i);

		char tmp[64];
		inet_ntop(AF_INET6, &to->sin6_addr, tmp, sizeof(tmp));

		if (verbose) {
			cerr << "Sending Report to " << tmp << "/" << ntohs(to->sin6_port) << endl;
		}

		if (sendto(mcastSock, buffer, len, 0, (struct sockaddr *)to, sizeof(struct sockaddr_in6)) < 0) {
			cerr << "Failed to send report to " << tmp << "/" << ntohs(to->sin6_port) << ": " << strerror(errno) << endl;
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

void do_dump() {
	FILE *fp = fopen("dump.xml", "w");
	if (!fp)
		return;

	char tmp[64];

	fprintf(fp, "<beacons>\n");

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		fprintf(fp, "\t<beacon name=\"%s\" group=\"%s\">\n", probeName, sessionName);
		fprintf(fp, "\t\t<sources>\n");

		uint64_t now = get_timestamp();

		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			if (i->second.hasstats && i->second.identified) {
				inet_ntop(AF_INET6, &i->second.addr, tmp, sizeof(tmp));
				fprintf(fp, "\t\t\t<source");
				fprintf(fp, " name=\"%s\"", i->second.name.c_str());
				if (!i->second.adminContact.empty())
					fprintf(fp, " admin=\"%s\"", i->second.adminContact.c_str());
				fprintf(fp, " address=\"%s\"", tmp);
				fprintf(fp, " ttl=\"%i\"", i->second.lastttl);
				fprintf(fp, " localage=\"%llu\"", (now - i->second.creation) / 1000);
				fprintf(fp, " loss=\"%.1f\"", i->second.avgloss);
				fprintf(fp, " delay=\"%.3f\"", i->second.avgdelay);
				fprintf(fp, " jitter=\"%.3f\"", i->second.avgjitter);
				fprintf(fp, " ooo=\"%.3f\"", i->second.avgooo);
				fprintf(fp, " dup=\"%.3f\"", i->second.avgdup);
				fprintf(fp, " />\n");
			}
		}

		fprintf(fp, "\t\t</sources>\n");

		fprintf(fp, "\t</beacon>\n");

		fprintf(fp, "\n");
	}

	for (map<string, externalBeacon>::const_iterator i = externalBeacons.begin(); i != externalBeacons.end(); i++) {
		inet_ntop(AF_INET6, &i->second.addr, tmp, sizeof(tmp));
		fprintf(fp, "\t<beacon name=\"%s\" addr=\"%s\">\n", i->first.c_str(), tmp);

		for (map<string, beaconExternalStats>::const_iterator j = i->second.sources.begin();
						j != i->second.sources.end(); j++) {
			fprintf(fp, "\t\t\t<source");
			fprintf(fp, " name=\"%s\"", j->first.c_str());
			if (newProtocol) {
				fprintf(fp, " ttl=\"%i\"", j->second.ttl);
				fprintf(fp, " age=\"%llu\"", j->second.age);
			}
			fprintf(fp, " loss=\"%.1f\"", j->second.avgloss);
			fprintf(fp, " delay=\"%.3f\"", j->second.avgdelay);
			fprintf(fp, " jitter=\"%.3f\"", j->second.avgjitter);
			fprintf(fp, " ooo=\"%.3f\"", j->second.avgooo);
			fprintf(fp, " dup=\"%.3f\"", j->second.avgdup);
			fprintf(fp, " />\n");
		}

		fprintf(fp, "\t</beacon>\n");
	}

	fprintf(fp, "</beacons>\n");

	fclose(fp);
}

int IPv6MulticastListen(int sock, struct in6_addr *grpaddr) {
	struct ipv6_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	mreq.ipv6mr_interface = 0;
	memcpy(&mreq.ipv6mr_multiaddr, grpaddr, sizeof(struct in6_addr));

	return setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
}

int SetupSocket(sockaddr_in6 *addr, bool needTSHL) {
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

	if (IN6_IS_ADDR_MULTICAST(&addr->sin6_addr)) {
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


