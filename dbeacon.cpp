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

static const char *magicString = "beacon0600";
static char sessionName[256] = "";
static char beaconName[256];
static char probeName[256] = "";
static struct sockaddr_in6 probeAddr;
static int mcastSock;
static int largestSock = 0;
static fd_set readSet;
static bool verbose = false;

enum content_type {
	JREPORT,
	JPROBE
};

static vector<pair<sockaddr_in6, content_type> > mcastListen;
static vector<pair<int, content_type> > mcastSocks;

static vector<sockaddr_in6> redist;

enum {
	REPORT_EVENT,
	SEND_EVENT,
	GARBAGE_COLLECT_EVENT,
	DUMP_EVENT
};

#define PACKETS_PERIOD 40
#define PACKETS_VERY_OLD 150

struct beaconSource {
	beaconSource();

	string name;
	struct in6_addr addr;

	uint32_t lastseq;
	uint64_t lasttimestamp;

	uint32_t packetcount, packetcountreal;
	uint32_t pointer;

	int lastdelay, lastjitter, lastloss, lastdup, lastooo;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;

	bool hasstats;

	uint32_t cacheseqnum[PACKETS_PERIOD+1];

	void refresh(uint32_t);
	void update(const in6_addr *, uint32_t, uint64_t, uint64_t);
};

static map<string, beaconSource> sources;

struct beaconExternalStats {
	uint64_t timestamp;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
};

struct externalBeacon {
	map<string, beaconExternalStats> sources;
};

map<string, externalBeacon> externalBeacons;

static void next_event(struct timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_jprobe(int);
static void handle_jreport(int);
static void handle_mcast(int, content_type);
static void handle_event();
static void handle_gc();
static int send_probe();
static int send_report();
static int build_probe(uint8_t *, int, uint32_t, uint64_t);

static void do_dump();

static uint64_t get_timestamp();

static void updateStats(const char *, const in6_addr *, uint32_t, uint64_t, uint64_t);

static int SetupSocket(sockaddr_in6 *, bool);
static int IPv6MulticastListen(int, struct in6_addr *);

static uint8_t buffer[2048];

extern char *optarg;

void usage() {
	fprintf(stderr, "Usage: dbeacon [OPTIONS...]\n\n");
	fprintf(stderr, "  -n NAME                Specifies the beacon name\n");
	fprintf(stderr, "  -b BEACON_ADDR/PORT    Multicast group address to send probes to\n");
	fprintf(stderr, "  -r REDIST_ADDR/PORT    Redistribute reports to the supplied host/port. Multiple may be supplied\n");
	fprintf(stderr, "  -M REDIST_ADDR/PORT    Redistribute and listen for reports in multicast addr\n");
	fprintf(stderr, "  -d                     Dump reports to dump.xml each 5 secs\n");
	fprintf(stderr, "  -l LOCAL_ADDR/PORT     Listen for reports from other probes\n");
	fprintf(stderr, "  -L REPORT_ADDR/PORT    Listen to reports from other probs in multicast group REPORT_ADDR\n");
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

	memset(&probeAddr, 0, sizeof(probeAddr));
	probeAddr.sin6_family = AF_INET6;

	bool dump = false;

	while (1) {
		res = getopt(argc, argv, "n:b:r:M:l:L:dhv");
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
		} else if (res == -1) {
			break;
		}
	}

	if (strlen(probeName) == 0) {
		fprintf(stderr, "No name supplied.\n");
		return -1;
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		mcastListen.push_back(make_pair(probeAddr, JPROBE));

		inet_ntop(AF_INET6, &probeAddr.sin6_addr, sessionName, sizeof(sessionName));
		sprintf(sessionName + strlen(sessionName), ":%u", 10000);
	} else {
		strcpy(sessionName, probeName);
	}

	FD_ZERO(&readSet);

	for (vector<pair<sockaddr_in6, content_type> >::iterator i = mcastListen.begin(); i != mcastListen.end(); i++) {
		int sock = SetupSocket(&i->first, i->second == JPROBE);
		if (sock < 0)
			return -1;
		mcastSocks.push_back(make_pair(sock, i->second));
		if (i->second == JPROBE)
			mcastSock = sock;
	}

	fprintf(stdout, "Local name is %s\n", probeName);

	insert_event(SEND_EVENT, 100);
	insert_event(REPORT_EVENT, 4000);
	insert_event(GARBAGE_COLLECT_EVENT, 120000);

	if (dump)
		insert_event(DUMP_EVENT, 5000);

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

void handle_event() {
	timer t = *timers.begin();
	timers.erase(timers.begin());

	switch (t.type) {
	case SEND_EVENT:
		send_probe();
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

	insert_sorted_event(t);
}

void handle_gc() {
	map<string, beaconSource>::iterator i = sources.begin();

	while (i != sources.end()) {
		if (i->second.hasstats) {
			i->second.hasstats = false;
			i++;
		} else {
			map<string, beaconSource>::iterator j = i;
			i++;
			sources.erase(j);
		}
	}
}

void handle_jprobe(int sock) {
	int len, pointer;
	struct sockaddr_in6 from;
	char name[256], tmp[64], *end;
	uint32_t seqnum;
	uint64_t timestamp;
	struct msghdr msg;
	struct iovec iov;
	uint8_t ctlbuf[64];
	uint64_t recvdts = 0;

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

	for (cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr)) {
		if (hdr->cmsg_level == SOL_SOCKET && hdr->cmsg_type == SO_TIMESTAMP) {
			timeval *tv = (timeval *)CMSG_DATA(hdr);
			recvdts = tv->tv_sec;
			recvdts *= 1000;
			recvdts += tv->tv_usec / 1000;
		}
	}

	if (!recvdts)
		return;

	if (len < (int)strlen(magicString))
		return;

	if (memcmp(buffer, magicString, strlen(magicString)) != 0)
		return;

	pointer = strlen(magicString);

	if (len < (pointer + buffer[pointer]))
		return;

	memcpy(name, buffer + pointer + 1, buffer[pointer]);
	name[buffer[pointer]] = 0;

	pointer += buffer[pointer] + 1;

	if (len < (pointer + buffer[pointer]) || buffer[pointer] >= sizeof(tmp))
		return;

	memcpy(tmp, buffer + pointer + 1, buffer[pointer]);
	tmp[buffer[pointer]] = 0;
	pointer += buffer[pointer] + 1;

	seqnum = strtoul(tmp, &end, 10);
	if (*end)
		return;

	if (len < (pointer + buffer[pointer]) || buffer[pointer] >= sizeof(tmp))
		return;

	memcpy(tmp, buffer + pointer + 1, buffer[pointer]);
	tmp[buffer[pointer]] = 0;
	pointer += buffer[pointer] + 1;

	if (sscanf(tmp, "%llu", &timestamp) != 1)
		return;

	updateStats(name, &from.sin6_addr, seqnum, timestamp, recvdts);
}

static int parse_jreport(uint8_t *buffer, int len, string &session, string &probe, externalBeacon &rpt);

void handle_jreport(int sock) {
	sockaddr_in6 from;
	socklen_t fromlen = sizeof(from);
	int len;

	len = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr *)&from, &fromlen);

	if (len < 0)
		return;

	string session, name;
	externalBeacon beac;

	if (parse_jreport(buffer, len, session, name, beac) < 0)
		return;

	externalBeacons[name] = beac;
}

struct jbuffer {
	jbuffer(uint8_t *, int);

	uint8_t *buff;
	int len, pointer;

	bool eob() { return pointer >= len; }
	uint8_t top() const { return buff[pointer]; }

	bool skip_string();
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

int parse_jreport(uint8_t *buffer, int len, string &session, string &probe, externalBeacon &rpt) {
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

		rpt.sources[name] = stats;
	}

	return 0;
}

void handle_mcast(int sock, content_type cnt) {
	if (cnt == JPROBE) {
		handle_jprobe(sock);
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

static inline beaconSource &getSource(const char *name, uint32_t seq) {
	map<string, beaconSource>::iterator i = sources.find(name);
	if (i != sources.end())
		return i->second;

	beaconSource &src = sources[name];

	src.name = name;

	src.lastseq = seq;

	return src;
}

beaconSource::beaconSource() {
	refresh(0);
}

void beaconSource::refresh(uint32_t seq) {
	lastseq = seq;
	lasttimestamp = 0;

	packetcount = packetcountreal = 0;
	pointer = 0;

	lastdelay = lastjitter = lastloss = lastdup = lastooo = 0;
	avgdelay = avgjitter = avgloss = avgdup = avgooo = 0;

	hasstats = false;
}

void beaconSource::update(const in6_addr *from, uint32_t seqnum, uint64_t timestamp, uint64_t now) {
	int64_t diff = now - (int64_t)timestamp;

	if (diff < 0)
		return;

	if (seqnum < lastseq && (lastseq - seqnum) > PACKETS_VERY_OLD) {
		refresh(seqnum - 1);
	}

	if (seqnum < lastseq && (seqnum - lastseq) >= packetcount)
		return;

	memcpy(&addr, from, sizeof(in6_addr));

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

		if (verbose) {
			cout << "Updating " << name << ": " << avgdelay << ", " << avgloss << ", " << avgooo << ", " << avgdup << endl;
		}
	}
}

void updateStats(const char *name, const in6_addr *from, uint32_t seqnum, uint64_t timestamp, uint64_t now) {
	getSource(name, seqnum).update(from, seqnum, timestamp, now);
}

int send_probe() {
	static uint32_t seq = 0;
	int len;

	len = build_probe(buffer, sizeof(buffer), seq, get_timestamp());
	seq++;

	return sendto(mcastSock, buffer, len, 0, (struct sockaddr *)&probeAddr, sizeof(probeAddr));
}

int build_report(uint8_t *buffer, int maxlen) {
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

	for (map<string, beaconSource>::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.hasstats)
			continue;
		if (!buf.write_string(i->first))
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
	int len = build_report(buffer, sizeof(buffer));
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

int build_probe(uint8_t *buff, int maxlen, uint32_t sn, uint64_t ts) {
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

int build_new_probe(uint8_t *buff, int maxlen, uint32_t sn, uint64_t ts) {
	if (maxlen < (int)(4 + 1 + strlen(beaconName) + 4 + 8))
		return -1;
	*((uint32_t *)buff) = htonl(0xbeac0000);
	int l = strlen(beaconName);
	buff[4] = l;
	memcpy(buff + 5, beaconName, l);

	*((uint32_t *)(buff + 5 + l)) = htonl(sn);
	*((uint32_t *)(buff + 5 + l + 4)) = htonl((uint32_t)((ts >> 32) & 0xffffffff));
	*((uint32_t *)(buff + 5 + l + 8)) = htonl((uint32_t)(ts & 0xffffffff));

	return 4 + 4 + 8 + 1 + l;
}

void do_dump() {
	FILE *fp = fopen("dump.xml", "w");
	if (!fp)
		return;

	fprintf(fp, "<beacons>\n");

	if (!IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		fprintf(fp, "\t<beacon name=\"%s\" group=\"%s\">\n", probeName, sessionName);
		fprintf(fp, "\t\t<sources>\n");

		char tmp[64];

		for (map<string, beaconSource>::const_iterator i = sources.begin(); i != sources.end(); i++) {
			if (i->second.hasstats) {
				inet_ntop(AF_INET6, &i->second.addr, tmp, sizeof(tmp));
				fprintf(fp, "\t\t\t<source>\n");
				fprintf(fp, "\t\t\t\t<name>%s</name>\n", i->first.c_str());
				fprintf(fp, "\t\t\t\t<address>%s</address>\n", tmp);
				fprintf(fp, "\t\t\t\t<loss>%.1f</loss>\n", i->second.avgloss);
				fprintf(fp, "\t\t\t\t<delay>%.3f</delay>\n", i->second.avgdelay);
				fprintf(fp, "\t\t\t\t<jitter>%.3f</jitter>\n", i->second.avgjitter);
				fprintf(fp, "\t\t\t\t<ooo>%.3f</ooo>\n", i->second.avgooo);
				fprintf(fp, "\t\t\t\t<dup>%.3f</dup>\n", i->second.avgdup);
				fprintf(fp, "\t\t\t</source>\n");
			}
		}

		fprintf(fp, "\t\t</sources>\n");

		fprintf(fp, "\t</beacon>\n");

		fprintf(fp, "\n");
	}

	for (map<string, externalBeacon>::const_iterator i = externalBeacons.begin(); i != externalBeacons.end(); i++) {
		fprintf(fp, "\t<beacon name=\"%s\">\n", i->first.c_str());

		for (map<string, beaconExternalStats>::const_iterator j = i->second.sources.begin();
						j != i->second.sources.end(); j++) {
			fprintf(fp, "\t\t\t<source name=\"%s\" timestamp=\"%llu\" loss=\"%.1f\" delay=\"%.3f\" jitter=\"%.3f\" ooo=\"%.3f\" dup=\"%.3f\" />\n",
				j->first.c_str(), j->second.timestamp, j->second.avgloss, j->second.avgdelay, j->second.avgjitter, j->second.avgooo, j->second.avgdup);
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

int SetupSocket(sockaddr_in6 *addr, bool needTimeStamp) {
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("Failed to create multicast socket");
		return -1;
	map<string, externalBeacon> externalBeacons;
	}

	if (bind(sock, (struct sockaddr *)addr, sizeof(*addr)) != 0) {
		perror("Failed to bind multicast socket");
		return -1;
	}

	int on = 1;

	if (needTimeStamp) {
		if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
			perror("setsockopt");
			return -1;
		}
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&addr->sin6_addr)) {
		on = 0;

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) != 0) {
			perror("setsockopt");
			return -1;
		}

		int ttl = 255;

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0) {
			perror("setsockopt");
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


