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

using namespace std;

static const char *magicString = "beacon0600";
static char sessionName[256] = "";
static char beaconName[256];
static char probeName[256] = "";
static struct sockaddr_in6 probeAddr;
static int mcastSock;
static bool verbose = false;

static list<sockaddr_in6> redist;

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
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
};

struct externalBeacon {
	map<string, beaconExternalStats> sources;
};

map<string, externalBeacon> externalBeacons;

static void next_event(struct timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_probe();
static void handle_event();
static void handle_gc();
static int send_probe();
static int send_report();
static int build_probe(uint8_t *, int, uint32_t, uint64_t);

static void do_dump();

static uint64_t get_timestamp();

static void updateStats(const char *, const in6_addr *, uint32_t, uint64_t, uint64_t);

static int IPv6MulticastListen(int, struct in6_addr *);

static uint8_t buffer[2048];

extern char *optarg;

void usage() {
	fprintf(stderr, "Usage: dbeacon [OPTIONS...]\n\n");
	fprintf(stderr, "  -n NAME                Specifies the beacon name\n");
	fprintf(stderr, "  -b BEACON_ADDR/PORT    Multicast group address to send probes to\n");
	fprintf(stderr, "  -r REDIST_ADDR/PORT    Redistribute reports to the supplied host/port. Multiple may be supplied\n");
	fprintf(stderr, "  -d                     Dump reports to dump.xml each 5 secs\n");
	fprintf(stderr, "  -l                     Listen for reports from other probes\n");
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
	bool listen = false;

	while (1) {
		res = getopt(argc, argv, "n:b:r:dlhv");
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
		} else if (res == 'r') {
			struct sockaddr_in6 addr;
			if (!parse_addr_port(optarg, &addr)) {
				fprintf(stderr, "Bad address format.\n");
				return -1;
			}
			redist.push_back(addr);
		} else if (res == 'd') {
			dump = true;
		} else if (res == 'l') {
			listen = true;
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

	if (IN6_IS_ADDR_UNSPECIFIED(&probeAddr.sin6_addr)) {
		fprintf(stderr, "No beacon address supplied.\n");
		return -1;
	}

	inet_ntop(AF_INET6, &probeAddr.sin6_addr, sessionName, sizeof(sessionName));
	sprintf(sessionName + strlen(sessionName), ":%u", 10000);

	mcastSock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (mcastSock < 0) {
		perror("Failed to create multicast socket");
		return -1;
	}

	if (bind(mcastSock, (struct sockaddr *)&probeAddr, sizeof(probeAddr)) != 0) {
		perror("Failed to bind multicast socket");
		return -1;
	}

	int on = 1;

	if (setsockopt(mcastSock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	if (setsockopt(mcastSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	on = 0;

	if (setsockopt(mcastSock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) != 0) {
		perror("setsockopt");
		return -1;
	}

	int ttl = 255;

	if (setsockopt(mcastSock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) != 0) {
		perror("setsockopt");
		return -1;
	}

	if (IPv6MulticastListen(mcastSock, &probeAddr.sin6_addr) != 0) {
		perror("Failed to join multicast beacon group");
		return -1;
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

		FD_ZERO(&readset);
		FD_SET(mcastSock, &readset);

		next_event(&eventm);

		res = select(mcastSock + 1, &readset, 0, 0, &eventm);
		if (res < 0) {
			perror("Select failed");
			return -1;
		} else if (res == 0) {
			handle_event();
		} else {
			handle_probe();
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

void handle_probe() {
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

	len = recvmsg(mcastSock, &msg, 0);
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

static inline bool write_string(uint8_t *buffer, int *pointer, int maxlen, const char *str) {
	if ((*pointer + (int)strlen(str) + 1) > maxlen)
		return false;

	buffer[*pointer] = strlen(str);
	memcpy(buffer + *pointer + 1, str, strlen(str));

	(*pointer) += 1 + strlen(str);

	return true;
}

static inline bool write_long(uint8_t *buffer, int *pointer, int maxlen, int d) {
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%i", d);

	return write_string(buffer, pointer, maxlen, tmp);
}

static inline bool write_float(uint8_t *buffer, int *pointer, int maxlen, float f, int d) {
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%f", f);

	return write_string(buffer, pointer, maxlen, tmp);
}

static inline bool write_longlong(uint8_t *buffer, int *pointer, int maxlen, uint64_t d) {
	char tmp[64];

	snprintf(tmp, sizeof(tmp), "%llu", d);

	return write_string(buffer, pointer, maxlen, tmp);
}

static inline bool write_char(uint8_t *buffer, int *pointer, int maxlen, char c) {
	if ((*pointer + 1) > maxlen)
		return false;
	buffer[*pointer] = c;
	(*pointer) ++;
	return true;
}

int build_report(uint8_t *buffer, int maxlen) {
	int pointer = 0;

	if (!write_string(buffer, &pointer, maxlen, sessionName))
		return -1;
	if (!write_string(buffer, &pointer, maxlen, probeName))
		return -1;

	if (!write_string(buffer, &pointer, maxlen, "")) // host ip
		return -1;
	if (!write_string(buffer, &pointer, maxlen, "")) // host ip 2nd part
		return -1;
	if (!write_string(buffer, &pointer, maxlen, "")) // OS name
		return -1;
	if (!write_string(buffer, &pointer, maxlen, "")) // OS version
		return -1;
	if (!write_string(buffer, &pointer, maxlen, "")) // machine arch
		return -1;
	if (!write_string(buffer, &pointer, maxlen, "")) // java vm shitness
		return -1;

	for (map<string, beaconSource>::const_iterator i = sources.begin(); i != sources.end(); i++) {
		if (!i->second.hasstats)
			continue;
		if (!write_string(buffer, &pointer, maxlen, i->first.c_str()))
			return -1;
		if (!write_longlong(buffer, &pointer, maxlen, i->second.lasttimestamp))
			return -1;
		if (!write_float(buffer, &pointer, maxlen, i->second.avgdelay, 0))
			return -1;
		if (!write_float(buffer, &pointer, maxlen, i->second.avgjitter, 1))
			return -1;
		if (!write_float(buffer, &pointer, maxlen, i->second.avgloss, 2))
			return -1;
		if (!write_float(buffer, &pointer, maxlen, i->second.avgooo, 3))
			return -1;
		if (!write_float(buffer, &pointer, maxlen, i->second.avgdup, 3))
			return -1;
	}

	if (!write_char(buffer, &pointer, maxlen, '#'))
		return -1;

	return pointer;
}

int send_report() {
	int len = build_report(buffer, sizeof(buffer));
	if (len < 0)
		return len;

	for (list<sockaddr_in6>::const_iterator i = redist.begin(); i != redist.end(); i++) {
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
	int len = 0;

	memcpy(buff, magicString, strlen(magicString));
	len += strlen(magicString);

	if (!write_string(buff, &len, maxlen, probeName))
		return -1;

	if (!write_long(buff, &len, maxlen, sn))
		return -1;

	if (!write_longlong(buff, &len, maxlen, ts))
		return -1;

	return len;
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

	for (map<string, externalBeacon>::const_iterator i = externalBeacons.begin(); i != externalBeacons.end(); i++) {
		fprintf(fp, "\t<beacon name=\"%s\">\n", i->first.c_str());

		for (map<string, beaconExternalStats>::const_iterator j = i->second.sources.begin();
						j != i->second.sources.end(); j++) {
			fprintf(fp, "\t\t\t<source name=\"%s\" loss=\"%.1f\" delay=\"%.3f\" jitter=\"%.3f\" ooo=\"%.3f\" dup=\"%.3f\" />\n",
				j->first.c_str(), j->second.avgloss, j->second.avgdelay, j->second.avgjitter, j->second.avgooo, j->second.avgdup);
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


