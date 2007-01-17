/*
 * Copyright (C) 2005-7, Hugo Santos <hugo@fivebits.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * $Id$
 */

#include "dbeacon.h"
#include "address.h"
#include "msocket.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <ctype.h>

#include <assert.h>

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <vector>

using namespace std;

static const char *versionInfo = "0.3.9 ($Rev$)";

static const char *defaultIPv6SSMChannel = "ff3e::beac";
static const char *defaultIPv4SSMChannel = "232.2.3.2";
const char *defaultPort = "10000";
#ifndef SOLARIS
const int defaultTTL = 127;
#else
const int defaultTTL = 64;
#endif
static const char *defaultDumpFile = "dump.xml";

/* time related constants */
static const int timeOutI = 6;
static const int reportI = 2;
static const int ssmReportI = 4;
static const int mapReportI = 6;
static const int websiteReportI = 24;
/* other constants */
static const int probeBurstLength = 10;

// Timer Events
enum {
	GARBAGE_COLLECT_EVENT,
	DUMP_EVENT,
	DUMP_BW_EVENT,
	DUMP_BIG_BW_EVENT,

	SENDING_EVENT,
	WILLSEND_EVENT,

	SSM_SENDING_EVENT,
	WILLSEND_SSM_EVENT,

	// Report types
	REPORT_EVENT = 'R',
	SSM_REPORT_EVENT,
	MAP_REPORT_EVENT,
	WEBSITE_REPORT_EVENT
};

// Timer event names
const char *TimerEventName[] = {
	"Garbage Collect",
	"Dump Stats",
	"Bandwidth stats",
	"Bandwidth stats [2]",
	"Send Probe",
	"New send probe process",
	"SSM Send Probe",
	"New SSM send probe process",

	"Send Report",
	"Send SSM Report",
	"Send Map-Report",
	"Send Website-Report"
};

const char *EventName(int type) {
	if (type < REPORT_EVENT)
		return TimerEventName[type];
	return TimerEventName[type - REPORT_EVENT + 8];
}

static const char *Flags[] = {
	"SSM",
	"SSMPing"
};

static const uint32_t KnownFlags = 2;

static uint32_t timeFact(int val, bool random = false);

string beaconName, adminContact, twoLetterCC;
Sources sources;
WebSites webSites;
address beaconUnicastAddr;
int verbose = 0;
uint32_t flags = 0;

int mcastInterface = 0;

static char sessionName[256];
static address probeAddr;
static const char *probeAddrLiteral = 0;
static const char *probeSSMAddrLiteral = 0;
static bool useSSM = false;
static bool listenForSSM = false;
static bool useSSMPing = false;
static address ssmProbeAddr;
static int mcastSock, ssmMcastSock = 0;
static int largestSock = 0;
static fd_set readSet;
static bool dumpBwReport = false;
static string launchSomething;

static double beacInt = 5.;

static uint64_t startTime = 0;

static const char *dumpFile = 0;

static vector<pair<address, content_type> > mcastListen;
static vector<pair<int, content_type> > mcastSocks;

static vector<address> redist;

static vector<address> ssmBootstrap;

static uint32_t bytesReceived = 0;
static uint32_t bytesSent = 0;

static uint64_t bigBytesReceived = 0;
static uint64_t bigBytesSent = 0;
static uint64_t lastDumpBwTS = 0;

static uint64_t dumpBytesReceived = 0;
static uint64_t dumpBytesSent = 0;
static uint64_t lastDumpDumpBwTS = 0;

static int dumpInterval = 5;
static const char *multicastInterface = 0;
int forceFamily = AF_UNSPEC;

static void next_event(timeval *);
static void insert_event(uint32_t, uint32_t);
static void handle_mcast(int, content_type);
static void handle_event();
static void handle_gc();
static int send_probe();
static int send_ssm_probe();
static int send_report(int);

static void do_dump();
static void do_bw_dump(bool);
extern "C" void dumpBigBwStats(int);
extern "C" void sendLeaveReport(int);

static int SetupSocketAndFDSet(const address &, bool, bool);

static inline double Rand() {
	double f = rand();

	/* Prevent 0.0 and 1.0, thanks to Alexander Gall */
	if (f == 0)
		f = 1;
	else if (f == RAND_MAX)
		f = RAND_MAX-1;

	return f / (double)RAND_MAX;
}

static inline double Exprnd(double mean) {
	return -mean * log(1 - Rand());
}

static const int bufferLen = 8192;
static uint8_t buffer[bufferLen];

void usage() {
	fprintf(stderr, "Usage: dbeacon [OPTIONS...]\n\n");
	fprintf(stderr, "  -n NAME, -name NAME    Specifies the beacon name\n");
	fprintf(stderr, "  -a MAIL                Supply administration contact\n");
	fprintf(stderr, "  -i IN, -interface IN   Use IN instead of the default interface for multicast\n");
	fprintf(stderr, "  -b BEACON_ADDR[/PORT]  Multicast group address to send probes to\n");
	fprintf(stderr, "  -S [GROUP_ADDR[/PORT]] Enables SSM reception/sending on optional GROUP_ADDR/PORT\n");
	fprintf(stderr, "  -O                     Disables the joining of SSM groups but still sends via SSM.\n");
	fprintf(stderr, "                         Use this option if your operating system has problems with SSM\n");
	fprintf(stderr, "  -B ADDR                Bootstraps by joining the specified address\n");
	fprintf(stderr, "  -P, -ssmping           Enable the SSMPing server capability\n");
	fprintf(stderr, "  -s ADDR                Bind to local address\n");
	fprintf(stderr, "  -d [FILE]              Dump periodic reports to dump.xml or specified file\n");
	fprintf(stderr, "  -I N, -interval N      Interval between dumps. Defaults to 5 secs\n");
	fprintf(stderr, "  -W URL, -website URL   Specify a website to announce.\n");
	fprintf(stderr, "  -Wm URL, -matrix URL   Specify your matrix URL\n");
	fprintf(stderr, "  -Wl URL, -lg URL       Specify your LG URL\n");
	fprintf(stderr, "                         will announce an URL for that type instead\n");
	fprintf(stderr, "  -C CC                  Specify your two letter Country Code\n");
	fprintf(stderr, "  -L program             Launch program after each dump.\n");
	fprintf(stderr, "                         The first argument will be the dump filename\n");
	fprintf(stderr, "  -F flag                Set a dbeacon flag to be announced.\n");
	fprintf(stderr, "                         Available flags are: ssmping\n");
	fprintf(stderr, "  -4, -ipv4              Force IPv4 usage\n");
	fprintf(stderr, "  -6, -ipv6              Force IPv6 usage\n");
	fprintf(stderr, "  -v                     be verbose (use several for more verbosity)\n");
	fprintf(stderr, "  -U                     Dump periodic bandwidth usage reports to stdout\n");
	fprintf(stderr, "  -V, -version           Outputs version information and leaves\n");
	fprintf(stderr, "\n");
}

static void debug(FILE *f, const char *format, ...) {
	timeval tv;
	gettimeofday(&tv, 0);

	char tbuf[64];

	/* Some FreeBSDs' tv.tv_sec isn't time_t */
	time_t tv_sec = tv.tv_sec;

	strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", localtime(&tv_sec));

	char buffer[256];

	va_list vl;
	va_start(vl, format);
	vsnprintf(buffer, sizeof(buffer), format, vl);
	va_end(vl);

	fprintf(f, "%s.%06u %s\n", tbuf, (uint32_t)tv.tv_usec, buffer);
}

void fixDumpFile() {
}

extern "C" void waitForMe(int) {
	int whocares;
	wait(&whocares);
}

static int parse_arguments(int, char **);

int main(int argc, char **argv) {
	int res;

	srand(time(NULL));

	char tmp[256];
	if (gethostname(tmp, sizeof(tmp)) != 0) {
		perror("Failed to get hostname");
		return -1;
	}

	beaconName = tmp;

	res = parse_arguments(argc, argv);
	if (res < 0)
		return res;

	MulticastStartup();

	if (beaconName.empty()) {
		fprintf(stderr, "No name supplied.\n");
		return -1;
	}

	fixDumpFile();

	if (multicastInterface) {
		mcastInterface = if_nametoindex(multicastInterface);
		if (mcastInterface <= 0) {
			fprintf(stderr, "Specified interface doesn't exist.\n");
			return -1;
		}
	}

	if (probeAddrLiteral) {
		if (!probeAddr.parse(probeAddrLiteral, true)) {
			return -1;
		}

		probeAddr.print(sessionName, sizeof(sessionName));

		if (!probeAddr.is_multicast()) {
			fprintf(stderr, "Specified probe addr (%s) is not of a multicast group\n", sessionName);
			return -1;
		}

		if (adminContact.empty()) {
			fprintf(stderr, "No administration contact supplied.\n");
			return -1;
		}

		mcastListen.push_back(make_pair(probeAddr, NPROBE));

		insert_event(SENDING_EVENT, 100);
		insert_event(REPORT_EVENT, 10000);
		insert_event(MAP_REPORT_EVENT, 30000);
		insert_event(WEBSITE_REPORT_EVENT, 120000);

		redist.push_back(probeAddr);

		if (useSSM) {
			if (!probeSSMAddrLiteral) {
				int family = forceFamily;

				if (family == AF_UNSPEC) {
					family = probeAddr.family();
				}
				if (family == AF_INET) {
					probeSSMAddrLiteral = defaultIPv4SSMChannel;
				} else {
					probeSSMAddrLiteral = defaultIPv6SSMChannel;
				}
			}

			if (!ssmProbeAddr.parse(probeSSMAddrLiteral, true)) {
				fprintf(stderr, "Bad address format for SSM channel.\n");
				return -1;
			} else if (!ssmProbeAddr.is_unspecified()) {
				insert_event(SSM_SENDING_EVENT, 100);
				insert_event(SSM_REPORT_EVENT, 15000);

				if (listenForSSM) {
					mcastListen.push_back(make_pair(ssmProbeAddr, NSSMPROBE));
				}
			}
		}
	} else {
		if (mcastListen.empty()) {
			fprintf(stderr, "Nothing to do, check `dbeacon -h`.\n");
			return -1;
		} else {
			strcpy(sessionName, beaconName.c_str());
		}
	}

	FD_ZERO(&readSet);

	address local;
	local.set_family(probeAddr.family());

	mcastSock = SetupSocketAndFDSet(local, false, false);
	if (mcastSock < 0)
		return -1;

	// connect the socket to probeAddr, so the source address can be determined

	socklen_t addrlen = probeAddr.addrlen();

	if (beaconUnicastAddr.is_unspecified()) {
		int tmpSock = socket(probeAddr.family(), SOCK_DGRAM, 0);
		if (tmpSock < 0) {
			perror("Failed to create socket to discover local addr");
			return -1;
		}

		if (connect(tmpSock, probeAddr.saddr(), addrlen) != 0) {
			perror("Failed to connect multicast socket");
			return -1;
		}

		beaconUnicastAddr.set_family(probeAddr.family());
		addrlen = beaconUnicastAddr.addrlen();

		if (getsockname(tmpSock, beaconUnicastAddr.saddr(), &addrlen) != 0) {
			perror("getsockname");
			return -1;
		}

		close(tmpSock);
	}

	if (bind(mcastSock, beaconUnicastAddr.saddr(), beaconUnicastAddr.addrlen()) != 0) {
		perror("Failed to bind local socket");
		return -1;
	}

	addrlen = beaconUnicastAddr.addrlen();

	// Retrieve the used port
	if (getsockname(mcastSock, beaconUnicastAddr.saddr(), &addrlen) != 0) {
		perror("getsockname");
		return -1;
	}

	for (vector<pair<address, content_type> >::iterator i = mcastListen.begin(); i != mcastListen.end(); i++) {
		int sock = SetupSocket(i->first, true, i->second == NSSMPROBE);
		if (sock < 0)
			return -1;
		ListenTo(i->second, sock);
		if (i->second == NSSMPROBE) {
			ssmMcastSock = sock;
		}
	}

	if (useSSMPing) {
		if (SetupSSMPing() < 0) {
			fprintf(stderr, "Failed to setup SSM Ping\n");
		} else {
			flags |= SSMPING_CAPABLE;
		}
	}

	if (ssmMcastSock) {
		flags |= SSM_CAPABLE;

		uint64_t now = get_timestamp();
		for (vector<address>::const_iterator i = ssmBootstrap.begin(); i != ssmBootstrap.end(); i++) {
			getSource(*i, 0, now, 0, false);
		}
	} else if (!ssmBootstrap.empty()) {
		fprintf(stderr, "Tried to bootstrap using SSM when SSM is not enabled.\n");
	}

	// Init timer events
	insert_event(GARBAGE_COLLECT_EVENT, 30000);

	if (dumpFile)
		insert_event(DUMP_EVENT, dumpInterval * 1000);

	insert_event(DUMP_BW_EVENT, 10000);

	if (dumpBwReport)
		insert_event(DUMP_BIG_BW_EVENT, 600000);

	send_report(WEBSITE_REPORT_EVENT);

	beaconUnicastAddr.print(tmp, sizeof(tmp), false);

	fprintf(stdout, "Local name is %s [Beacon group: %s, Local address: %s]\n",
					beaconName.c_str(), sessionName, tmp);

	signal(SIGUSR1, dumpBigBwStats);
	signal(SIGINT, sendLeaveReport);

	signal(SIGCHLD, waitForMe); // bloody fork, we dont want to wait for thee

	startTime = lastDumpBwTS = lastDumpDumpBwTS = get_timestamp();

	while (1) {
		fd_set readset;
		timeval eventm;

		memcpy(&readset, &readSet, sizeof(fd_set));

		next_event(&eventm);

		res = select(largestSock + 1, &readset, 0, 0, &eventm);

		if (verbose > 5) {
			fprintf(stderr, "select(): res = %i\n", res);
		}

		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("Select failed");
			return -1;
		} else {
			for (vector<pair<int, content_type> >::const_iterator i = mcastSocks.begin(); i != mcastSocks.end(); ++i)
				if (FD_ISSET(i->first, &readset))
					handle_mcast(i->first, i->second);

			handle_event();
		}
	}

	return 0;
}

void ListenTo(content_type content, int sock) {
	SetupFDSet(sock);

	mcastSocks.push_back(make_pair(sock, content));
}

void show_version() {
	fprintf(stderr, "\n");
	fprintf(stderr, "dbeacon - a Multicast Beacon %s\n", versionInfo);
	fprintf(stderr, "\n");
	fprintf(stderr, "  Copyright (c) 2005-7, Hugo Santos <hugo@fivebits.net>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  http://fivebits.net/proj/dbeacon\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  o Ideas, IPv4 port, SSM pushing by Hoerdt Mickael;\n");
	fprintf(stderr, "  o Ideas and testing by Sebastien Chaumontet;\n");
	fprintf(stderr, "  o SSM Ping originaly by Stig Venaas\n");
	fprintf(stderr, "    - first proposed by Pavan Namburi, Kamil Sarac and Kevin C. Almeroth;\n");
	fprintf(stderr, "  o Bernhard Schmidt provided valuable resources and helped during testing.\n");
	fprintf(stderr, "\n");

	exit(1);
}

enum {
	NAME = 1,
	CONTACT,
	INTERFACE,
	BEACONADDR,
	SSMADDR,
	SSMSENDONLY,
	BOOTSTRAP,
	ENABLESSMPING,
	SOURCEADDR,
	DUMP,
	DUMPINTERVAL,
	DUMPEXEC,
	SPECWEBSITE,
	SPECMATRIX,
	SPECLG,
	COUNTRY,
	SPECFLAG,
	VERBOSE,
	DUMPBW,
	HELP,
	FORCEv4,
	FORCEv6,
	SHOWVERSION
};

enum {
	NO_ARG = 0,
	REQ_ARG,
	OPT_ARG
};

static const struct param_tok {
	int name;
	const char *sf, *lf;
	int param;
} param_format[] = {
	{ NAME,		"n", "name", REQ_ARG },
	{ CONTACT,	"a", 0, REQ_ARG },
	{ INTERFACE,	"i", "interface", REQ_ARG },
	{ BEACONADDR,	"b", 0, REQ_ARG },
	{ SSMADDR,	"S", 0, OPT_ARG },
	{ SSMSENDONLY,	"O", 0, NO_ARG },
	{ BOOTSTRAP,	"B", "bootstrap", REQ_ARG },
	{ ENABLESSMPING,"P", "ssmping", NO_ARG },
	{ SOURCEADDR,	"s", 0, REQ_ARG },
	{ DUMP,		"d", "dump", OPT_ARG },
	{ DUMPINTERVAL,	"I", "interval", REQ_ARG },
	{ DUMPEXEC,	"L", "exec", REQ_ARG },
	{ SPECWEBSITE,	"W", "website", REQ_ARG },
	{ SPECMATRIX,	"Wm", "matrix", REQ_ARG },
	{ SPECLG,	"Wl", "lg", REQ_ARG },
	{ COUNTRY,	"C", "CC", REQ_ARG },
	{ SPECFLAG,	"F", "flag", REQ_ARG },
	{ VERBOSE,	"v", "verbose", NO_ARG },
	{ DUMPBW,	"U", "dump-bw", NO_ARG },
	{ HELP,		"h", "help", NO_ARG },
	{ FORCEv4,	"4", "ipv4", NO_ARG },
	{ FORCEv6,	"6", "ipv6", NO_ARG },
	{ SHOWVERSION,	"V", "version", NO_ARG },
	{ 0, 0, 0, 0 }
};

static void check_good_string(const char *what, const char *value) {
	int l = strlen(value);

	for (int i = 0; i < l; i++) {
		if (!isprint(value[i])) {
			fprintf(stderr, "Invalid `%s` string.\n", what);
			exit(1);
		}
	}
}

int parse_arguments(int argc, char **argv) {
	vector< pair<const char *, const char *> > args;
	vector<const char *> stray;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			const char *mast = argv[i];
			const char *arg = 0;
			if ((i + 1) < argc && argv[i+1][0] != '-') {
				arg = argv[i+1];
				i++;
			}
			args.push_back(make_pair(mast + 1, arg));
		} else {
			stray.push_back(argv[i]);
		}
	}

	for (vector< pair<const char *, const char *> >::const_iterator i = args.begin();
							i != args.end(); i++) {
		const param_tok *tok = 0;
		int j;
		for (j = 0; !tok && param_format[j].name; j++) {
			if ((param_format[j].sf && !strcmp(i->first, param_format[j].sf))
				|| (param_format[j].lf && !strcmp(i->first, param_format[j].lf))) {
				tok = &param_format[j];
			}
		}
		if (!tok) {
			fprintf(stderr, "Unknown parameter `%s`\n", i->first);
		} else {
			if (tok->param == REQ_ARG && !i->second) {
				fprintf(stderr, "Parameter `%s` requires an argument\n", i->first);
				return -1;
			} else if (tok->param == NO_ARG && i->second) {
				fprintf(stderr, "Parameter `%s` doesn't require an argument, ignoring.\n", i->first);
			}

			switch (tok->name) {
			case NAME:
				check_good_string("name", i->second);
				beaconName = i->second;
				break;
			case CONTACT:
				if (!strchr(i->second, '@')) {
					fprintf(stderr, "Not a valid email address.\n");
					return -1;
				}
				check_good_string("admin contact", i->second);
				adminContact = i->second;
				break;
			case INTERFACE:
				multicastInterface = i->second;
				break;
			case BEACONADDR:
				probeAddrLiteral = i->second;
				break;
			case SSMADDR:
				if (i->second) {
					probeSSMAddrLiteral = i->second;
				}
				useSSM = true;
				listenForSSM = true;
				break;
			case SSMSENDONLY:
				useSSM = true;
				listenForSSM = false;
				break;
			case BOOTSTRAP:
				{
					address addr;
					if (!addr.parse(i->second, false)) {
						fprintf(stderr, "Bad address format.\n");
						return -1;
					}
					ssmBootstrap.push_back(addr);
				}
				break;
			case ENABLESSMPING:
				useSSMPing = true;
				break;
			case SOURCEADDR:
				if (!beaconUnicastAddr.parse(i->second, false, false)) {
					fprintf(stderr, "Bad address format.\n");
					return -1;
				}
				break;
			case DUMP:
				dumpFile = i->second ? i->second : defaultDumpFile;
				break;
			case DUMPINTERVAL:
				{
					char *end;
					dumpInterval = strtoul(i->second, &end, 10);
					if (*end || dumpInterval < 5) {
						fprintf(stderr, "Bad interval.\n");
						return -1;
					}
				}
				break;
			case DUMPEXEC:
				launchSomething = i->second;
				break;
			case SPECWEBSITE:
				if (strncmp(i->second, "lg$", 3) == 0) {
					check_good_string("LG website", i->second + 3);
					webSites[T_WEBSITE_LG] = i->second + 3;
				} else if (strncmp(i->second, "matrix$", 7) == 0) {
					check_good_string("matrix url", i->second + 7);
					webSites[T_WEBSITE_MATRIX] = i->second + 7;
				} else {
					check_good_string("website", i->second);
					webSites[T_WEBSITE_GENERIC] = i->second;
				}
				break;
			case SPECMATRIX:
				check_good_string("matrix url", i->second);
				webSites[T_WEBSITE_MATRIX] = i->second;
				break;
			case SPECLG:
				check_good_string("lg url", i->second);
				webSites[T_WEBSITE_LG] = i->second;
				break;
			case COUNTRY:
				check_good_string("country", i->second);
				if (strlen(i->second) != 2) {
					fprintf(stderr, "Bad country code.\n");
					return -1;
				}
				twoLetterCC = i->second;
				break;
			case SPECFLAG:
				if (!strcmp(i->second, "ssmping")) {
					flags |= SSMPING_CAPABLE;
				} else {
					fprintf(stderr, "Unknown flag \"%s\"\n", i->second);
				}
				break;
			case VERBOSE:
				verbose ++;
				break;
			case DUMPBW:
				dumpBwReport = true;
				break;
			case HELP:
				usage();
				return -1;
			case FORCEv4:
				forceFamily = AF_INET;
				break;
			case FORCEv6:
				forceFamily = AF_INET6;
				break;
			case SHOWVERSION:
				show_version();
				break;
			}
		}
	}

	return 0;
}

struct timer {
	uint32_t type, interval;
	uint32_t target;
};

typedef std::list<timer> tq_def;
static tq_def timers;

/* accumulated time waiting to be spent by events */
static uint32_t taccum = 0;
static uint64_t lastclk = 0;

static void update_taccum() {
	uint64_t now = get_timestamp();
	int32_t diff = now - (int64_t)lastclk;

	if (now < lastclk) {
		fprintf(stderr, "BAD behaviour. now=%llu lastclk=%llu diff=%i\n", now, lastclk, diff);
		assert(0);
	}

	lastclk = now;
	taccum += diff;
}

void next_event(timeval *eventm) {
	update_taccum();

	timer &h = *timers.begin();

	/* we assume we always have a timer in the list */
	if (taccum > h.target) {
		taccum -= h.target;
		h.target = 0;
	} else {
		h.target -= taccum;
		taccum = 0;
	}

	eventm->tv_sec = h.target / 1000;
	eventm->tv_usec = (h.target % 1000) * 1000;

	/* debug(stderr, "next_event %s %u %u", EventName(h.type), eventm->tv_sec, eventm->tv_usec); */
}

void insert_sorted_event(timer &t) {
	uint32_t accum = 0;

	tq_def::iterator i = timers.begin();

	while (1) {
		if (i == timers.end() || (accum + i->target) >= t.interval)
			break;
		accum += i->target;
		++i;
	}

	t.target = t.interval - accum;

	if (i != timers.end())
		i->target -= t.target;

	if (timers.empty()) {
		lastclk = get_timestamp();
		taccum = 0;
	}

	timers.insert(i, t);
}

void insert_event(uint32_t type, uint32_t interval) {
	timer t;
	t.type = type;
	t.interval = interval;

	insert_sorted_event(t);
}

static int send_count = 0;
static int send_ssm_count = 0;

uint32_t timeFact(int val, bool random) {
	return (uint32_t) ((random ? ceil(Exprnd(beacInt * val)) : (beacInt * val)) * 1000);
}

static void handle_single_event() {
	timer t = *timers.begin();
	timers.erase(timers.begin());

	switch (t.type) {
	case SENDING_EVENT:
		send_probe();
		send_count++;
		break;
	case SSM_SENDING_EVENT:
		send_ssm_probe();
		send_ssm_count++;
		break;
	case REPORT_EVENT:
	case SSM_REPORT_EVENT:
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
	} else if (t.type == WILLSEND_SSM_EVENT) {
		insert_event(SSM_SENDING_EVENT, 100);
		send_ssm_count = 0;
	} else if (t.type == SENDING_EVENT && send_count == probeBurstLength) {
		insert_event(WILLSEND_EVENT, timeFact(1, true));
	} else if (t.type == SSM_SENDING_EVENT && send_ssm_count == probeBurstLength) {
		insert_event(WILLSEND_SSM_EVENT, timeFact(1, true));
	} else if (t.type == REPORT_EVENT) {
		insert_event(REPORT_EVENT, timeFact(reportI));
	} else if (t.type == SSM_REPORT_EVENT) {
		insert_event(SSM_REPORT_EVENT, timeFact(ssmReportI));
	} else if (t.type == MAP_REPORT_EVENT) {
		insert_event(MAP_REPORT_EVENT, timeFact(mapReportI));
	} else if (t.type == WEBSITE_REPORT_EVENT) {
		insert_event(WEBSITE_REPORT_EVENT, timeFact(websiteReportI));
	} else {
		insert_sorted_event(t);
	}
}

void handle_event() {
	update_taccum();

	while (!timers.empty()) {
		if (timers.begin()->target > taccum) {
			return;
		}

		taccum -= timers.begin()->target;

		handle_single_event();
	}
}

void handle_gc() {
	Sources::iterator i = sources.begin();

	uint64_t now = get_timestamp();

	while (i != sources.end()) {
		bool remove = false;
		if ((now - i->second.lastevent) > timeFact(timeOutI)) {
			remove = true;
		}
		if (!remove) {
			i->second.ASM.s.check_validity(now);
			i->second.SSM.s.check_validity(now);

			beaconSource::ExternalSources::iterator j = i->second.externalSources.begin();
			while (j != i->second.externalSources.end()) {
				if ((now - j->second.lastupdate) > timeFact(timeOutI)) {
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

			removeSource(j->first, true);
		}
	}
}

void handle_mcast(int sock, content_type type) {
	address from, to;

	uint64_t recvdts;
	int ttl;

	int len = RecvMsg(sock, from, to, buffer, bufferLen, ttl, recvdts);
	if (len < 0)
		return;

	if (from.is_equal(beaconUnicastAddr))
		return;

	if (verbose > 3) {
		char tmp[64];
		from.print(tmp, sizeof(tmp));
		fprintf(stderr, "RecvMsg(%s): len = %u\n", tmp, len);
	}

	if (type == SSMPING) {
		handle_ssmping(sock, from, to, buffer, len, recvdts);
	} else if (type == NPROBE || type == NSSMPROBE) {
		bytesReceived += len;

		handle_nmsg(from, recvdts, ttl, buffer, len, type == NSSMPROBE);
	}
}

Stats::Stats() {
	valid = false;
	timestamp = lastupdate = 0;
	avgdelay = avgjitter = avgloss = avgdup = avgooo = 0;
	rttl = 0;
}

void Stats::check_validity(uint64_t now) {
	if ((now - lastupdate) > timeFact(timeOutI))
		valid = false;
}

beaconExternalStats::beaconExternalStats() : identified(false) {}

beaconSource &getSource(const address &baddr, const char *name, uint64_t now, uint64_t recvdts, bool rx_local) {
	Sources::iterator i = sources.find(baddr);
	if (i != sources.end()) {
		i->second.lastevent = now;
		if (rx_local)
			i->second.lastlocalevent = now;
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
	if (rx_local)
		src.lastlocalevent = now;

	if (ssmMcastSock) {
		if (SSMJoin(ssmMcastSock, ssmProbeAddr, baddr) != 0) {
			if (verbose) {
				char tmp[64];
				baddr.print(tmp, sizeof(tmp));
				fprintf(stderr, "Failed to join SSM (S,G) where S = %s, reason: %s\n",
								tmp, strerror(errno));
			}
		} else {
			if (verbose > 1) {
				char tmp[64];
				baddr.print(tmp, sizeof(tmp));
				fprintf(stderr, "Joined SSM (S, G) where S = %s\n", tmp);
			}
		}
	}

	return src;
}

void removeSource(const address &baddr, bool timeout) {
	Sources::iterator i = sources.find(baddr);
	if (i != sources.end()) {
		if (verbose) {
			char tmp[64];

			baddr.print(tmp, sizeof(tmp));

			if (i->second.identified) {
				fprintf(stderr, "Removing source %s [%s]%s\n",
					tmp, i->second.name.c_str(), (timeout ? " by Timeout" : ""));
			} else {
				fprintf(stderr, "Removing source %s%s\n",
					tmp, (timeout ? " by Timeout" : ""));
			}
		}

		if (ssmMcastSock) {
			SSMLeave(ssmMcastSock, ssmProbeAddr, baddr);
		}

		sources.erase(i);
	}
}

beaconSource::beaconSource()
	: identified(false) {
	sttl = 0;
	lastlocalevent = 0;
	Flags = 0;
}

void beaconSource::setName(const string &n) {
	name = n;
	identified = true;
}

beaconExternalStats &beaconSource::getExternal(const address &baddr, uint64_t now, uint64_t ts) {
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

	stats.lastupdate = now;

	return stats;
}

template<typename T> T udiff(T a, T b) { if (a > b) return a - b; return b - a; }

void beaconSource::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now, uint64_t recvts, bool ssm) {
	if (verbose > 2)
		fprintf(stderr, "beacon(%s%s) update %u, %llu, %llu\n",
			name.c_str(), (ssm ? "/SSM" : ""), seqnum, timestamp, now);

	beaconMcastState *st = ssm ? &SSM : &ASM;

	st->update(ttl, seqnum, timestamp, now, recvts);
}

bool beaconSource::rxlocal(uint64_t now) const {
	return (now - lastlocalevent) < timeFact(timeOutI);
}

beaconMcastState::beaconMcastState() {
	refresh(0, 0);
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

int64_t abs64(int64_t foo) { return foo < 0 ? -foo : foo; }

// logic adapted from java beacon

void beaconMcastState::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t tsnow, uint64_t _now) {
	/*
	 * ttl - received TTL
	 * seqnum - received seqnum in probe
	 * timestamp - received timestamp in probe (timeofday in sender)
	 * _now - when this packet was received locally (timeofday of host)
	 */

	int64_t now = (uint32_t)_now;

	int64_t diff = now - timestamp;
	int64_t absdiff = abs64(diff);

	if (udiff(seqnum, lastseq) > PACKETS_VERY_OLD) {
		refresh(seqnum - 1, tsnow);
	}

	if (seqnum < lastseq && (lastseq - seqnum) >= packetcount)
		return;

	s.timestamp = timestamp;
	s.lastupdate = tsnow;

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

		int newjitter = absdiff - lastjitter;
		lastjitter = absdiff;
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

static int send_nprobe(const address &addr, uint32_t &seq) {
	int len;

	len = build_probe(buffer, bufferLen, seq, get_time_of_day());
	seq++;

	len = sendto(mcastSock, buffer, len, 0, addr.saddr(), addr.addrlen());
	if (len > 0)
		bytesSent += len;
	return len;
}

int send_probe() {
	static uint32_t seq = rand();

	return send_nprobe(probeAddr, seq);
}

int send_ssm_probe() {
	static uint32_t seq = rand();

	return send_nprobe(ssmProbeAddr, seq);
}

int send_report(int type) {
	int len;

	len = build_report(buffer, bufferLen, type == SSM_REPORT ? STATS_REPORT : type, true);
	if (len < 0)
		return len;

	int res;

	if (type == SSM_REPORT) {
		if ((res = sendto(mcastSock, buffer, len, 0, ssmProbeAddr.saddr(), ssmProbeAddr.addrlen())) < 0) {
			cerr << "Failed to send SSM report: " << strerror(errno) << endl;
		} else {
			bytesSent += res;
		}
	} else {
		for (vector<address>::const_iterator i = redist.begin(); i != redist.end(); i++) {
			const address *to = &(*i);

			char tmp[64];
			to->print(tmp, sizeof(tmp));

			if (verbose) {
				cerr << "Sending Report to " << tmp << endl;
			}

			if ((res = sendto(mcastSock, buffer, len, 0, to->saddr(), to->addrlen())) < 0) {
				cerr << "Failed to send report to " << tmp << ": " << strerror(errno) << endl;
			} else {
				bytesSent += res;
			}
		}
	}

	return 0;
}

void dumpStats(FILE *fp, const char *tag, const Stats &s, uint64_t now, int sttl, bool diff) {
	fprintf(fp, "\t\t\t\t<%s", tag);
	if (!diff)
		fprintf(fp, " ttl=\"%i\"", s.rttl);
	else if (sttl)
		fprintf(fp, " ttl=\"%i\"", sttl - s.rttl);
	fprintf(fp, " rptage=\"%u\"", (uint32_t)((now - s.lastupdate) / 1000));
	fprintf(fp, " loss=\"%.1f\"", s.avgloss * 100);
	fprintf(fp, " delay=\"%.3f\"", fabs(s.avgdelay));
	if (s.avgdelay < 0) {
		fprintf(fp, " future=\"true\"");
	}
	fprintf(fp, " jitter=\"%.3f\"", s.avgjitter);
	fprintf(fp, " ooo=\"%.3f\"", s.avgooo * 100);
	fprintf(fp, " dup=\"%.3f\"", s.avgdup * 100);
	fprintf(fp, " />\n");
}

static void doLaunchSomething();

void do_dump() {
	string tmpf = dumpFile;
	tmpf += ".working";

	FILE *fp = fopen(tmpf.c_str(), "w");
	if (!fp)
		return;

	char tmp[64];

	uint64_t now = get_timestamp();
	uint64_t diff = now - lastDumpDumpBwTS;
	lastDumpDumpBwTS = now;

	double rxRate = dumpBytesReceived * 8 / ((double)diff);
	double txRate = dumpBytesSent * 8 / ((double)diff);
	dumpBytesReceived = 0;
	dumpBytesSent = 0;

	fprintf(fp, "<beacons rxrate=\"%.2f\" txrate=\"%.2f\" versioninfo=\"%s\">\n", rxRate, txRate, versionInfo);

	fprintf(fp, "<group addr=\"%s\"", sessionName);

	if (ssmMcastSock) {
		ssmProbeAddr.print(tmp, sizeof(tmp));
		fprintf(fp, " ssmgroup=\"%s\"", tmp);
	}

	fprintf(fp, " int=\"%.2f\">\n", beacInt);

	if (!probeAddr.is_unspecified()) {
		beaconUnicastAddr.print(tmp, sizeof(tmp));

		fprintf(fp, "\t<beacon name=\"%s\" addr=\"%s\"", beaconName.c_str(), tmp);
		if (!adminContact.empty())
			fprintf(fp, " contact=\"%s\"", adminContact.c_str());
		if (!twoLetterCC.empty())
			fprintf(fp, " country=\"%s\"", twoLetterCC.c_str());
		fprintf(fp, " age=\"%llu\" lastupdate=\"0\" rxlocal=\"true\">\n", (now - startTime) / 1000);

		for (uint32_t k = 0; k < KnownFlags; k++) {
			if (flags & (1 << k)) {
				fprintf(fp, "\t\t<flag name=\"%s\" value=\"true\" />\n", Flags[k]);
			}
		}

		for (WebSites::const_iterator j = webSites.begin(); j != webSites.end(); j++) {
			const char *typnam = j->first == T_WEBSITE_GENERIC ?
				"generic" : (j->first == T_WEBSITE_LG ? "lg" : "matrix");
			fprintf(fp, "\t\t<website type=\"%s\" url=\"%s\" />\n", typnam, j->second.c_str());
		}

		fprintf(fp, "\t\t<sources>\n");

		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			i->first.print(tmp, sizeof(tmp));
			fprintf(fp, "\t\t\t<source addr=\"%s\"", tmp);
			if (i->second.identified) {
				fprintf(fp, " name=\"%s\"", i->second.name.c_str());
				if (!i->second.adminContact.empty())
					fprintf(fp, " contact=\"%s\"", i->second.adminContact.c_str());
			}

			if (!i->second.CC.empty())
				fprintf(fp, " country=\"%s\"", i->second.CC.c_str());

			fprintf(fp, " age=\"%llu\"", (now - i->second.creation) / 1000);
			fprintf(fp, " lastupdate=\"%llu\">\n", (now - i->second.lastevent) / 1000);

			if (i->second.ASM.s.valid)
				dumpStats(fp, "asm", i->second.ASM.s, now, i->second.sttl, true);

			if (i->second.SSM.s.valid)
				dumpStats(fp, "ssm", i->second.SSM.s, now, i->second.sttl, true);

			fprintf(fp, "\t\t\t</source>\n");
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
		fprintf(fp, " rxlocal=\"%s\"", i->second.rxlocal(now) ? "true" : "false");
		fprintf(fp, " lastupdate=\"%llu\">\n", (now - i->second.lastevent) / 1000);

		for (uint32_t k = 0; k < KnownFlags; k++) {
			if (i->second.Flags & (1 << k)) {
				fprintf(fp, "\t\t<flag name=\"%s\" value=\"true\" />\n", Flags[k]);
			}
		}

		for (WebSites::const_iterator j = i->second.webSites.begin();
						j != i->second.webSites.end(); j++) {
			const char *typnam = j->first == T_WEBSITE_GENERIC ?
				"generic" : (j->first == T_WEBSITE_LG ? "lg" : "matrix");
			fprintf(fp, "\t\t<website type=\"%s\" url=\"%s\" />\n",
						typnam, j->second.c_str());
		}

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
			fprintf(fp, " age=\"%u\">\n", j->second.age);
			if (j->second.ASM.valid)
				dumpStats(fp, "asm", j->second.ASM, now, i->second.sttl, false);
			if (j->second.SSM.valid)
				dumpStats(fp, "ssm", j->second.SSM, now, i->second.sttl, false);
			fprintf(fp, "\t\t\t</source>\n");
		}

		fprintf(fp, "\t\t</sources>\n");
		fprintf(fp, "\t</beacon>\n");
	}

	fprintf(fp, "</group>\n</beacons>\n");

	fclose(fp);

	rename(tmpf.c_str(), dumpFile);

	if (!launchSomething.empty())
		doLaunchSomething();
}

void doLaunchSomething() {
	pid_t p = fork();
	if (p == 0) {
		execlp(launchSomething.c_str(), launchSomething.c_str(), dumpFile, NULL);
	}
}

static void outputBwStats(uint32_t diff, uint64_t txbytes, double txrate, uint64_t rxbytes, double rxrate) {
	fprintf(stdout, "BW Usage for %u secs: RX %llu bytes (%.2f Kb/s) TX %llu bytes (%.2f Kb/s)\n",
			diff, txbytes, txrate, rxbytes, rxrate);
}

void do_bw_dump(bool big) {
	if (big) {
		outputBwStats(600, bigBytesReceived, bigBytesReceived * 8 / (1000. * 600),
					bigBytesSent, bigBytesSent * 8 / (1000. * 600));
		bigBytesReceived = 0;
		bigBytesSent = 0;
		lastDumpBwTS = get_timestamp();
	} else {
		double incomingRate = bytesReceived * 8 / 10000.;

		if (dumpBwReport) {
			debug(stdout, "BW: Received %u bytes (%.2f Kb/s) Sent %u bytes (%.2f Kb/s)",
					bytesReceived, incomingRate, bytesSent, bytesSent * 8 / 10000.);
		}

		bigBytesReceived += bytesReceived;
		bigBytesSent += bytesSent;
		dumpBytesReceived += bytesReceived;
		dumpBytesSent += bytesSent;
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
	outputBwStats((uint32_t)diff, bigBytesReceived, bigBytesReceived * 8 / (1000. * diff),
					bigBytesSent, bigBytesSent * 8 / (1000. * diff));
}

void sendLeaveReport(int) {
	send_report(LEAVE_REPORT);
	exit(0);
}

void SetupFDSet(int sock) {
	if (sock > largestSock)
		largestSock = sock;

	FD_SET(sock, &readSet);
}

int SetupSocketAndFDSet(const address &addr, bool shouldbind, bool ssm) {
	int sock = SetupSocket(addr, shouldbind, ssm);

	if (sock > 0) {
		SetupFDSet(sock);
	}

	return sock;
}

