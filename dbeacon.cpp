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
#include <syslog.h>

#include <assert.h>

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <vector>

using namespace std;

const char * const versionInfo = "0.3.9.1 ($Rev$)";

const char * const defaultIPv6SSMChannel = "ff3e::beac";
const char * const defaultIPv4SSMChannel = "232.2.3.2";
const char * const defaultPort = "10000";
#ifndef SOLARIS
const int defaultTTL = 127;
#else
const int defaultTTL = 64;
#endif
const char * const defaultDumpFile = "dump.xml";

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
static string probeAddrLiteral;
static string probeSSMAddrLiteral;
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

static string dumpFile;

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
int forceFamily = AF_UNSPEC;
bool daemonize = false;
bool use_syslog = false;
bool past_init = false;

const char *pidfile = NULL;

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
	fprintf(stdout, "Usage: dbeacon [OPTIONS...]\n\n");
	fprintf(stdout, "  -n NAME, -name NAME    Specifies the beacon name\n");
	fprintf(stdout, "  -a MAIL                Supply administration contact\n");
	fprintf(stdout, "  -i IN, -interface IN   Use IN instead of the default interface for multicast\n");
	fprintf(stdout, "  -b BEACON_ADDR[/PORT]  Multicast group address to send probes to\n");
	fprintf(stdout, "  -S [GROUP_ADDR[/PORT]] Enables SSM reception/sending on optional GROUP_ADDR/PORT\n");
	fprintf(stdout, "  -O                     Disables the joining of SSM groups but still sends via SSM.\n");
	fprintf(stdout, "                         Use this option if your operating system has problems with SSM\n");
	fprintf(stdout, "  -B ADDR                Bootstraps by joining the specified address\n");
	fprintf(stdout, "  -P, -ssmping           Enable the SSMPing server capability\n");
	fprintf(stdout, "  -s ADDR                Bind to local address\n");
	fprintf(stdout, "  -d [FILE]              Dump periodic reports to dump.xml or specified file\n");
	fprintf(stdout, "  -I N, -interval N      Interval between dumps. Defaults to 5 secs\n");
	fprintf(stdout, "  -W URL, -website URL   Specify a website to announce.\n");
	fprintf(stdout, "  -Wm URL, -matrix URL   Specify your matrix URL\n");
	fprintf(stdout, "  -Wl URL, -lg URL       Specify your LG URL\n");
	fprintf(stdout, "                         will announce an URL for that type instead\n");
	fprintf(stdout, "  -C CC                  Specify your two letter Country Code\n");
	fprintf(stdout, "  -L program             Launch program after each dump.\n");
	fprintf(stdout, "                         The first argument will be the dump filename\n");
	fprintf(stdout, "  -F flag                Set a dbeacon flag to be announced.\n");
	fprintf(stdout, "                         Available flags are: ssmping\n");
	fprintf(stdout, "  -4, -ipv4              Force IPv4 usage\n");
	fprintf(stdout, "  -6, -ipv6              Force IPv6 usage\n");
	fprintf(stdout, "  -v                     be verbose (use several for more verbosity)\n");
	fprintf(stdout, "  -U                     Dump periodic bandwidth usage reports to stdout\n");
	fprintf(stdout, "  -D, -daemon            fork to the background (daemonize)\n");
	fprintf(stdout, "  -pidfile FILE          Specifies the PID filename to use\n");
	fprintf(stdout, "  -syslog                Outputs using syslog facility.\n");
	fprintf(stdout, "  -c FILE                Specifies the configuration file\n");
	fprintf(stdout, "  -V, -version           Outputs version information and leaves\n");
	fprintf(stdout, "\n");

	exit(1);
}

static void logv(int level, const char *format, va_list vl)
{
	char buffer[256];
	vsnprintf(buffer, sizeof(buffer), format, vl);

	if (use_syslog && past_init) {
		syslog(level, buffer);
	} else {
		char tbuf[64];
		timeval tv;
		gettimeofday(&tv, 0);

		/* Some FreeBSDs' tv.tv_sec isn't time_t */
		time_t tv_sec = tv.tv_sec;
		strftime(tbuf, sizeof(tbuf), "%b %d %H:%M:%S", localtime(&tv_sec));

		fprintf(stderr, "%s.%06u %s\n", tbuf, (uint32_t)tv.tv_usec, buffer);
	}
}

static void log(int level, const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	logv(level, format, vl);
	va_end(vl);
}

void info(const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	logv(LOG_INFO, format, vl);
	va_end(vl);
}

void fatal(const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	logv(LOG_CRIT, format, vl);
	va_end(vl);
	exit(-1);
}

extern "C" void waitForMe(int) {
	int whocares;
	wait(&whocares);
}

static void parse_arguments(int, char **);

int main(int argc, char **argv) {
	int res;

	srand(time(NULL));

	char tmp[256];
	if (gethostname(tmp, sizeof(tmp)) != 0) {
		perror("Failed to get hostname");
		return -1;
	}

	beaconName = tmp;

	parse_arguments(argc, argv);

	MulticastStartup();

	if (beaconName.empty())
		fatal("No name supplied.");

	if (!probeAddrLiteral.empty()) {
		if (!probeAddr.parse(probeAddrLiteral.c_str(), true))
			return -1;

		probeAddr.print(sessionName, sizeof(sessionName));

		if (!probeAddr.is_multicast())
			fatal("Specified probe addr (%s) is not of a multicast group.",
					sessionName);

		if (adminContact.empty())
			fatal("No administration contact supplied.");

		mcastListen.push_back(make_pair(probeAddr, NPROBE));

		insert_event(SENDING_EVENT, 100);
		insert_event(REPORT_EVENT, 10000);
		insert_event(MAP_REPORT_EVENT, 30000);
		insert_event(WEBSITE_REPORT_EVENT, 120000);

		redist.push_back(probeAddr);

		if (useSSM) {
			if (probeSSMAddrLiteral.empty()) {
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

			if (!ssmProbeAddr.parse(probeSSMAddrLiteral.c_str(), true)) {
				fatal("Bad address format for SSM channel.");
			} else if (!ssmProbeAddr.is_unspecified()) {
				insert_event(SSM_SENDING_EVENT, 100);
				insert_event(SSM_REPORT_EVENT, 15000);

				if (listenForSSM) {
					mcastListen.push_back(make_pair(ssmProbeAddr, NSSMPROBE));
				}
			}
		}
	} else {
		if (mcastListen.empty())
			fatal("Nothing to do, check `dbeacon -h`.");
		else
			strcpy(sessionName, beaconName.c_str());
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
		if (SetupSSMPing() < 0)
			log(LOG_ERR, "Failed to setup SSM Ping.");
		else
			flags |= SSMPING_CAPABLE;
	}

	if (ssmMcastSock) {
		flags |= SSM_CAPABLE;

		uint64_t now = get_timestamp();
		for (vector<address>::const_iterator i = ssmBootstrap.begin(); i != ssmBootstrap.end(); i++) {
			getSource(*i, 0, now, 0, false);
		}
	} else if (!ssmBootstrap.empty())
		log(LOG_WARNING, "Tried to bootstrap using SSM when SSM is not enabled.");

	if (daemonize || use_syslog) {
		use_syslog = true;
		openlog("dbeacon", LOG_NDELAY | LOG_PID, LOG_DAEMON);
	}

	past_init = true;

	if (daemonize) {
		if (daemon(0, 0)) {
			perror("Failed to daemon()ize.");
			return -1;
		}
		if (pidfile) {
			FILE *f = fopen(pidfile, "w");
			if (f) {
				fprintf(f, "%u\n", getpid());
				fclose(f);
			} else {
				log(LOG_ERR, "Failed to open PID file to write.");
			}
		}
	}

	// Init timer events
	insert_event(GARBAGE_COLLECT_EVENT, 30000);

	if (!dumpFile.empty())
		insert_event(DUMP_EVENT, dumpInterval * 1000);

	insert_event(DUMP_BW_EVENT, 10000);

	if (dumpBwReport)
		insert_event(DUMP_BIG_BW_EVENT, 600000);

	send_report(WEBSITE_REPORT_EVENT);

	beaconUnicastAddr.print(tmp, sizeof(tmp), false);

	info("Local name is `%s` [Beacon group: %s, Local address: %s]",
			beaconName.c_str(), sessionName, tmp);

	signal(SIGUSR1, dumpBigBwStats);
	signal(SIGINT, sendLeaveReport);
	signal(SIGTERM, sendLeaveReport);

	signal(SIGCHLD, waitForMe); // bloody fork, we dont want to wait for thee

	startTime = lastDumpBwTS = lastDumpDumpBwTS = get_timestamp();

	while (1) {
		fd_set readset;
		timeval eventm;

		memcpy(&readset, &readSet, sizeof(fd_set));

		next_event(&eventm);

		res = select(largestSock + 1, &readset, 0, 0, &eventm);

		if (res < 0) {
			if (errno == EINTR)
				continue;
			fatal("Select failed: %s", strerror(errno));
		} else {
			for (vector<pair<int, content_type> >::const_iterator
					i = mcastSocks.begin(); i != mcastSocks.end(); ++i)
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
	SHOWVERSION,
	DAEMON,
	PIDFILE,
	USE_SYSLOG,
	CONFFILE
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
	{ CONTACT,	"a", "contact", REQ_ARG },
	{ INTERFACE,	"i", "interface", REQ_ARG },
	{ BEACONADDR,	"b", "addr", REQ_ARG },
	{ SSMADDR,	"S", "ssm_addr", OPT_ARG },
	{ SSMSENDONLY,	"O", "ssm_send_only", OPT_ARG },
	{ BOOTSTRAP,	"B", "bootstrap", REQ_ARG },
	{ ENABLESSMPING,"P", "ssmping", OPT_ARG },
	{ SOURCEADDR,	"s", "source", REQ_ARG },
	{ DUMP,		"d", "dump", OPT_ARG },
	{ DUMPINTERVAL,	"I", "interval", REQ_ARG },
	{ DUMPEXEC,	"L", "exec", REQ_ARG },
	{ SPECWEBSITE,	"W", "website", REQ_ARG },
	{ SPECMATRIX,	"Wm", "matrix", REQ_ARG },
	{ SPECLG,	"Wl", "lg", REQ_ARG },
	{ COUNTRY,	"C", "CC", REQ_ARG },
	{ SPECFLAG,	"F", "flag", REQ_ARG },
	{ VERBOSE,	"v", "verbose", OPT_ARG },
	{ DUMPBW,	"U", "dump-bw", OPT_ARG },
	{ HELP,		"h", "help", NO_ARG },
	{ FORCEv4,	"4", "ipv4", NO_ARG },
	{ FORCEv6,	"6", "ipv6", NO_ARG },
	{ DAEMON,	"D", "daemon", NO_ARG },
	{ PIDFILE,	"p", "pidfile", REQ_ARG },
	{ USE_SYSLOG,	"Y", "syslog", NO_ARG },
	{ CONFFILE,	"c", NULL, REQ_ARG },
	{ SHOWVERSION,	"V", "version", NO_ARG },
	{ 0, NULL, NULL, 0 }
};

static const char *check_good_string(const char *what, const char *value) {
	int l = strlen(value);

	for (int i = 0; i < l; i++) {
		if (!isprint(value[i])) {
			fprintf(stderr, "Invalid `%s` string.\n", what);
			exit(1);
		}
	}

	return value;
}

static void parse_or_fail(address *addr, const char *arg, bool mc, bool addport) {
	if (!addr->parse(arg, mc, addport))
		fatal("Bad address format.");
}

static void add_bootstrap_address(const char *arg) {
	address addr;
	parse_or_fail(&addr, arg, false, true);
	ssmBootstrap.push_back(addr);
}

static uint32_t parse_u32(const char *name, const char *arg) {
	uint32_t result;
	char *end;

	result = strtoul(arg, &end, 10);
	if (end[0] != 0)
		fatal("%s: Expected unsigned integer.", name);

	return result;
}

static bool parse_bool(const char *name, const char *arg, bool def) {
	if (arg == NULL)
		return def;

	if (!strcasecmp(arg, "yes"))
		return true;
	else if (!strcasecmp(arg, "true"))
		return true;
	else if (!strcasecmp(arg, "1"))
		return true;
	else if (!strcasecmp(arg, "no"))
		return false;
	else if (!strcasecmp(arg, "false"))
		return false;
	else if (!strcasecmp(arg, "0"))
		return false;

	fatal("%s: Expected one of \'yes\', \'true\', \'no\' or \'false\'.");
	return false;
}

static void parse_config_file(const char *);

static void process_param(const param_tok *tok, const char *arg) {
	switch (tok->name) {
	case NAME:
		beaconName = check_good_string("name", arg);
		break;
	case CONTACT:
		if (!strchr(arg, '@'))
			fatal("Not a valid email address.");

		adminContact = check_good_string("admin contact", arg);
		break;
	case INTERFACE:
		mcastInterface = if_nametoindex(arg);
		if (mcastInterface <= 0)
			fatal("Invalid interface name.");
		break;
	case BEACONADDR:
		probeAddrLiteral = arg;
		break;
	case SSMADDR:
		if (arg)
			probeSSMAddrLiteral = arg;
		useSSM = true;
		listenForSSM = true;
		break;
	case SSMSENDONLY:
		useSSM = true;
		listenForSSM = parse_bool("SSMSendOnly", arg, false);
		break;
	case BOOTSTRAP:
		add_bootstrap_address(arg);
		break;
	case ENABLESSMPING:
		useSSMPing = parse_bool("SSMPing", arg, true);
		break;
	case SOURCEADDR:
		parse_or_fail(&beaconUnicastAddr, arg, false, false);
		break;
	case DUMP:
		dumpFile = arg ? arg : defaultDumpFile;
		break;
	case DUMPINTERVAL:
		dumpInterval = parse_u32("Dump interval", arg);
		if (dumpInterval < 5)
			dumpInterval = 5;
		break;
	case DUMPEXEC:
		launchSomething = arg;
		break;
	case SPECWEBSITE:
		if (strncmp(arg, "lg$", 3) == 0) {
			webSites[T_WEBSITE_LG] =
				check_good_string("LG website", arg + 3);
		} else if (strncmp(arg, "matrix$", 7) == 0) {
			webSites[T_WEBSITE_MATRIX] =
				check_good_string("matrix url", arg + 7);
		} else {
			webSites[T_WEBSITE_GENERIC] =
				check_good_string("website", arg);
		}
		break;
	case SPECMATRIX:
		webSites[T_WEBSITE_MATRIX] =
			check_good_string("matrix url", arg);
		break;
	case SPECLG:
		webSites[T_WEBSITE_LG] =
			check_good_string("lg url", arg);
		break;
	case COUNTRY:
		if (strlen(arg) != 2)
			fatal("Bad country code.");
		twoLetterCC = check_good_string("country", arg);
		break;
	case SPECFLAG:
		if (!strcmp(arg, "ssmping")) {
			flags |= SSMPING_CAPABLE;
		} else {
			fprintf(stderr, "Unknown flag \"%s\"\n", arg);
		}
		break;
	case VERBOSE:
		if (arg)
			verbose = parse_u32("Verbose", arg);
		else
			verbose ++;
		break;
	case DUMPBW:
		dumpBwReport = parse_bool("DumpBandwidth", arg, true);
		break;
	case HELP:
		usage();
		break;
	case FORCEv4:
		forceFamily = AF_INET;
		break;
	case FORCEv6:
		forceFamily = AF_INET6;
		break;
	case SHOWVERSION:
		show_version();
		break;
	case DAEMON:
		daemonize = true;
		break;
	case PIDFILE:
		pidfile = check_good_string("pidfile", arg);
		break;
	case USE_SYSLOG:
		use_syslog = true;
		break;
	case CONFFILE:
		parse_config_file(arg);
		break;
	}
}

static char *skip_spaces(char *in) {
	while (isspace(in[0]))
		in++;
	return in;
}

static char *terminate_str(char *left, char *right) {
	for (; left < right && isspace(*right); right--);
	right[1] = 0;
	return left;
}

static const param_tok *resolve_tok(const char *arg, bool longonly) {
	for (int j = 0; param_format[j].sf != NULL; j++) {
		if (param_format[j].lf && !strcmp(arg, param_format[j].lf))
			return &param_format[j];

		if (longonly)
			continue;

		if (!strcmp(arg, param_format[j].sf))
			return &param_format[j];
	}

	return NULL;
}

static void resolve_string(const char *name, char **ptr) {
	char *p, *str = (*ptr);

	if (str[0] != '\"')
		return;

	for (p = str + 1; (*p) != '\"'; p++);

	if (p[0] == 0 || p[1] != 0)
		fatal("%s: Bad string format.", name);

	p[0] = 0;

	(*ptr) = str + 1;
}

static void check_option_value(const param_tok *tok, const char *lp,
	const char *value)
{
	if (tok == NULL)
		fatal("Unknown option `%s`", lp);
	else if (tok->param == REQ_ARG && value == NULL)
		fatal("Parameter `%s` requires an argument.", lp);
	else if (tok->param == NO_ARG && value != NULL)
		fatal("Parameter `%s` doesn't accept an argument.", lp);
}

static void parse_config_file(const char *filename) {
	FILE *f = fopen(filename, "r");

	if (f == NULL)
		fatal("Failed to open configuration file.");

	char linebuf[256];
	int lc = 0;

	while (fgets(linebuf, sizeof(linebuf), f)) {
		char *lp = skip_spaces(linebuf);
		char *val, *end = lp + strlen(lp);

		lc++;

		if (lp[0] == 0 || lp[0] == '#' || strncmp(lp, "//", 2) == 0)
			continue;

		val = strchr(lp, ':');
		if (val) {
			terminate_str(lp, val - 1);
			val = terminate_str(skip_spaces(val + 1), end - 1);
		} else {
			terminate_str(lp, lp + strlen(lp) - 1);
		}

		const param_tok *tok = resolve_tok(lp, true);

		check_option_value(tok, lp, val);

		if (val)
			resolve_string(lp, &val);
		process_param(tok, val);
	}

	fclose(f);
}

typedef pair<const char *, const char *> string_pair;

void parse_arguments(int argc, char **argv) {
	vector<string_pair> args;
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

	for (vector<string_pair>::const_iterator i = args.begin();
						 i != args.end(); ++i) {
		const param_tok *tok = resolve_tok(i->first, false);
		check_option_value(tok, i->first, i->second);
		process_param(tok, i->second);
	}
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

	assert(now >= lastclk);

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
		info("RecvMsg(%s): len = %u", tmp, len);
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
			info("Adding source %s [%s]", tmp, name);
		} else {
			info("Adding source %s", tmp);
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
				info("Failed to join SSM (S,G) where S = %s, reason: %s",
					tmp, strerror(errno));
			}
		} else {
			if (verbose > 1) {
				char tmp[64];
				baddr.print(tmp, sizeof(tmp));
				info("Joined SSM (S, G) where S = %s", tmp);
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
				info("Removing source %s [%s]%s",
					tmp, i->second.name.c_str(), (timeout ? " by Timeout" : ""));
			} else {
				info("Removing source %s%s",
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
			info("Adding external source (%s) %s", name.c_str(), tmp);
	}

	beaconExternalStats &stats = k->second;

	stats.lastupdate = now;

	return stats;
}

template<typename T> T udiff(T a, T b) { if (a > b) return a - b; return b - a; }

void beaconSource::update(uint8_t ttl, uint32_t seqnum, uint64_t timestamp, uint64_t now, uint64_t recvts, bool ssm) {
	if (verbose > 2)
		info("beacon(%s%s) update %u, %llu, %llu",
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

	rename(tmpf.c_str(), dumpFile.c_str());

	if (!launchSomething.empty())
		doLaunchSomething();
}

void doLaunchSomething() {
	pid_t p = fork();
	if (p == 0) {
		execlp(launchSomething.c_str(), launchSomething.c_str(),
		       dumpFile.c_str(), NULL);
	}
}

static void
outputBwStats(uint32_t diff, uint64_t txbytes, double txrate, uint64_t rxbytes,
				double rxrate) {
	info("BW Usage for %u secs: RX %llu bytes (%.2f Kb/s) TX %llu "
			"bytes (%.2f Kb/s)", diff, txbytes, txrate, rxbytes, rxrate);
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
			log(LOG_DEBUG, "BW: Received %u bytes (%.2f Kb/s) Sent %u bytes (%.2f Kb/s)",
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
	if (daemonize && pidfile)
		unlink(pidfile);
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

