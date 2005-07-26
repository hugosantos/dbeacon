/*
 * Copyright (C) 2005  Hugo Santos <hsantos@av.it.pt>
 * $Id$
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _dbeacon_h_
#define _dbeacon_h_

#if __FreeBSD_version <= 500042
#include <inttypes.h>
#else
#include <stdint.h>
#endif

#include <string>
#include <map>

#include "address.h"

struct Stats {
	Stats();

	uint64_t timestamp, lastupdate;
	float avgdelay, avgjitter, avgloss, avgdup, avgooo;
	bool valid;
	uint8_t rttl;

	void check_validity(uint64_t);
};

struct beaconExternalStats {
	beaconExternalStats();

	uint64_t lastupdate;
	uint32_t age;

	Stats ASM, SSM;

	bool identified;
	std::string name, contact;
};

struct beaconMcastState {
	beaconMcastState();

	uint32_t lastseq;

	uint32_t packetcount, packetcountreal;
	uint32_t pointer;

	int lastdelay, lastjitter, lastloss, lastdup, lastooo;

	Stats s;

#define PACKETS_PERIOD		40
#define PACKETS_VERY_OLD	150

	uint32_t cacheseqnum[PACKETS_PERIOD+1];

	void refresh(uint32_t, uint64_t);
	void update(uint8_t, uint32_t, uint64_t, uint64_t, uint64_t);
};

typedef std::map<int, std::string> WebSites;

struct beaconSource {
	beaconSource();

	address addr;

	uint64_t creation;

	int sttl;

	uint64_t lastevent;
	uint64_t lastlocalevent;

	beaconMcastState ASM, SSM;

	void setName(const std::string &);
	void update(uint8_t, uint32_t, uint64_t, uint64_t, uint64_t, bool);

	beaconExternalStats &getExternal(const address &, uint64_t now, uint64_t ts);

	bool rxlocal(uint64_t now) const;

	std::string name;
	std::string adminContact;
	std::string CC;

	uint32_t Flags;

	typedef std::map<address, beaconExternalStats> ExternalSources;
	ExternalSources externalSources;

	WebSites webSites;

	bool identified;
};

typedef std::map<address, beaconSource> Sources;

beaconSource &getSource(const address &, const char *name, uint64_t now, uint64_t recvts, bool rxlocal);
void removeSource(const address &, bool);

uint64_t get_timestamp();
uint64_t get_time_of_day();

enum content_type {
	NPROBE,
	NSSMPROBE,
	SSMPING
};

void ListenTo(content_type, int);
void SetupFDSet(int);

int SetupSSMPing();
void handle_ssmping(int s, address &, const address &, uint8_t *, int, uint64_t);

extern const char *defaultPort;
extern const int defaultTTL;

extern int forceFamily;
extern int mcastInterface;

struct beaconExternalStats;

extern uint32_t flags;

extern std::string beaconName, adminContact, twoLetterCC;
extern Sources sources;
extern WebSites webSites;
extern address beaconUnicastAddr;

extern int verbose;

#endif

