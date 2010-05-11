/*
 * Copyright 2005-2010, Hugo Santos <hugo@fivebits.net>
 * Distributed under the terms of the MIT License.
 */

#ifndef _protocol_h_
#define _protocol_h_

#include "address.h"

#define PROTO_VER 1

// Protocol TLV types
enum {
	T_BEAC_NAME = 'n',
	T_ADMIN_CONTACT = 'a',
	T_SOURCE_INFO_IPv4 = 'i',
	T_SOURCE_INFO = 'I',
	T_ASM_STATS = 'A',
	T_SSM_STATS = 'S',

	T_SOURCE_FLAGS = 'F',

	T_WEBSITE_GENERIC = 'G',
	T_WEBSITE_MATRIX = 'M',
	T_WEBSITE_LG = 'L',
	T_CC = 'C',

	T_LEAVE = 'Q'
};

// Report types
enum {
	STATS_REPORT = 'R',
	SSM_REPORT,
	MAP_REPORT,
	WEBSITE_REPORT,
	LEAVE_REPORT
};

// Known Flags
enum {
	SSM_CAPABLE = 1,
	SSMPING_CAPABLE = 2
};

int build_probe(uint8_t *, int, uint32_t, uint64_t);
int build_report(uint8_t *, int, int, bool);

void handle_nmsg(const address &from, uint64_t recvdts, int ttl, uint8_t *buffer, int len, bool);

#endif

