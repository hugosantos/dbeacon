/*
 * dbeacon, a Multicast Beacon
 *   protocol.h
 *
 * Copyright (C) 2005 Hugo Santos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:	Hugo Santos <hsantos@av.it.pt>
 */

#ifndef _protocol_h_
#define _protocol_h_

#define PROTO_VER 1

// Protocol TLV types
enum {
	T_BEAC_NAME = 'n',
	T_ADMIN_CONTACT = 'a',
	T_SOURCE_INFO_IPv4 = 'i',
	T_SOURCE_INFO = 'I',
	T_ASM_STATS = 'A',
	T_SSM_STATS = 'S',

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

int build_probe(uint8_t *, int, uint32_t, uint64_t);
int build_report(uint8_t *, int, int, bool);

void handle_nmsg(const address &from, uint64_t recvdts, int ttl, uint8_t *buffer, int len, bool);

#endif

