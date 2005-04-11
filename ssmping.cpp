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

#include "dbeacon.h"
#include "address.h"
#include "msocket.h"

#include <stdio.h>
#include <unistd.h>

enum {
	SSMPING_REQUEST = 'Q',
	SSMPING_ANSWER = 'A'
};

static const int maxSSMPingMessage = 1000;

static const char *SSMPingV6ResponseChannel = "ff3e::4321:1234";
static const char *SSMPingV4ResponseChannel = "232.43.211.234";

static int ssmPingSocket = -1;

int SetupSSMPing() {
	address addr;

	if (!addr.set_family(beaconUnicastAddr.family()))
		return -1;

	if (!addr.set_port(4321))
		return -1;

	ssmPingSocket = SetupSocket(addr, true, false);
	if (ssmPingSocket < 0)
		return -1;

	if (!SetHops(ssmPingSocket, addr, 64)) {
		close(ssmPingSocket);
		return -1;
	}

	if (!RequireToAddress(ssmPingSocket, addr)) {
		close(ssmPingSocket);
		return -1;
	}

	ListenTo(SSMPING, ssmPingSocket);

	return 0;
}

void handle_ssmping(int s, address &from, const address &to, uint8_t *buffer, int len, uint64_t ts) {
	if (buffer[0] != SSMPING_REQUEST || len > maxSSMPingMessage)
		return;

	if (verbose > 1) {
		char tmp[64];
		from.print(tmp, sizeof(tmp));
		fprintf(stderr, "Got SSM Ping Request from %s\n", tmp);
	}

	buffer[0] = SSMPING_ANSWER;

	if (SendTo(s, buffer, len, to, from) < 0)
		return;

	if (!from.set_addr(from.family() == AF_INET6 ? SSMPingV6ResponseChannel :
							SSMPingV4ResponseChannel))
		return;

	SendTo(s, buffer, len, to, from);
}

