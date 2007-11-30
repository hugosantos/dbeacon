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

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

enum {
	SSMPING_REQUEST = 'Q',
	SSMPING_ANSWER = 'A'
};

static const size_t maxSSMPingMessage = 1000;

static const char *SSMPingV6ResponseChannel = "ff3e::4321:1234";
static const char *SSMPingV4ResponseChannel = "232.43.211.234";

static address SSMPingV6Addr(AF_INET6), SSMPingV4Addr(AF_INET);

static int ssmPingSocket = -1;

static void handle_ssmping(int s, const Message &msg)
{
	if (msg.buffer[0] != SSMPING_REQUEST || msg.len > maxSSMPingMessage)
		return;

	if (verbose > 1) {
		char tmp[64];
		info("Got SSM Ping Request from %s",
			msg.from.to_string(tmp, sizeof(tmp)));
	}

	msg.buffer[0] = SSMPING_ANSWER;

	if (SendTo(s, msg.buffer, msg.len, msg.to, msg.from) < 0)
		return;

	address mcastDest(msg.from.family() == AF_INET6 ?
			SSMPingV6Addr : SSMPingV4Addr);
	mcastDest.set_port(msg.from.port());

	SendTo(s, msg.buffer, msg.len, msg.to, mcastDest);
}

int SetupSSMPing() {
	address addr(beaconUnicastAddr.family());

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

	assert(SSMPingV4Addr.set_addr(SSMPingV4ResponseChannel));
	assert(SSMPingV6Addr.set_addr(SSMPingV6ResponseChannel));

	ListenTo(ssmPingSocket, handle_ssmping);

	return 0;
}


