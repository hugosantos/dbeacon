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

#ifndef _msocket_h_
#define _msocket_h_

#include "address.h"

void MulticastStartup();

int MulticastListen(int sock, const address &);
int SSMJoin(int sock, const address &, const address &);
int SSMLeave(int sock, const address &, const address &);

int SetupSocket(const address &, bool bind, bool ssm);

int RecvMsg(int, address &from, uint8_t *buffer, int len, int &ttl, uint64_t &ts);

#endif

