/*
 * Copyright 2005-2010, Hugo Santos <hugo@fivebits.net>
 * Distributed under the terms of the MIT License.
 */

#ifndef _msocket_h_
#define _msocket_h_

#include "address.h"

void MulticastStartup();

int MulticastListen(int sock, const address &);
int SSMJoin(int sock, const address &, const address &);
int SSMLeave(int sock, const address &, const address &);

int SetupSocket(const address &, bool bind, bool ssm);
bool SetHops(int sock, const address &, int);
bool RequireToAddress(int sock, const address &);

int RecvMsg(int, address &from, address &to, uint8_t *buffer, int len, int &ttl, uint64_t &ts);
int SendTo(int, const uint8_t *, int len, const address &from, const address &to);

#endif

