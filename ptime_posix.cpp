/*
 * dbeacon, a Multicast Beacon
 *   ptime_posix.cpp
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

#include "dbeacon.h"
#include "ptime.h"

#include <sys/time.h>

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

