#include "dbeacon.h"
#include "protocol.h"
#include <math.h>
#include <netinet/in.h>
#include <stdio.h>

using namespace std;

static inline bool write_tlv_string(uint8_t *buf, int maxlen, int &pointer, uint8_t type, const char *str) {
	int len = strlen(str);
	if ((pointer + 2 + len) > maxlen)
		return false;
	buf[pointer + 0] = type;
	buf[pointer + 1] = len;
	memcpy(buf + pointer + 2, str, len);
	pointer += len + 2;
	return true;
}

static bool write_tlv_start(uint8_t *buff, int maxlen, int &ptr, uint8_t type, int len) {
	if ((ptr + len + 2) > maxlen)
		return false;

	buff[ptr + 0] = type;
	buff[ptr + 1] = len;

	ptr += 2;

	return true;
}

static bool write_tlv_stats(uint8_t *buff, int maxlen, int &ptr, uint8_t type, uint32_t age, int sttl, const beaconMcastState &st) {
	if (!write_tlv_start(buff, maxlen, ptr, type, 20))
		return false;

	uint8_t *b = buff + ptr;

	uint32_t val;

	val = htonl((uint32_t)st.s.timestamp);
	memcpy(b + 0, &val, sizeof(val));
	val = htonl(age);
	memcpy(b + 4, &val, sizeof(val));

	// *((uint32_t *)(b + 0)) = htonl((uint32_t)st.s.timestamp);
	// *((uint32_t *)(b + 4)) = htonl(age);

	b[8] = (sttl ? sttl : defaultTTL) - st.s.rttl;

	uint32_t *stats = (uint32_t *)(b + 9);

	val = htonl(*((uint32_t *)&st.s.avgdelay));
	memcpy(stats + 0, &val, sizeof(val));
	val = htonl(*((uint32_t *)&st.s.avgjitter));
	memcpy(stats + 1, &val, sizeof(val));

	// stats[0] = htonl(*((uint32_t *)&st.s.avgdelay));
	// stats[1] = htonl(*((uint32_t *)&st.s.avgjitter));

	b[17] = (uint8_t)(st.s.avgloss * 0xff);
	b[18] = st.s.avgdup > 10. ? 0xff : ((uint8_t)ceil(st.s.avgdup * 25.5));
	b[19] = (uint8_t)(st.s.avgooo * 0xff);

	ptr += 20;

	return true;
}

int build_report(uint8_t *buff, int maxlen, int type, bool publishsources) {
	if (maxlen < 4)
		return -1;

	// 0-2 magic
	*((uint16_t *)buff) = htons(0xbeac);

	// 3 version
	buff[2] = PROTO_VER;

	// 4 packet type
	buff[3] = 1; // Report

	buff[4] = defaultTTL; // Original Hop Limit

	int ptr = 5;

	if (!write_tlv_string(buff, maxlen, ptr, T_BEAC_NAME, beaconName.c_str()))
		return -1;
	if (!write_tlv_string(buff, maxlen, ptr, T_ADMIN_CONTACT, adminContact.c_str()))
		return -1;

	if (type == WEBSITE_REPORT) {
		for (WebSites::const_iterator j = webSites.begin(); j != webSites.end(); j++)
			if (!write_tlv_string(buff, maxlen, ptr, j->first, j->second.c_str()))
				return -1;
		if (!twoLetterCC.empty()) {
			if (!write_tlv_string(buff, maxlen, ptr, T_CC, twoLetterCC.c_str()))
				return -1;
		}
		return ptr;
	} else if (type == LEAVE_REPORT) {
		if (!write_tlv_start(buff, maxlen, ptr, T_LEAVE, 0))
			return -1;
		return ptr;
	}

	if (publishsources) {
		uint64_t now = get_timestamp();

		for (Sources::const_iterator i = sources.begin(); i != sources.end(); i++) {
			if (!i->second.identified)
				continue;

			if (!i->second.ASM.s.valid && !i->second.SSM.s.valid)
				continue;

			int len = 18;

			if (i->first.family() == AF_INET)
				len = 6;

			if (type == MAP_REPORT) {
				int namelen = i->second.name.size();
				int contactlen = i->second.adminContact.size();
				len += 2 + namelen + 2 + contactlen;
			} else {
				len += (i->second.ASM.s.valid ? 22 : 0) + (i->second.SSM.s.valid ? 22 : 0);
			}

			if (!write_tlv_start(buff, maxlen, ptr, i->first.family() == AF_INET6 ? T_SOURCE_INFO : T_SOURCE_INFO_IPv4, len))
				break;

			if (i->first.family() == AF_INET6) {
				const sockaddr_in6 *addr = i->first.v6();

				memcpy(buff + ptr, &addr->sin6_addr, sizeof(in6_addr));
				memcpy(buff + ptr + 16, &addr->sin6_port, sizeof(uint16_t));

				ptr += 18;
			} else {
				const sockaddr_in *addr = i->first.v4();

				memcpy(buff + ptr, &addr->sin_addr, sizeof(in_addr));
				memcpy(buff + ptr + 4, &addr->sin_port, sizeof(uint16_t));

				ptr += 6;
			}

			if (type == MAP_REPORT) {
				write_tlv_string(buff, maxlen, ptr, T_BEAC_NAME, i->second.name.c_str());
				write_tlv_string(buff, maxlen, ptr, T_ADMIN_CONTACT, i->second.adminContact.c_str());
			} else {
				uint32_t age = (now - i->second.creation) / 1000;

				if (i->second.ASM.s.valid)
					write_tlv_stats(buff, maxlen, ptr, T_ASM_STATS, age, i->second.sttl, i->second.ASM);
				if (i->second.SSM.s.valid)
					write_tlv_stats(buff, maxlen, ptr, T_SSM_STATS, age, i->second.sttl, i->second.SSM);
			}
		}
	}

	return ptr;
}

int build_probe(uint8_t *buff, int maxlen, uint32_t sn, uint64_t ts) {
	if (maxlen < (int)(4 + 4 + 4))
		return -1;

	// 0-2 magic
	*((uint16_t *)buff) = htons(0xbeac);

	// 3 version
	buff[2] = PROTO_VER;

	// 4 packet type
	buff[3] = 0; // Probe

	*((uint32_t *)(buff + 4)) = htonl(sn);
	*((uint32_t *)(buff + 8)) = htonl((uint32_t)ts);

	return 4 + 4 + 4;
}

static inline uint8_t *tlv_begin(uint8_t *hd, int &len) {
	if (len < 2 || hd[1] > len)
		return 0;
	return hd;
}

static inline uint8_t *tlv_next(uint8_t *hd, int &len) {
	len -= hd[1] + 2;
	return tlv_begin(hd + hd[1] + 2, len);
}

static bool read_tlv_stats(uint8_t *tlv, beaconExternalStats &extb, Stats &st) {
	if (tlv[1] != 20)
		return false;

	uint32_t tmp;

	memcpy(&tmp, tlv + 2, sizeof(tmp));
	st.timestamp = ntohl(tmp);
	memcpy(&tmp, tlv + 6, sizeof(tmp));
	extb.age = tmp;

	// st.timestamp = ntohl(*(uint32_t *)(tlv + 2));
	// extb.age = ntohl(*(uint32_t *)(tlv + 6));

	st.rttl = tlv[10];

	memcpy(&tmp, tlv + 11, sizeof(tmp));
	tmp = ntohl(tmp);

	// tmp = ntohl(*(uint32_t *)(tlv + 11));
	st.avgdelay = *(float *)&tmp;

	memcpy(&tmp, tlv + 15, sizeof(tmp));
	tmp = ntohl(tmp);

	// tmp = ntohl(*(uint32_t *)(tlv + 15));
	st.avgjitter = *(float *)&tmp;

	st.avgloss = tlv[19] / 255.;
	st.avgdup = tlv[20] == 0xff ? 1e10 : tlv[20] / 25.5;
	st.avgooo = tlv[21] / 255.;

	st.valid = true;

	return true;
}

static inline bool check_string(char *hd, int len, string &result) {
	for (int i = 0; i < len; i++) {
		if (hd[i] <= 0)
			return false;
	}
	result = string(hd, len);
	return true;
}

void handle_nmsg(const address &from, uint64_t recvdts, int ttl, uint8_t *buff, int len, bool ssm) {
	if (len < 4)
		return;

	if (ntohs(*((uint16_t *)buff)) != 0xbeac)
		return;

	if (buff[2] != PROTO_VER)
		return;

	if (buff[3] == 0) {
		if (len == 12) {
			uint32_t seq = ntohl(*((uint32_t *)(buff + 4)));
			uint32_t ts = ntohl(*((uint32_t *)(buff + 8)));
			getSource(from, 0, recvdts, true).update(ttl, seq, ts, recvdts, ssm);
		}
		return;
	} else if (buff[3] == 1) {
		if (len < 5)
			return;

		beaconSource &src = getSource(from, 0, recvdts, true);

		src.sttl = buff[4];

		len -= 5;

		for (uint8_t *hd = tlv_begin(buff + 5, len); hd; hd = tlv_next(hd, len)) {
			if (verbose > 4) {
				char tmp[64];
				from.print(tmp, sizeof(tmp));
				fprintf(stderr, "Parsing TLV (%i, %i) for %s [len is now %i]\n", (int)hd[0], (int)hd[1], tmp, len);
			}

			if (hd[0] == T_BEAC_NAME) {
				string name;
				if (check_string((char *)hd + 2, hd[1], name))
					src.setName(name);
			} else if (hd[0] == T_ADMIN_CONTACT) {
				check_string((char *)hd + 2, hd[1], src.adminContact);
			} else if (hd[0] == T_SOURCE_INFO || hd[0] == T_SOURCE_INFO_IPv4) {
				int blen = hd[0] == T_SOURCE_INFO ? 18 : 6;

				if (hd[1] < blen)
					continue;

				address addr;

				if (hd[0] == T_SOURCE_INFO) {
					sockaddr_in6 *a6 = (sockaddr_in6 *)&addr;

					a6->sin6_family = AF_INET6;

					memcpy(&a6->sin6_addr, hd + 2, sizeof(in6_addr));
					memcpy(&a6->sin6_port, hd + 18, sizeof(uint16_t));
				} else {
					sockaddr_in *a4 = (sockaddr_in *)&addr;

					a4->sin_family = AF_INET;

					memcpy(&a4->sin_addr, hd + 2, sizeof(in_addr));
					memcpy(&a4->sin_port, hd + 6, sizeof(uint16_t));
				}

				beaconExternalStats &stats = src.getExternal(addr, recvdts);

				int plen = hd[1] - blen;
				for (uint8_t *pd = tlv_begin(hd + 2 + blen, plen); pd; pd = tlv_next(pd, plen)) {
					if (pd[0] == T_BEAC_NAME) {
						if (check_string((char *)pd + 2, pd[1], stats.name)) {
							stats.identified = !stats.name.empty();
						}
					} else if (pd[0] == T_ADMIN_CONTACT) {
						check_string((char *)pd + 2, pd[1], stats.contact);
					} else if (pd[0] == T_ASM_STATS || pd[0] == T_SSM_STATS) {
						Stats *st = (pd[0] == T_ASM_STATS ? &stats.ASM : &stats.SSM);

						if (!read_tlv_stats(pd, stats, *st))
							break;
						st->lastupdate = recvdts;
					}
				}

				// trigger local SSM join
				if (!addr.is_equal(beaconUnicastAddr)) {
					beaconSource &t = getSource(addr, stats.identified ? stats.name.c_str() : 0, recvdts, false);
					if (t.adminContact.empty())
						t.adminContact = stats.contact;
				}
			} else if (hd[0] == T_WEBSITE_GENERIC || hd[0] == T_WEBSITE_LG || hd[0] == T_WEBSITE_MATRIX) {
				string url;
				if (check_string((char *)hd + 2, hd[1], url)) {
					src.webSites[hd[0]] = url;
				}
			} else if (hd[0] == T_CC) {
				if (hd[1] == 2) {
					src.CC = string((char *)hd + 2, 2);
				}
			} else if (hd[0] == T_LEAVE) {
				removeSource(from, false);
				break;
			}
		}
	}
}

