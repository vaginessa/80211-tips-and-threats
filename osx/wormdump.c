#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/select.h>
#include <sys/param.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/bpf.h>

// don't feel like doing this properly
#define SIOCGIFLLADDR   _IOWR('i', 158, struct ifreq) /* get link level addr */

#define PACKED __attribute__((packed))

struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __packed;

#define TEN_TEN 1

#define STR_ENUM_ENUMERATOR(name, val) \
	name = val,

#define STR_ENUM_CASE(name, val) \
	case name: return #name;

#define STR_ENUM(name, enumvals) \
	enum name { \
		enumvals(STR_ENUM_ENUMERATOR) \
	}; \
	static const char *strval_##name(enum name e) { \
		switch (e) { \
			enumvals(STR_ENUM_CASE) \
		default: \
			return "(unknown " #name ")"; \
		} \
	}

#define ensure(x...) do { \
	if(!(x)) { \
		perror(#x); \
		exit(1); \
	} \
} while(0)

enum apple80211_cipher_type {
    APPLE80211_CIPHER_NONE      = 0,
    APPLE80211_CIPHER_WEP_40  = 1,
    APPLE80211_CIPHER_WEP_104 = 2,
    APPLE80211_CIPHER_TKIP      = 3,
    APPLE80211_CIPHER_AES_OCB = 4,
    APPLE80211_CIPHER_AES_CCM = 5,
    APPLE80211_CIPHER_PMK      = 6,
    APPLE80211_CIPHER_PMKSA      = 7,
};

enum apple80211_authtype_lower {
    APPLE80211_AUTHTYPE_OPEN  = 1,
    APPLE80211_AUTHTYPE_SHARED = 2,
    APPLE80211_AUTHTYPE_CISCO  = 3,
};

enum apple80211_apmode {
    APPLE80211_AP_MODE_UNKNOWN = 0,
    APPLE80211_AP_MODE_IBSS = 1,
    APPLE80211_AP_MODE_INFRA = 2,
    APPLE80211_AP_MODE_ANY = 3,
};


enum {
    APPLE80211_KEY_FLAG_UNICAST = 0x1,
    APPLE80211_KEY_FLAG_MULTICAST = 0x2,
    APPLE80211_KEY_FLAG_TX = 0x4,
    APPLE80211_KEY_FLAG_RX = 0x8,
};

/* This is up to date from wifid. */
#define enumvals(e) \
    e(APPLE80211_M_POWER_CHANGED, 1) \
    e(APPLE80211_M_SSID_CHANGED, 2) \
    e(APPLE80211_M_BSSID_CHANGED, 3) \
    e(APPLE80211_M_LINK_CHANGED, 4) \
    e(APPLE80211_M_MIC_ERROR_UCAST, 5) \
    e(APPLE80211_M_MIC_ERROR_MCAST, 6) \
    e(APPLE80211_M_INT_MIT_CHANGED, 7) \
    e(APPLE80211_M_MODE_CHANGED, 8) \
    e(APPLE80211_M_ASSOC_DONE, 9) \
    e(APPLE80211_M_SCAN_DONE, 10) \
    e(APPLE80211_M_COUNTRY_CODE_CHANGED, 11) \
    e(APPLE80211_M_STA_ARRIVE, 12) \
    e(APPLE80211_M_STA_LEAVE, 13) \
    e(APPLE80211_M_DECRYPTION_FAILURE, 14) \
    e(APPLE80211_M_SCAN_CACHE_UPDATED, 15) \
    e(APPLE80211_M_INTERNAL_SCAN_DONE, 16) \
    e(APPLE80211_M_LINK_QUALITY, 17) \
    e(APPLE80211_M_IBSS_PEER_ARRIVED, 18) \
    e(APPLE80211_M_IBSS_PEER_LEFT, 19) \
    e(APPLE80211_M_RSN_HANDSHAKE_DONE, 20) \
    e(APPLE80211_M_BT_COEX_CHANGED, 21) \
    e(APPLE80211_M_P2P_PEER_DETECTED, 22) \
    e(APPLE80211_M_P2P_LISTEN_COMPLETE, 23) \
    e(APPLE80211_M_P2P_SCAN_COMPLETE, 24) \
    e(APPLE80211_M_P2P_LISTEN_STARTED, 25) \
    e(APPLE80211_M_P2P_SCAN_STARTED, 26) \
    e(APPLE80211_M_P2P_INTERFACE_CREATED, 27) \
    e(APPLE80211_M_P2P_GROUP_STARTED, 28) \
    e(APPLE80211_M_BGSCAN_NET_DISCOVERED, 29) \
    e(APPLE80211_M_ROAMED, 30) \
    e(APPLE80211_M_ACT_FRM_TX_COMPLETE, 31) \
    e(APPLE80211_M_DEAUTH_RECEIVED, 32)
STR_ENUM(a80211_event_code, enumvals)
#undef enumvals

#define enumvals(e) \
	e(APPLE80211_LOCALE_UNKNOWN	, 0) \
	e(APPLE80211_LOCALE_FCC, 1) \
	e(APPLE80211_LOCALE_ETSI, 2) \
	e(APPLE80211_LOCALE_JAPAN, 3) \
	e(APPLE80211_LOCALE_KOREA, 4) \
	e(APPLE80211_LOCALE_APAC, 5) \
	e(APPLE80211_LOCALE_ROW, 6)
STR_ENUM(apple80211_locale, enumvals)
#undef enumvals

struct apple80211_key {
    uint32_t version; // 0
    uint32_t key_len; // 4
    uint32_t key_cipher_type; // 8
    uint16_t key_flags; // c
    uint16_t key_index; // e
    uint8_t key[TEN_TEN ? 64 : 32]; // 10
    uint32_t key_rsc_len; // 30
    uint8_t key_rsc[8]; // 34
    struct ether_addr bssid; // 3c
	uint32_t unk; // 44
	uint8_t unk2[16]; // 48
	uint32_t unk3; // 58
	uint8_t unk4[16]; // 5c
	uint8_t unk5[8]; // 6c
    // 74
};

struct apple80211_assoc_data {
    uint32_t version; // 0
    uint16_t ad_mode; // 4
    uint16_t ad_auth_lower; // 6
    uint16_t ad_auth_upper; // 8
    uint32_t ad_ssid_len; // c
    uint8_t ad_ssid[32]; // 10
    struct ether_addr ad_bssid; // 30
    struct apple80211_key ad_key; // 38
    uint16_t ad_rsn_ie_len;
    uint8_t ad_rsn_ie[257];
	uint8_t flags[1];
};

struct apple80211_channel {
    uint32_t version;
    uint32_t channel;
    uint32_t flags;
};

enum apple80211_channel_flag {
	APPLE80211_C_FLAG_NONE = 0x0,
	APPLE80211_C_FLAG_10MHZ = 0x1,
	APPLE80211_C_FLAG_20MHZ = 0x2,
	APPLE80211_C_FLAG_40MHZ = 0x4,
	APPLE80211_C_FLAG_2GHZ = 0x8,
	APPLE80211_C_FLAG_5GHZ = 0x10,
	APPLE80211_C_FLAG_IBSS = 0x20,
	APPLE80211_C_FLAG_HOST_AP = 0x40,
	APPLE80211_C_FLAG_ACTIVE = 0x80,
	APPLE80211_C_FLAG_DFS = 0x100,
	APPLE80211_C_FLAG_EXT_ABV = 0x200,
	// name made up - set if channelWidth == 80 && 5ghz && AC
	APPLE80211_C_FLAG_80MHZ = 0x400,
};

struct apple80211_network_data {
	uint32_t version;
	uint16_t nd_mode;
	uint16_t nd_auth_lower;
	uint16_t nd_auth_upper;
	struct apple80211_channel nd_channel;
	uint32_t nd_ssid_len;
	uint8_t nd_ssid[32];
	struct apple80211_key nd_key;

  // guessed names
  uint32_t nd_flags2;
  uint8_t nd_rsn_ie[257];
	uint32_t nd_ie_len;
	void *nd_ie_data;
};

struct apple80211_power_data {
	uint32_t version;
	uint32_t num_radios;
	uint32_t power_state[4];
};


enum a80211_network_flags2 {
	NF2_A = 0x2,
	NF2_B = 0x4,
	NF2_G = 0x8,
	NF2_N = 0x10,
	NF2_AC = 0x80,
};

struct a80211_country_code {
    uint32_t version;
    uint32_t country;
};

struct apple80211_ssid_data {
    uint32_t version;
    uint32_t ssid_length;
    uint8_t ssid[32];
};

struct apple80211_scan_multiple_data {
    uint32_t version; // 0
    uint32_t three; // 4
    uint32_t ssid_count; // 8
    struct apple80211_ssid_data ssids[16]; // c
    uint32_t bssid_count;
    struct ether_addr bssids[16];
    uint32_t scan_type; // 2f0
    uint32_t phy_mode; // 2f4
    uint16_t dwell_time; // 2f8
    uint32_t rest_time; // 2fc
    uint32_t channel_count; // 300
    struct apple80211_channel channels[128]; // 304
    uint8_t unk2[1]; // 904
};

struct apple80211_scan_result {
    uint32_t version; // 0
    struct apple80211_channel asr_channel; // 4
#if TEN_TEN
	int16_t asr_unk;
#endif
    int16_t asr_noise; // 10 / 12
#if TEN_TEN
	int16_t asr_unk2;
#endif
    int16_t asr_rssi; // 12 / 16
    uint16_t asr_beacon_int; // 14
    uint16_t asr_cap; // 16
    struct ether_addr asr_bssid; // 18
    uint8_t asr_nrates; // 1e
    uint32_t asr_rates[15]; // 1f
    uint8_t asr_ssid_len; // 1c
    uint8_t asr_ssid[32]; // 1d
    uint32_t asr_age;
    uint16_t unk;
    uint16_t asr_ie_len;
    void *asr_ie_data;
};

struct apple80211_deauth_data {
    uint32_t version;
    uint32_t deauth_reason;
    uint8_t deauth_ea[6];
};

struct a80211_set_offload_rsn_data {
    uint32_t version;
    uint32_t settings;
};

struct a80211_get_channel_data {
	int status;
	struct apple80211_channel channel;
};

struct apple80211_factory_mode_data {
	uint32_t version;
	uint8_t mode1; // power management
	uint8_t mode2; // country
	uint8_t mode3; // roaming
};

struct apple80211_locale_data {
	uint32_t version;
	uint32_t locale;
};

enum a80211_key_management {
	RSN_8021X_RSN = 4,
	RSN_8021X = 1,
	RSN_PSK_RSN = 8,
	RSN_PSK = 2,
};

struct apple80211_rsn_params {
    uint32_t multicast_cipher;
    uint32_t unicast_cipher_count;
    uint32_t unicast_cipher[8];
    uint32_t key_management_count;
    uint32_t key_management[8];
    uint16_t flags; // replay counter stuff
};

struct apple80211_rsn_conf_data {
    uint32_t version;
    struct apple80211_rsn_params wpa_params;
    struct apple80211_rsn_params wpa2_params;
};

enum a80211_ie_flags {
	IE_PRBREQ = 0x1,
	IE_PRBRSP = 0x2,
	IE_ASSOCREQ = 0x4,
	IE_ASSOCRSP = 0x8,
	IE_BEACON = 0x10,
};

struct apple80211_ie_data {
	uint32_t version; // 0
	uint32_t flags; // 4
	uint32_t have_ie; // 8
	uint32_t some_other_len; // c
	uint32_t ie_len; // 10
	void *ie_data; // 18
};

struct apple80211req {
    char ifname[16]; //0
    uint32_t type; // 0x10
    uint32_t value; // 0x14
    uint32_t length; // 0x18
    void *data; // 0x20 / 0x1c
#ifndef __LP64__
    uint32_t unk; // 0x20
#endif
};

_Static_assert(sizeof(struct apple80211_assoc_data) == (TEN_TEN ? 0x1d0 : 0x1b0), "wrong apple80211_assoc_data size");

_Static_assert(sizeof(struct apple80211_rsn_conf_data) == 0xa4, "wrong apple80211_rsn_conf_data size");

_Static_assert(sizeof(struct apple80211_network_data) ==
#ifdef __LP64__
	TEN_TEN ? 0x1e8 : 0x1c8
#else
	0x1e4 // ?
#endif
, "wrong apple80211_network_data size");

_Static_assert(sizeof(struct apple80211_scan_result) ==
#ifdef __LP64__
    (TEN_TEN ? 0x98 : 0x90)
#else
    0x8c
#endif
    , "wrong apple80211_scan_result size");

_Static_assert(sizeof(struct apple80211_scan_multiple_data) == 0x908, "wrong apple80211_scan_multiple_data size");


_Static_assert(sizeof(struct apple80211_ie_data) == 0x20, "wrong apple80211_ie_data size");

_Static_assert(sizeof(struct apple80211req) ==
#ifdef __LP64__
    0x28
#else
    0x24
#endif
    , "wrong apple80211req size");

#define A80211_IOC_SET _IOW('i', 200, struct apple80211req)
#define A80211_IOC_GET _IOWR('i', 201, struct apple80211req)

static int a80211_sock = -1;
static char ifname[16] = "en0";
static int ev_sock = -1;
static int bpf_fd = -1;


static int a80211_getset(uint32_t ioc, uint32_t type, uint32_t *valuep, void *data, size_t length) {
	ensure(length < UINT32_MAX);
    struct apple80211req cmd;
    memcpy(cmd.ifname, ifname, 16);
    cmd.type = type;
    cmd.value = valuep ? *valuep : 0;
    cmd.length = (uint32_t) length;
    cmd.data = data;
	errno = 0;
    int ret = ioctl(a80211_sock, ioc, &cmd, sizeof(cmd));
	if (valuep)
		*valuep = cmd.value;
	return ret;
}

static int scan_cache_clear() {
	return a80211_getset(A80211_IOC_SET, 90, 0, NULL, 0);
}

static int scan() {
	static struct apple80211_scan_multiple_data smd;

	memset(&smd, 0, sizeof(smd));
	smd.version = 1;
	smd.three = 3;
	smd.scan_type = 1;
	smd.phy_mode = 1;

	return a80211_getset(A80211_IOC_SET, 86, 0, &smd, sizeof(smd));
}

static int get_channel(struct apple80211_channel *chan) {
	struct a80211_get_channel_data data;
	int ret;
	if ((ret = a80211_getset(A80211_IOC_GET, 4 /* CHANNEL */, 0, &data, sizeof(data))))
		return ret;
	ensure(data.status == 1);
	*chan = data.channel;
	return 0;
}

static int set_channel(struct apple80211_channel *channel) {
    return a80211_getset(A80211_IOC_SET, 4, NULL, channel, sizeof(*channel));
}

static int set_offload_rsn_config(uint32_t setting, uint32_t gtk_owner) {
	struct a80211_set_offload_rsn_data data;
	data.version = 1;
	data.settings = setting | gtk_owner;
	return a80211_getset(A80211_IOC_SET, 177, 0, &data, sizeof(data));
}

static int set_powersave(uint32_t setting) {
	return a80211_getset(A80211_IOC_SET, 5, &setting, NULL, 0);
}

static int get_ssid(char *ssid) {
    return a80211_getset(A80211_IOC_GET, 1, 0, ssid, 32);
}

static int get_bssid(struct ether_addr *bssid) {
    return a80211_getset(A80211_IOC_GET, 9, 0, bssid, sizeof(*bssid));
}

static int get_factory_mode(struct apple80211_factory_mode_data *factory) {
    return a80211_getset(A80211_IOC_GET, 112, 0, factory, sizeof(*factory));
}

static int get_locale(uint32_t *locale) {
    return a80211_getset(A80211_IOC_GET, 28, locale, NULL, 0);
}

static int set_locale(uint32_t locale) {
    return a80211_getset(A80211_IOC_SET, 28, &locale, NULL, 0);
}

static int set_debug_flags(uint32_t flags) {
    return a80211_getset(A80211_IOC_SET, 52, &flags, NULL, 0);
}

static int disassociate() {
    return a80211_getset(A80211_IOC_SET, 22, NULL, NULL, 0);
}

static int host_ap(struct apple80211_network_data *data) {
	uint32_t one = 1;
    return a80211_getset(A80211_IOC_SET, 25, &one, data, sizeof(*data));
}

static int disable_host_ap() {
	uint32_t two = 2;
    return a80211_getset(A80211_IOC_SET, 25, &two, NULL, 0);
}
static void hex_dump(uint8_t *data, size_t len);

static int set_ies(int flags, void *ie_data, size_t ie_len) {
	uint8_t *iep = ie_data;
	static uint8_t buf[1024];
	int num_added = 0;
	size_t i;
	for (i = 0; i < ie_len;) {
		ensure(ie_len - i >= 2);
		uint8_t eid = iep[i++];
		size_t len = iep[i++];
		ensure(ie_len - i >= len);
		if (eid >= 200 || eid == 7 /* country */) {

			struct apple80211_ie_data data;
			memset(&data, 0, sizeof(data));
			data.version = 1;
			data.flags = flags;
			data.have_ie = 1;
			ensure(len <= 1023);
			memcpy(&buf[1], &iep[i], len);
			buf[0] = eid;
			data.some_other_len = data.ie_len = (uint32_t) len + 1;
			data.ie_data = buf;
			int ret = a80211_getset(A80211_IOC_SET, 85, NULL, &data, sizeof(data));
			if (ret) {
				printf("(error setting IE @ %zu)\n", i);
				return ret;
			}
			num_added++;
		}
		i += len;
	}
	ensure(i == ie_len);
	return num_added;
}

static int get_lladdr(struct ether_addr *addr) {
	struct ifreq ifr;
	_Static_assert(sizeof(ifr.ifr_name) == 16, "ifr_name");
	memcpy(ifr.ifr_name, ifname, 16);
	int ret = ioctl(a80211_sock, SIOCGIFLLADDR, &ifr);
	if (ret)
		return ret;
	ensure(ifr.ifr_addr.sa_len == sizeof(struct ether_addr));
	memcpy(addr, ifr.ifr_addr.sa_data, sizeof(struct ether_addr));
	return 0;
}

static int set_lladdr(struct ether_addr *addr) {
	struct ifreq ifr;
	_Static_assert(sizeof(ifr.ifr_name) == 16, "ifr_name");
	memcpy(ifr.ifr_name, ifname, 16);
	ifr.ifr_addr.sa_len = sizeof(struct ether_addr);
	memcpy(ifr.ifr_addr.sa_data, addr, sizeof(struct ether_addr));
	return ioctl(a80211_sock, SIOCSIFLLADDR, &ifr);
}

static int get_power(struct apple80211_power_data *data) {
    return a80211_getset(A80211_IOC_GET, 19, NULL, data, sizeof(*data));
}

static int set_power(struct apple80211_power_data *data) {
    return a80211_getset(A80211_IOC_SET, 19, NULL, data, sizeof(*data));
}

static void power_cycle() {
	struct apple80211_power_data data;
	ensure(!get_power(&data));
	printf("num radios %d\n", data.num_radios);
	ensure(data.num_radios <= 4);
	data.version = 1;
	for (int i = 0; i < data.num_radios; i++)
		data.power_state[i] = 0;
	ensure(!set_power(&data));
	for (int i = 0; i < data.num_radios; i++)
		data.power_state[i] = 1;
	ensure(!set_power(&data));
}

static void set_bpf_is_monitor(bool monitor) {
	ensure(!ioctl(bpf_fd, BIOCSDLT, (int[]) {monitor ? DLT_IEEE802_11 : DLT_EN10MB }));
}

static void test_injection() {
	set_bpf_is_monitor(true);
#define MCS
#define RATE
	struct {
		struct ieee80211_radiotap_header rt;
		uint8_t flags;
#ifdef RATE
		//uint8_t pad;
		uint8_t rate;
		//uint8_t dumb_osx;
#endif
#ifdef MCS
		uint8_t mcs[3];
#endif
		char data[sizeof(assoc_template)];
	} PACKED d;
    d.rt.it_version = 0;
    d.rt.it_pad = 0;
    d.rt.it_len = offsetof(typeof(d), data);
    d.rt.it_present =  1 << 1; // flags
#ifdef RATE
	d.rt.it_present |= 1 << 2;  // rate
#endif
#ifdef MCS
	d.rt.it_present |= 1 << 19; // MCS
#endif

	d.flags = 0x02; // short preamble
#ifdef RATE
	d.rate = 2;
	printf("    rate = %d\n", d.rate);
#endif
#ifdef MCS
	d.mcs[0] = 0x03 | 0x04 | 0x08 | 0x10; // known
	d.mcs[1] = 0x00 | 0x04 | 0x08 | 0x10; // flags
	d.mcs[2] = 0x00; // mcs
	printf("    mcs = 0x%02x, 0x%02x, 0x%02x\n", d.mcs[0], d.mcs[1], d.mcs[2]);
#endif
	memcpy(d.data, assoc_template, sizeof(d.data));
	printf("inject: (it_present = %x)\n", d.rt.it_present);
	ensure(write(bpf_fd, &d, sizeof(d)) == sizeof(d));
	sleep(1);
	exit(0);
}


static void enable_bpf() {
	struct ifreq ifr;
	memcpy(ifr.ifr_name, ifname, 16);

	ensure(!fcntl(bpf_fd, F_SETFL, O_NONBLOCK));
	//ensure(!ioctl(bpf_fd, BIOCSBLEN, (int[]) {2048}));
	ensure(!ioctl(bpf_fd, BIOCSETIF, &ifr));
	ensure(!ioctl(bpf_fd, BIOCIMMEDIATE, (int[]) {1}));
	ensure(!ioctl(bpf_fd, BIOCSHDRCMPLT, (int[]) {1}));
	set_bpf_is_monitor(true);
	set_bpf_is_monitor(false);
}

static void setup() {
	a80211_sock = socket(PF_INET, SOCK_DGRAM, 0);
	ensure(a80211_sock != -1);
	// see if it actually responds to Apple80211 requests */
	struct apple80211_channel chan;
	ensure(!get_channel(&chan));

	ensure(!get_lladdr(&orig_lladdr));
	have_orig_lladdr = true;

	ev_sock = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
	ensure(ev_sock != -1);

	char bpf_path[sizeof("/dev/bpf99")];
	for (int i = 1; i < 100; i++) {
		sprintf(bpf_path, "/dev/bpf%d", i);
		bpf_fd = open(bpf_path, O_RDWR);
		if (bpf_fd >= 0)
			break;
	}
	if (bpf_fd == -1) {
		printf("couldn't open bpf :(\n");
		exit(1);
	}

	struct kev_request kev;
	kev.vendor_code = KEV_VENDOR_APPLE;
	kev.kev_class = KEV_IEEE80211_CLASS;
	kev.kev_subclass = KEV_ANY_SUBCLASS;
	ensure(!ioctl(ev_sock, SIOCSKEVFILT, &kev));

	ensure(!ioctl(ev_sock, FIONBIO, (int[]) {1}, sizeof(int)));

#if 0
	ensure(!set_powersave(0));
	//ensure(!set_offload_rsn_config(1, 0x10)); // ?
	ensure(!get_locale(&orig_locale));
	atexit(pre_exit);
	signal(SIGINT, sigint);
	ensure(!set_debug_flags(0xffffffff));
	printf("original locale %s; setting to JAPAN\n", strval_apple80211_locale(orig_locale));
	// On 10.10, JAPAN doesn't work, although ROW (rest of world) seems
	// to suffice to at least see networks in scan results.
	ensure(!set_locale(TEN_TEN ? APPLE80211_LOCALE_ROW : APPLE80211_LOCALE_JAPAN));
	ensure(!disassociate());
	power_cycle();
#endif

	enable_bpf();
}


static void fakesta_associate(const struct apple80211_scan_result *result) {

	ensure(!set_lladdr((void *) (uint8_t[]) {0xb8, 0xaf, 0x6e, 0x09, 0x01, 0xab}));

	fakesta_state = ST_FAKESTA_ASSOCIATING;
	struct apple80211_assoc_data ad;

	memset(&ad, 0, sizeof(ad));
	ad.version = 1;
	ad.ad_mode = APPLE80211_AP_MODE_INFRA;
	ad.ad_auth_upper = 0x20;
	ad.ad_auth_lower = APPLE80211_AUTHTYPE_SHARED;
	memcpy(ad.ad_ssid, result->asr_ssid, 32);
	//strcpy((char*)ad.ad_ssid, "LOLO");
	ad.ad_ssid_len = result->asr_ssid_len;
	ad.ad_bssid = result->asr_bssid;

	struct apple80211_key *key = &ad.ad_key;
	key->version = 1;
	key->key_len = 13;
	key->key_cipher_type = APPLE80211_CIPHER_WEP_104;
	key->key_rsc_len = 8;
	key->key_flags |= APPLE80211_KEY_FLAG_TX;
	key->key_flags |= APPLE80211_KEY_FLAG_RX;
	key->key_flags |= APPLE80211_KEY_FLAG_UNICAST;
	key->key_flags |= APPLE80211_KEY_FLAG_MULTICAST;

	ad.ad_rsn_ie_len = sizeof(fake_rsn_ie);
	memcpy(ad.ad_rsn_ie, fake_rsn_ie, sizeof(fake_rsn_ie));

	//ad.flags[0] = 1;

	/*
	// I don't think this is necessary, but it keeps everything in one channel to sniff.
	struct apple80211_channel chan = result->asr_channel;
	chan.version = 1;
	// I get 0xa, aka 20MHZ | 2GHZ
	printf(" -> set channel %d flags %x\n", chan.channel, chan.flags);
	ensure(!set_channel(&chan));
	*/

	printf(" -> associating to bssid %s...\n", ether_ntoa(&ad.ad_bssid));
	// setBSSID
	ensure(!a80211_getset(A80211_IOC_SET, 9, 0, &ad.ad_bssid, sizeof(ad.ad_bssid)));

	// setASSOCIATE
	ensure(!a80211_getset(A80211_IOC_SET, 20, 0, &ad, sizeof(ad)));

	fakesta_forge_assoc(result);
}

// country:
// ioc 0x54
// iovar 495/275
// 0x54 <- wlcStart
// cmd 0x70 = factory mode w/ apple80211_factory_mode_data

/* encryption:
   flags2 = {OPEN: 0, SHARED: 1, CISCO: 128}
   ioctl 22, flags2
	   +116w = flags2 == 1
	   +118w = flags2 > 1
   flags1 = (based on upper flags)
   ioctl 165, flags1
	   "wpa_auth" -> firmware
*/


static void fakeap_host(struct ether_addr bssid, int channel, char *ssid, size_t ssid_len, void *ie_data, size_t ie_len) {
	printf("hosting with bssid %s channel %d\n", ether_ntoa(&bssid), channel);
	printf("IE data:\n");
	uint8_t *iep = ie_data;
	size_t i;
	for (i = 0; i < ie_len;) {
		ensure(ie_len - i >= 2);
		int eid = iep[i++];
		int len = iep[i++];
		ensure(ie_len - i >= len);
		if (eid >= 200 || eid == 7 /* country */) {
			printf("   (%d) ", eid);
			hex_dump(&iep[i], len);
			printf("\n");
		}
		i += len;
	}
	ensure(i == ie_len);
	ensure(!set_lladdr(&bssid));

	struct apple80211_network_data data;
	memset(&data, 0, sizeof(data));
	data.version = 1;
	data.nd_mode = 2;

	//data.nd_auth_upper = 0x20;
	//data.nd_auth_lower = APPLE80211_AUTHTYPE_OPEN;
	data.nd_auth_upper = 0;
	data.nd_auth_lower = APPLE80211_AUTHTYPE_OPEN;

	struct apple80211_key *key = &data.nd_key;
	key->version = 1;
	key->key_len = 13;
	key->key_cipher_type = APPLE80211_CIPHER_WEP_104;
	key->key_rsc_len = 8;
	key->key_flags |= APPLE80211_KEY_FLAG_TX;
	key->key_flags |= APPLE80211_KEY_FLAG_RX;
	key->key_flags |= APPLE80211_KEY_FLAG_UNICAST;
	key->key_flags |= APPLE80211_KEY_FLAG_MULTICAST;

	data.nd_channel.version = 1;
	ensure(1 <= channel && channel <= 11);
	data.nd_channel.channel = channel;
	data.nd_channel.flags = 0xa;
	ensure(ssid_len <= 32);
	memcpy(data.nd_ssid, ssid, ssid_len);
	data.nd_ssid_len = (uint32_t) ssid_len;
	data.nd_flags2 = NF2_G | NF2_N;
	ensure(ie_len <= UINT32_MAX);
	data.nd_ie_len = (uint32_t) ie_len;
	data.nd_ie_data = ie_data;
	// wifid also does RSN_CONF
	ensure(!host_ap(&data));

	// since it apparently ignores ie_data
	int num_added = set_ies(IE_BEACON | IE_PRBRSP, ie_data, ie_len);
	ensure(num_added >= 0);
	printf("IEs added: %d\n", num_added);

	fakeap_state = ST_FAKEAP_ASSOC_WAIT;
}

static void read_ev() {
	struct {
		struct kern_event_msg msg;
		uint8_t rest[0x1000];
	} buf;
	ssize_t size = recv(ev_sock, &buf, sizeof(buf), 0);
	ensure(size != -1);
	ensure(size == buf.msg.total_size);
    printf("kern event %s\n", strval_a80211_event_code(buf.msg.event_code));
    switch (buf.msg.event_code) {
    case APPLE80211_M_ASSOC_DONE:
		if (fakesta_state == ST_FAKESTA_ASSOCIATING)
			fakesta_assoc_done();
        break;
    case APPLE80211_M_BSSID_CHANGED:
		printf(" -> now ");
		dump_bssid();
        break;
    case APPLE80211_M_SCAN_CACHE_UPDATED:
		if (fakesta_state == ST_FAKESTA_SCANNING)
			fakesta_scan_done();
        break;
	}
}

static void worm_sock_established() {
	if (global_mode == FAKESTA) {
		fakesta_state = ST_FAKESTA_SCANNING;
		ensure(!scan_cache_clear());
		ensure(!scan());
	} else {
		fakeap_state = ST_FAKEAP_AP_INFO_WAIT;
	}
}

static void read_bpf() {
	printf("read_bpf\n");
	uint8_t buf[0x1000];
	ssize_t ret = read(bpf_fd, buf, sizeof(buf));
	printf("-> %zd\n", ret);
	if (ret > 0) {
		hex_dump(buf, ret);
		printf("\n");
	}
}