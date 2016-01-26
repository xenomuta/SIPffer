/*
 *    SIPffer: A SIP protocol sniffer for quick and smart troubleshooting.
 *    https://github.com/xenomuta/SIPffer
 *    XenoMuta / Methylxantina 256mg - http://xenomuta.com - xenmuta@gmail.com
 *
 *    SIPffer is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    SIPffer is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#define VERSION "1.0.0"

#ifdef __GNUC__
#define DEFAULT_NIC "any"
#else
#define DEFAULT_NIC "en0"
#endif

#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <net/bpf.h>
#else
#include <pcap/bpf.h>
#endif
#include <pcap.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "sipffer.h"

/* Ethernet Interface */
static char dev[32];
/* Pcap file */
static char file[128];
/* BPF Filter */
static char filter[2048];
/* SIP port */
static char port[5];
/* SIP method */
static char method[128];
/* SIP response */
static char response[3];
/* Seguir paguete SIP */
static char follow, *callID;
/* SIP header */
static char header[128];
/* Packets captured */
static int captured = 0;
/* Packets shown */
static int shown = 0;
/* Sniffing handler */
static pcap_t *sniff;
/* BPF filter program */
struct bpf_program fp;
/* PCRE regexp filter */
static char regexp[2048];
static pcre *rx;

/*
 * goodBye(): Trap UNIX signals and cleanup before exiting.
 *
 * Parameters:
 * - sig:  captured system signal.
 */
void goodBye(int sig) {
	fprintf(stderr, "\x1b[0;37m\n-=[ END OF CAPTURE ]=-\n\n");
	pcap_breakloop(sniff);
	pcap_freecode(&fp);
	pcap_close(sniff);

	fprintf(stderr, "%d packets captured\n%d packets shown\n\n", captured, shown);
	_exit(0);
}


/*
 * getTime(): returns formatted packet date-time
 * Y-m-d hh:mm:ss
 *
 * Parameters:
 * - cap_tv:  Captured packet's timeval
 */
char *getTime(struct timeval cap_tv) {
	char *buff;
	time_t curtime;    // Hora actual en milisegundos

	if (!cap_tv.tv_sec) return "n/a";
	curtime=cap_tv.tv_sec;

	buff = (char *)malloc(30); memset(buff, 0, 30);
	strftime(buff, 30, "%Y-%m-%d %T", localtime(&curtime));
	return buff;
}


/*
 * getSIPHeader(): Returns a header's value in a SIP packet
 *
 * Parameters:
 * - packet:				raw packet
 * - wantedHeader:	desired header
 *
 */
char *getSIPHeader(const u_char *packet, char *wantedHeader) {
	char *crudo, *linea, *header = NULL;

	crudo = strdup((char *)packet);
	linea = strtok(crudo, "\r\n");

	for (;;) {
		linea = strtok(NULL, "\r\n");
		if (!linea) break;

		if ((strchr(linea, ':'))) {
			memset(strchr(linea, ':'), 0, 1);
			header = linea;
			if (!strncasecmp(wantedHeader, header, strlen(wantedHeader))) return (header+strlen(header) + 2);
		}
	}
	if (!header) return NULL;
	header[0] = 0x00;
	return header;
}


/*
 * getSIPPacket(): Extracts SIP payload from packet
 *
 * Parameters:
 * - data: The data passed from pcap_loop()
 * - h:    Captured packet's header
 * - p:    Serialized packet data
 */
void getSIPPacket(u_char *data, const struct pcap_pkthdr *h, const u_char *p) {
	struct iphdr *cip;			// Captured IP
	const u_char *packet;	// Headerless packet
	unsigned int caplen;

	captured++;
	// Two additional bytes in 'any' interface
	if (!strlen(file) && !strcmp(dev, "any")) p += 2;

	cip = (struct iphdr *)(p+ETH_LEN);
	// Ignore packet if not correctly captured or truncated or if it isn't IPV4
	if ((!p) || (h->len <= (ETH_LEN+IP_MIN_LEN)) || ((unsigned char)cip->version != 4)) {
		if (p && p + 1) {
			p += 2;
			cip = (struct iphdr *)(p+ETH_LEN);
		} else {
			if (DEBUG) fprintf(stderr, "Invalid Packet\n");
			return;
		}
		if ((!p) || (h->len <= (ETH_LEN+IP_MIN_LEN)) || ((unsigned char)cip->version != 4)) {
			if (DEBUG) fprintf(stderr, "Invalid Packet\n");
			return;
		}
	}

	packet = (u_char *)malloc(h->len);
	memset((char *)packet, 0, h->caplen);
	strncpy((char *)packet, (char *)(p + ETH_LEN + IP_MIN_LEN + 8), h->len - (ETH_LEN + IP_MIN_LEN + 8));
	memset((char *)packet + (h->len - (ETH_LEN + IP_MIN_LEN + (!strcmp(dev, "any")?10:8))), 0, 1);

	caplen = h->caplen;
	if ((strlen(method) > 0) && strncmp((char *)packet, method, strlen(method))) return;
	if (strlen(response) > 0) {
		if (caplen < 4) return;
		if (strncmp((char *)packet, "SIP/", 4)) return;
		if (strncmp((char *)packet + 8, response, 3)) return;
	}
	if (strlen(regexp) > 0) {
		if ((strlen(header) > 0) && !rx_match(getSIPHeader(packet, header))) return;
		if (!rx_match((char *)packet)) return;
	}
	if (follow) {
		if (follow == 1) {
			if (!(callID = getSIPHeader(packet, "Call-ID"))) {
				callID = getSIPHeader(packet, "call-id");
			}
			if (callID) {
				follow = 2;
			} else return;
		}
		if (follow == 2) {
			char *call_id = getSIPHeader(packet, "Call-ID");
			if (!call_id)	call_id = getSIPHeader(packet, "call-id");
			if (!call_id)	return;
			if (strcmp(call_id, callID)) return;
		}
	}

	shown++;
	u_char *srcip = (u_char *)&cip->saddr;
	u_char *dstip = (u_char *)&cip->daddr;

	printf("\x1b[1;32m<==[%d bytes]==[%s] : %d.%d.%d.%d => ", caplen, getTime(h->ts), srcip[0], srcip[1], srcip[2], srcip[3]);
	printf("%d.%d.%d.%d ====\n\x1b[1;37m%s\n\x1b[1;32m=================>\n\n\x1b[0;37m", dstip[0], dstip[1], dstip[2], dstip[3], packet);
}

/*
 * rx_match: Verifies if packet's contents matches a pcre regexp.
 *
 * parameters:
 * - packet: the packet to match to
 */
int rx_match (char *packet) {
  const char *error;
  int erroffset;
  int rc = pcre_exec(rx, NULL, packet, strlen(packet), 0, 0, NULL, 0);
  return rc == 0;
}

/*
 * payola(): El nombre lo dice todo :)
 */
void payola() {
	fprintf(stderr, "SIPffer v%s: A SIP protocol sniffer\nXenoMuta.com - https://github.com/xenomuta/SIPffer\n\n", VERSION);
}

/*
 * usage(): Displays usage
 */
void usage() {
	fprintf(stderr, "Usage: sipffer [OPTIONS] -i interface [regular expression (PCRE)]\n");
	fprintf(stderr, "   or: sipffer [OPTIONS] -a file [regular expression (PCRE)]\n\n");
	fprintf(stderr, " -i interface:  \tEthernet Interface to sniff\n");
	fprintf(stderr, " -a/--file file:\tArchived PCAP file to read\n\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr, " -p port:       \tSpecify port to filtrar on ( defaults to udp/5060 )\n");
	fprintf(stderr, " -f BPF filter: \tFiltro BPF adicional ( formato tcpdump )\n");
	fprintf(stderr, " -m method:     \tFiltra por method SIP (INVITE,REGISTER,\n");
	fprintf(stderr, "                \t\tACK,SUBSCRIBE,CANCEL,BYE or OPTIONS)\n");
	fprintf(stderr, " -r response:   \tFilter by (numerical) response (200, 404, etc...)\n");
	// /* Soon ;) , I'm too busy or lazy */
	// fprintf(stderr, " -w file:     \tWrite the packets to a .pcap file\n");
	fprintf(stderr, " -s/--follow:   \tCapture the first matching packet and follow it's session (Call-ID)\n");
	fprintf(stderr, " -c header      \tOnly match regular expression with header specified\n");
	fprintf(stderr, "                \t\tej. (From, To, Contact, etc...)\n");
	fprintf(stderr, " -h             \tShow this help screen\n\n\n");
}

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 ip;		// Our IP
	bpf_u_int32 mask;	// Our mask
	int i;

	payola();
	memset((char *)&port, 0, sizeof(port));
	strncpy((char *)&port, "5060", sizeof(port));
	memset((char *)&dev, 0, sizeof(dev));
	memset((char *)&file, 0, sizeof(file));
	memset((char *)&method, 0, sizeof(method));
	memset((char *)&response, 0, sizeof(response));
	memset((char *)&regexp, 0, sizeof(regexp));
	memset((char *)&header, 0, sizeof(header));
	memset((char *)&filter, 0, sizeof(filter));
	follow = 0;
	/* Sniff on all interfaces by default ( Linux Only ) */
	strncpy((char *)&dev, DEFAULT_NIC, sizeof(dev));

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			strncpy((char *)&regexp, argv[i], sizeof(regexp));
			continue;
		} else if ((argv[i][0] == '-') && strcmp(argv[i], "-s") && strcmp(argv[i], "--follow") && (i + 1 == argc)) {
			usage();
			return 2;
		}
		if (!strcmp(argv[i], "-h")) {
			usage();
			return 0;
		}
		if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--follow")) {
			follow = 1;
			continue;
		}
		if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--file")) {
			strncpy((char *)&file, argv[++i], sizeof(file));
			continue;
		}
		if (!strcmp(argv[i], "-i")) {
			strncpy((char *)&dev, argv[++i], sizeof(dev));
			continue;
		}
		if (!strcmp(argv[i], "-p")) {
			strncpy((char *)&port, argv[++i], sizeof(port));
			continue;
		}
		if (!strcmp(argv[i], "-c")) {
			strncpy((char *)&header, argv[++i], sizeof(header));
			continue;
		}
		if (!strcmp(argv[i], "-f")) {
			strncpy((char *)&filter, argv[++i], sizeof(filter));
			continue;
		}
		if (!strcmp(argv[i], "-m")) {
			strncpy((char *)&method, argv[++i], sizeof(method));
			continue;
		}
		if (!strcmp(argv[i], "-r")) {
			strncpy((char *)&response, argv[++i], sizeof(response));
			continue;
		}
	}

	if ((strlen(header) > 0) && (strlen(regexp) == 0)) {
		fprintf(stderr, "ERROR: Must specify regular expression when using '-c' option\n\n");
		return 2;
	}


	if (strlen(regexp) > 0) {	
		// Build the regular expression
	  const char *rxerror;
	  int rxerroffset;
	  rx = pcre_compile((char *)&regexp, PCRE_CASELESS, &rxerror, &rxerroffset, NULL);
	  if (rx == NULL) {
	    fprintf(stderr, "ERROR: Invalid PCRE pattern at offset %d: %s\n\n", rxerroffset, rxerror);
	    return 2;
	  }
	}

	// Build the BPF filter
	char filterfinal[2048];
	memset(filterfinal, 0, 2048);
	if (strlen(filter) > 0) {
		snprintf((char *)&filterfinal, sizeof(filterfinal), "udp and port %s and %s", port, filter);
	} else {
		snprintf((char *)&filterfinal, sizeof(filterfinal), "udp and port %s", port);
	}

	// Prepare signal traps
	signal(SIGABRT, &goodBye);
	signal(SIGTERM, &goodBye);
	signal(SIGSTOP, &goodBye);
	signal(SIGKILL, &goodBye);
	signal(SIGINT, &goodBye);

	if (strlen(file) > 0) {
		if ((sniff = pcap_open_offline(file, errbuf)) == NULL) {
			fprintf(stderr, "ERROR: Can't open file '%s': %s\n\n", dev, errbuf);
			return 2;
		}
	} else {
		if ((sniff = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf)) == NULL) {
			fprintf(stderr, "ERROR: Can't open interface '%s': %s\n\n", dev, errbuf);
			return 2;
		}
		if (!strcmp(dev, "any")) {
			if ((pcap_set_datalink(sniff, DLT_LINUX_SLL)) == -1) {
				fprintf(stderr, "ERROR: Can't assign link type DTL_LINUX_SLL\n\n");
				return 2;
			}
		}
		// Find out our IP and mask
		if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
			fprintf(stderr, "WARNING: Can't find IP/Netmask for interface '%s'\n\n", dev);
			mask = 0;
			ip = 0;
		}
	}

	// Compile filter
	if (pcap_compile(sniff, &fp, filterfinal, 1, mask) == -1) {
		fprintf(stderr, "ERROR: Can't parse BPF filter \"%s\": %s\n\n", filter, pcap_geterr(sniff));
		return 2;
	}

	// Apply filter to capture
	if (pcap_setfilter(sniff, &fp) == -1) {
		fprintf(stderr, "ERROR: Can't apply BPF filter \"%s\": %s\n\n", filter, pcap_geterr(sniff));
		return 2;
	}

	// All good
	fprintf(stderr, "OK, sniffing interface '%s' on port '%s'\n", dev, port);
	if (strlen(filter) > 0) fprintf(stderr, "BPF filter: \"%s\"\n", filterfinal);
	if (strlen(method) > 0) fprintf(stderr, "Only packets with SIP method: %s\n", method);
	if (strlen(response) > 0) fprintf(stderr, "Only Packets with SIP response: %s\n", response);
	if (strlen(regexp) > 0) {
		fprintf(stderr, "Only packets matching regular expression: /%s/", regexp);
		if (strlen(header) > 0) fprintf(stderr, " in header field: %s\n", header);
		else fprintf(stderr, "\n");
	}
	if (follow) {
		fprintf(stderr, "Follow first packet with related packets by Call-ID.\n");
	}

	// Capture and parse
	int res = pcap_loop(sniff, 0, getSIPPacket, NULL);

	pcap_freecode(&fp);
	pcap_close(sniff);

	if (res > 0) {
		fprintf(stderr, "%d packets captured\n%d packets shown\n\n", res, shown);
	}
	return (res >= 0)?0:2;
}

