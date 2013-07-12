/*
 *    SIPffer: Un sniffer del protocolo SIP
 *    version: 0.4
 *    https://github.com/xenomuta/SIPffer
 *    XenoMuta / Methylxantina 256mg - http://xenomuta.com - xenmuta[arroba]gmail.com
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
#define VERSION "0.4.5"

#ifdef __LINUX__
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

/* Interfaz Ethernet */
static char dev[32];
/* Archivo pcap */
static char archivo[128];
/* Filtro BPF pcap */
static char filtro[2048];
/* Puerto SIP */
static char port[5];
/* Metodo SIP */
static char metodo[128];
/* Respuesta SIP */
static char respuesta[3];
/* Seguir paguete SIP */
static char seguir, *seguir_id;
/* Cabecera SIP */
static char cabecera[128];
/* Paquetes capturados */
static int capturados = 0;
/* Paquetes mostrados */
static int mostrados = 0;
/* Manejador del sniffing */
static pcap_t *sniff;
/* Filtro BPF */
struct bpf_program fp;
/* Filtro PCRE */
static char regexp[2048];
static pcre *rx;

/*
 * adios(): Funcion que captura senales UNIX y limpia todo antes de salir
 *
 * Parametros:
 * - sig:  Senal capturada por el Sistema.
 */
void adios(int sig) {
	fprintf(stderr, "\x1b[0;37m\n-=[ END OF CAPTURE ]=-\n\n");
	pcap_breakloop(sniff);
	pcap_freecode(&fp);
	pcap_close(sniff);

	fprintf(stderr, "%d packets captured\n%d packets shown\n\n", capturados, mostrados);
	_exit(0);
}


/*
 * obtener_hora(): Retorna la fecha-hora del paquete capturado en formato
 * Y-m-d hh:mm:ss
 *
 * Parametros:
 * - cabeza:  Cabezera del paquete capturado.
 */
char *obtener_hora(struct timeval cap_tv) {
	char *buff;
	time_t curtime;    // Hora actual en milisegundos

	if (!cap_tv.tv_sec) return "n/a";
	curtime=cap_tv.tv_sec;

	buff = (char *)malloc(30); memset(buff, 0, 30);
	strftime(buff, 30, "%Y-%m-%d %T", localtime(&curtime));
	return buff;
}


/*
 * obten_cabecera_SIP(): Retorna el valor de un cabecera x en un paquete SIP
 *
 * Parametros:
 * - paquete:  paquete crudo
 * - cabecera:    el cabeceradeseado
 *
 */
char *obten_cabecera_SIP(const u_char *paquete, char *quiero_cabecera) {
	char *crudo, *linea, *cabecera = NULL;

	crudo = strdup((char *)paquete);
	linea = strtok(crudo, "\r\n");

	for (;;) {
		linea = strtok(NULL, "\r\n");
		if (!linea) break;

		if ((strchr(linea, ':'))) {
			memset(strchr(linea, ':'), 0, 1);
			cabecera = linea;
			if (!strncasecmp(quiero_cabecera, cabecera, strlen(quiero_cabecera))) return (cabecera+strlen(cabecera) + 2);
		}
	}
	if (!cabecera) return NULL;
	cabecera[0] = 0x00;
	return cabecera;
}


/*
 * obten_paquete_SIP(): Extrae la data SIP del paquete
 *
 * Parametros:
 * - data: Datos pasados a la funcion por parte de pcap_loop()
 * - h:    Cabezera del paquete capturado
 * - p:    Data serializada del paquete
 */
void obten_paquete_SIP(u_char *data, const struct pcap_pkthdr *h, const u_char *p) {
	struct iphdr *cip;			// La IP capturada
	const u_char *paquete;	// La data decapitada del paquete capturado
	unsigned int caplen;

	capturados++;
	// La interfaz any tiene 2 bytes adicionales en su header
	if (!strcmp(dev, "any")) p+=2;

	cip = (struct iphdr *)(p+ETH_LEN);
	// Ignora el paquete si no capturo bien o si esta recortado o si no es IPV4
	if ((!p) || (h->len <= (ETH_LEN+IP_MIN_LEN)) || ((unsigned char)cip->version != 4)) {
		if (DEBUG) fprintf(stderr, "Invalid Packet\n");
	} else {
		paquete = (u_char *)malloc(h->len);
		memset((char *)paquete, 0, h->caplen);
		strncpy((char *)paquete, (char *)(p + ETH_LEN + IP_MIN_LEN + 8), h->len - (ETH_LEN + IP_MIN_LEN + 8));
		memset((char *)paquete + (h->len - (ETH_LEN + IP_MIN_LEN + (!strcmp(dev, "any")?10:8))), 0, 1);

		caplen = h->caplen;
		if ((strlen(metodo) > 0) && strncmp((char *)paquete, metodo, strlen(metodo))) return;
		if (strlen(respuesta) > 0) {
			if (caplen < 4) return;
			if (strncmp((char *)paquete, "SIP/", 4)) return;
			if (strncmp((char *)paquete + 8, respuesta, 3)) return;
		}
		if (strlen(regexp) > 0) {
			if ((strlen(cabecera) > 0) && !rx_match(obten_cabecera_SIP(paquete, cabecera))) return;
			if (!rx_match((char *)paquete)) return;
		}
		if (seguir) {
			if (seguir == 1) {
				if (!(seguir_id = obten_cabecera_SIP(paquete, "Call-ID"))) {
					seguir_id = obten_cabecera_SIP(paquete, "call-id");
				}
				if (seguir_id) {
					seguir = 2;
				} else return;
			}
			if (seguir == 2) {
				char *call_id = obten_cabecera_SIP(paquete, "Call-ID");
				if (!call_id)	call_id = obten_cabecera_SIP(paquete, "call-id");
				if (!call_id)	return;
				if (strcmp(call_id, seguir_id)) return;
			}
		}

		mostrados++;
		u_char *srcip = (u_char *)&cip->saddr;
		u_char *dstip = (u_char *)&cip->daddr;

		printf("\x1b[1;32m<==[%d bytes]==[%s] : %d.%d.%d.%d => ", caplen, obtener_hora(h->ts), srcip[0], srcip[1], srcip[2], srcip[3]);
		printf("%d.%d.%d.%d ====\n\x1b[1;37m%s\n\x1b[1;32m=================>\n\n\x1b[0;37m", dstip[0], dstip[1], dstip[2], dstip[3], paquete);
	}
}

/*
 * rx_match: verifica si el paquete coincide con la expresión regular PCRE
 */
int rx_match (char *paquete) {
  const char *error;
  int erroffset;
  int rc = pcre_exec(rx, NULL, paquete, strlen(paquete), 0, 0, NULL, 0);
  return rc == 0;
}

/*
 * payola(): El nombre lo dice todo
 */
void payola() {
	fprintf(stderr, "SIPffer v%s: A SIP protocol sniffer\nXenoMuta.com - https://github.com/xenomuta/SIPffer\n\n", VERSION, 64);
}

/*
 * usage(): El nombre lo dice todo
 */
void usage() {
	fprintf(stderr, "Usage: sipffer [OPTIONS] -i interfaz [regular expression (PCRE)]\n");
	fprintf(stderr, "   or: sipffer [OPTIONS] -a file [regular expression (PCRE)]\n\n");
	fprintf(stderr, " -i interface:  \tEthernet Interface to sniff\n");
	fprintf(stderr, " -a/--file file:\tArchived PCAP file to read\n\n");
	fprintf(stderr, "OPTIONS:\n");
	fprintf(stderr, " -p port:       \tSpecify port to filtrar on ( defaults to udp/5060 )\n");
	fprintf(stderr, " -f BPF filter: \tFiltro BPF adicional ( formato tcpdump )\n");
	fprintf(stderr, " -m method:     \tFiltra por metodo SIP (INVITE,REGISTER,\n");
	fprintf(stderr, "                \t\tACK,CANCEL,BYE or OPTIONS)\n");
	fprintf(stderr, " -r response:   \tFilter by (numerical) response (200, 404, etc...)\n");
	// /* Pronto ;) , estoy muy vago */
	// fprintf(stderr, " -e archivo:     \tEscribe captura de paquetes a archivo\n");
	fprintf(stderr, " -s/--follow:   \tCapture the first matching packet and follow it's session (Call-ID)\n");
	fprintf(stderr, " -c header      \tOnly match regular expression with header specified\n");
	fprintf(stderr, "                \t\tej. (From, To, Contact, etc...)\n");
	fprintf(stderr, " -h             \tShow this help screen\n\n\n");
}

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 ip;		// Nuestra IP
	bpf_u_int32 mask;	// Nuestra Mascara
	int i;

	payola();
	memset((char *)&port, 0, sizeof(port));
	strncpy((char *)&port, "5060", sizeof(port));
	memset((char *)&dev, 0, sizeof(dev));
	memset((char *)&archivo, 0, sizeof(archivo));
	memset((char *)&metodo, 0, sizeof(metodo));
	memset((char *)&respuesta, 0, sizeof(respuesta));
	memset((char *)&regexp, 0, sizeof(regexp));
	memset((char *)&cabecera, 0, sizeof(cabecera));
	memset((char *)&filtro, 0, sizeof(filtro));
	seguir = 0;
	/* Snifea en todas por default */
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
			seguir = 1;
			continue;
		}
		if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--file")) {
			strncpy((char *)&archivo, argv[++i], sizeof(archivo));
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
			strncpy((char *)&cabecera, argv[++i], sizeof(cabecera));
			continue;
		}
		if (!strcmp(argv[i], "-f")) {
			strncpy((char *)&filtro, argv[++i], sizeof(filtro));
			continue;
		}
		if (!strcmp(argv[i], "-m")) {
			strncpy((char *)&metodo, argv[++i], sizeof(metodo));
			continue;
		}
		if (!strcmp(argv[i], "-r")) {
			strncpy((char *)&respuesta, argv[++i], sizeof(respuesta));
			continue;
		}
	}

	if ((strlen(cabecera) > 0) && (strlen(regexp) == 0)) {
		fprintf(stderr, "ERROR: Must specify regular expression when using '-c' option\n\n");
		return 2;
	}


	if (strlen(regexp) > 0) {	
		// Fabrica la expresión regular
	  const char *rxerror;
	  int rxerroffset;
	  rx = pcre_compile((char *)&regexp, PCRE_CASELESS, &rxerror, &rxerroffset, NULL);
	  if (rx == NULL) {
	    fprintf(stderr, "ERROR: Invalid PCRE pattern at offset %d: %s\n\n", rxerroffset, rxerror);
	    return 2;
	  }
	}

	// Fabrica el filtro
	char filtrofinal[2048];
	memset(filtrofinal, 0, 2048);

	snprintf((char *)&filtrofinal, sizeof(filtrofinal), "udp and port %s", port);
	if (strlen(filtro) > 0) {
		snprintf((char *)&filtrofinal, sizeof(filtrofinal), "%s and %s", filtrofinal, filtro);
	}

	// Preparate las trampas de senal
	signal(SIGABRT, &adios);
	signal(SIGTERM, &adios);
	signal(SIGSTOP, &adios);
	signal(SIGKILL, &adios);
	signal(SIGINT, &adios);

	if (strlen(archivo) > 0) {
		if ((sniff = pcap_open_offline(archivo, errbuf))==NULL) {
			fprintf(stderr, "ERROR: Can't open file '%s': %s\n\n", dev, errbuf);
			return 2;
		}
	} else {
		if ((sniff = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf))==NULL) {
			fprintf(stderr, "ERROR: Can't open interface '%s': %s\n\n", dev, errbuf);
			return 2;
		}
		if (!strcmp(dev, "any")) {
			if ((pcap_set_datalink(sniff, DLT_LINUX_SLL))==-1) {
				fprintf(stderr, "ERROR: Can't assign link type DTL_LINUX_SLL\n\n");
				return 2;
			}
		}
		// Averigua nuestra IP/Mascara
		if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
			fprintf(stderr, "ERROR: Can't find IP/Netmask for interface '%s'\n\n", dev);
			mask = 0;
			ip = 0;
		}
	}

	// Compila el filtro
	if (pcap_compile(sniff, &fp, filtrofinal, 1, mask) == -1) {
		fprintf(stderr, "ERROR: Can't parse BPF filter \"%s\": %s\n\n", filtro, pcap_geterr(sniff));
		return 2;
	}

	// Aplica el filtro a la captura
	if (pcap_setfilter(sniff, &fp) == -1) {
		fprintf(stderr, "ERROR: Can't apply BPF filter \"%s\": %s\n\n", filtro, pcap_geterr(sniff));
		return 2;
	}

	// Todo Bien
	fprintf(stderr, "OK, sniffing interface '%s' on port '%s'\n", dev, port);
	if (strlen(filtro) > 0) fprintf(stderr, "BPF filter: \"%s\"\n", filtrofinal);
	if (strlen(metodo) > 0) fprintf(stderr, "Only packets with SIP method: %s\n", metodo);
	if (strlen(respuesta) > 0) fprintf(stderr, "Only Packets with SIP response: %s\n", respuesta);
	if (strlen(regexp) > 0) {
		fprintf(stderr, "Only packets matching regular expression: /%s/", regexp);
		if (strlen(cabecera) > 0) fprintf(stderr, " in header field: %s\n", cabecera);
		else fprintf(stderr, "\n");
	}
	if (seguir) {
		fprintf(stderr, "Follow first packet with related packets by Call-ID.\n");
	}

	// Captura y parsea
	int res = pcap_loop(sniff, 0, obten_paquete_SIP, NULL);

	pcap_freecode(&fp);
	pcap_close(sniff);

	if (res > 0) {
		fprintf(stderr, "%d packets captured\n%d packets shown\n\n", res, mostrados);
	}
	return (res >= 0)?0:2;
}

