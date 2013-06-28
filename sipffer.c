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
#define VERSION "0.4.2"

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
/* Archivo pcap salida */
static char archivoO[128];
/* Cadena de Busqueda */
static char cadena[2048];
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

/*
 * me_Quite(): Funcion que captura senales UNIX y limpia todo antes de salir
 *
 * Parametros:
 * - sig:  Senal capturada por el Sistema.
 */
void me_Quite(int sig) {
	fprintf(stderr, "\x1b[0;37m\n-=[ CORTE! ]=-\n\n");
	pcap_breakloop(sniff);
	pcap_freecode(&fp);
	pcap_close(sniff);

	fprintf(stderr, "%d paquetes capturados\n%d paquetes mostrados\n\n", capturados, mostrados);
	_exit(0);
}


/*
 * manga_hora(): Retorna la fecha-hora del paquete capturado en formato
 * Y-m-d hh:mm:ss
 *
 * Parametros:
 * - cabeza:  Cabezera del paquete capturado.
 */
char *manga_hora(struct timeval cap_tv) {
	char *buff;
	time_t curtime;    // Hora actual en milisegundos

	if (!cap_tv.tv_sec) return "n/a";
	curtime=cap_tv.tv_sec;

	buff = (char *)malloc(30); memset(buff, 0, 30);
	strftime(buff, 30, "%Y-%m-%d %T", localtime(&curtime));
	return buff;
}


/*
 * manga_cabecera_SIP(): Retorna el valor de un cabecera x en un paquete SIP
 *
 * Parametros:
 * - paquete:  paquete crudo
 * - cabecera:    el cabeceradeseado
 *
 */
char *manga_cabecera_SIP(const u_char *paquete, char *quiero_cabecera) {
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
 * manga_paquete_SIP(): Extrae la data SIP del paquete
 *
 * Parametros:
 * - data: Datos pasados a la funcion por parte de pcap_loop()
 * - h:    Cabezera del paquete capturado
 * - p:    Data serializada del paquete
 */
void manga_paquete_SIP(u_cxhar *data, const struct pcap_pkthdr *h, const u_char *p) {
	struct iphdr *cip;			// La IP capturada
	const u_char *paquete;	// La data decapitada del paquete capturado
	unsigned int caplen;

	capturados++;
	// La interfaz any tiene 2 bytes adicionales en su header
	if (!strcmp(dev, "any")) p+=2;

	cip = (struct iphdr *)(p+ETH_LEN);
	// Ignora el paquete si no capturo bien o si esta recortado o si no es IPV4
	if ((!p) || (h->len <= (ETH_LEN+IP_MIN_LEN)) || ((unsigned char)cip->version != 4)) {
		if (DEBUG) fprintf(stderr, "Paquete Inválido\n");
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
		if (strlen(cadena) > 0) {
			if (!strstr((char *)paquete, (char *)&cadena)) return;
			if ((strlen(cabecera) > 0) && !strstr(manga_cabecera_SIP(paquete, cabecera), cadena)) return;
		}
		if (seguir) {
			if (seguir == 1) {
				if (!(seguir_id = manga_cabecera_SIP(paquete, "Call-ID"))) {
					seguir_id = manga_cabecera_SIP(paquete, "call-id");
				}
				if (seguir_id) {
					seguir = 2;
				} else return;
			}
			if (seguir == 2) {
				char *call_id = manga_cabecera_SIP(paquete, "Call-ID");
				if (!call_id)	call_id = manga_cabecera_SIP(paquete, "call-id");
				if (!call_id)	return;
				if (strcmp(call_id, seguir_id)) return;
			}
		}

		mostrados++;
		u_char *srcip = (u_char *)&cip->saddr;
		u_char *dstip = (u_char *)&cip->daddr;

		printf("\x1b[1;32m<==[%d bytes]==[%s] : %d.%d.%d.%d => ", caplen, manga_hora(h->ts), srcip[0], srcip[1], srcip[2], srcip[3]);
		printf("%d.%d.%d.%d ====\n\x1b[1;37m%s\n\x1b[1;32m=================>\n\n\x1b[0;37m", dstip[0], dstip[1], dstip[2], dstip[3], paquete);
	}
}


/*
 * payola(): El nombre lo dice todo
 */
void payola() {
	fprintf(stderr, "SIPffer v%s: Un sniffer para el protocolo SIP\nXenoMuta.com - https://github.com/xenomuta/SIPffer\n\n", VERSION, 64);
}

/*
 * usage(): El nombre lo dice todo
 */
void usage() {
	fprintf(stderr, "Uso: sipffer [OPCIONES] -i interfaz [cadena a buscar]\n");
	fprintf(stderr, "  o: sipffer [OPCIONES] -a archivo [cadena a buscar]\n\n");
	fprintf(stderr, " -i interfaz:    \tInterfaz Ethernet a sniffear\n");
	fprintf(stderr, " -a archivo:     \tArchivo de captura pcap a analizar\n\n");
	fprintf(stderr, "OPCIONES:\n");
	fprintf(stderr, " -p puerto:      \tPuerto a filtrar ( 5060 por defecto )\n");
	fprintf(stderr, " -f filtro bpf:  \tFiltro BPF adicional ( formato tcpdump )\n");
	fprintf(stderr, " -m metodo:      \tFiltra por metodo SIP (INVITE,REGISTER,\n");
	fprintf(stderr, "                 \t\tACK,CANCEL,BYE o OPTIONS)\n");
	fprintf(stderr, " -r respuesta:   \tFiltra por respuesta (numerica) (200, 404, etc...)\n");
	// /* Pronto ;) , estoy muy bago */
	// fprintf(stderr, " -e archivo:     \tEscribe captura de paquetes a archivo\n");
	fprintf(stderr, " -s:             \tCapturar y perseguir paquetes relacionados\n");
	fprintf(stderr, " -c cabecera     \tBuscar la cadena unicamente en la cabecera especificada\n");
	fprintf(stderr, "                 \t\tej. (From, To, Contact, etc...)\n");
	fprintf(stderr, " -h              \tMuestra esta pantalla de ayuda\n\n\n");
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
	memset((char *)&archivoO, 0, sizeof(archivoO));
	memset((char *)&metodo, 0, sizeof(metodo));
	memset((char *)&respuesta, 0, sizeof(respuesta));
	memset((char *)&cadena, 0, sizeof(cadena));
	memset((char *)&cabecera, 0, sizeof(cabecera));
	memset((char *)&filtro, 0, sizeof(filtro));
	seguir = 0;
	/* Snifea en todas por default */
	strncpy((char *)&dev, "any", sizeof(dev));

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			strncpy((char *)&cadena, argv[i], sizeof(cadena));
			continue;
		} else if ((argv[i][0] == '-') && strcmp(argv[i], "-s") && (i + 1 == argc)) {
			usage();
			return 2;
		}
		if (!strcmp(argv[i], "-h")) {
			usage();
			return 0;
		}
		if (!strcmp(argv[i], "-s")) {
			seguir = 1;
			continue;
		}
		if (!strcmp(argv[i], "-a")) {
			strncpy((char *)&archivo, argv[++i], sizeof(archivo));
			continue;
		}
		if (!strcmp(argv[i], "-e")) {
			strncpy((char *)&archivoO, argv[++i], sizeof(archivoO));
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

	if ((strlen(cabecera) > 0) && (strlen(cadena) == 0)) {
		fprintf(stderr, "ERROR: Si usa la opcion -c, debe especificar la cadena a buscar\n\n");
		return 2;
	}

	// Fabrica el filtro
	char filtrofinal[2048];
	memset(filtrofinal, 0, 2048);

	snprintf((char *)&filtrofinal, sizeof(filtrofinal), "udp and port %s", port);
	if (strlen(filtro) > 0) {
		snprintf((char *)&filtrofinal, sizeof(filtrofinal), " and %s", filtro);
	}

	// Preparate las trampas de senal
	signal(SIGABRT, &me_Quite);
	signal(SIGTERM, &me_Quite);
	signal(SIGSTOP, &me_Quite);
	signal(SIGKILL, &me_Quite);
	signal(SIGINT, &me_Quite);

	if (strlen(archivo) > 0) {
		if ((sniff = pcap_open_offline(archivo, errbuf))==NULL) {
			fprintf(stderr, "ERROR: No pudo abrir el archivo %s: %s\n\n", dev, errbuf);
			return 2;
		}
	} else {
		if ((sniff = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf))==NULL) {
			fprintf(stderr, "ERROR: No pudo abrir el dispositivo %s: %s\n\n", dev, errbuf);
			return 2;
		}
		if (!strcmp(dev, "any")) {
			if ((pcap_set_datalink(sniff, DLT_LINUX_SLL))==-1) {
				fprintf(stderr, "ERROR: No pudo asignar el tipo de link a DTL_LINUX_SLL\n\n");
				return 2;
			}
		}
		// Averigua nuestra IP/Mascara
		if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
			fprintf(stderr, "ERROR: No se pudo averiguar la IP/Mascara de %s\n\n", dev);
			mask = 0;
			ip = 0;
		}
	}

	// Compila el filtro
	if (pcap_compile(sniff, &fp, filtrofinal, 1, mask) == -1) {
		fprintf(stderr, "ERROR: No se pudo parsear el fitro \"%s\": %s\n\n", filtro, pcap_geterr(sniff));
		return 2;
	}

	// Aplica el filtro a la captura
	if (pcap_setfilter(sniff, &fp) == -1) {
		fprintf(stderr, "ERROR: No se pudo aplicar el filtro \"%s\": %s\n\n", filtro, pcap_geterr(sniff));
		return 2;
	}

	// Todo Bien
	fprintf(stderr, "OK, escuchando en la interfaz %s puerto %s\n", dev, port);
	if (strlen(filtro) > 0) fprintf(stderr, "Filtrado BPF: \"%s\"\n", filtro);
	if (strlen(metodo) > 0) fprintf(stderr, "Paquetes con el metodo SIP: %s\n", metodo);
	if (strlen(respuesta) > 0) fprintf(stderr, "Paquetes con la respuesta SIP: %s\n", respuesta);
	if (strlen(cadena) > 0) {
		fprintf(stderr, "Solo paquetes con la cadena: \"%s\"", cadena);
		if (strlen(cabecera) > 0) fprintf(stderr, " en la cabecera: %s\n", cabecera);
		else fprintf(stderr, "\n");
	}
	if (seguir) {
		fprintf(stderr, "Perseguir paquetes relacionados por Call-ID al primer paquete capturado\n");
	}

	// Captura y parsea
	int res = pcap_loop(sniff, 0, manga_paquete_SIP, NULL);

	pcap_freecode(&fp);
	pcap_close(sniff);

	if (res > 0) {
		fprintf(stderr, "%d paquetes capturados\n%d paquetes mostrados\n\n", res, mostrados);
	}
	return (res >= 0)?0:2;
}

