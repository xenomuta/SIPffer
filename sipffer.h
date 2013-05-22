/*
 *    SIPffer: Un sniffer del protocolo SIP
 *    version: 0.4
 *    XenoMuta / Methylxantina 256mg xenmuta[arroba]gmail.com http://xenomuta.com/
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
#define DEBUG 1

#define MAX_SIMULT 2048

#define ETH_LEN    14
#define IP_MIN_LEN 20
#define SNAP_LEN   65535

// Estructura de la cabezera IP
struct iphdr {
  u_char  ihl:4,        
  version:4;           
  u_char  tos;        
  short   tot_len;      
  u_short id;           
  short   off;          
  u_char  ttl;         
  u_char  protocol;    
  u_short check;       
  struct  in_addr saddr;
  struct  in_addr daddr; 
};

