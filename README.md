# SIPffer
 **SIPffer** (_SIP + sniffer_): A SIP protocol sniffer for quick and smart troubleshooting.

 *XenoMuta <xenomuta@gmail.com> - Metylxantina 256mg 2013 - <http://xenomuta.com/>*

### What's SIPffer

SIPffer is an easy to use tool for troubleshooting issues with SIP traffice (switches, proxies, SBCs, VoIP Servers, PBXs, etc..).
It comes very handy in high traffic environments to do quick and smart diagnostic on remote ends, terminals or otherwise  hard to install WireShark or other heavy all-purpose traffic analysis tools.

It is distributed under the GPLv3 license.

### Features

* Filter SIP packets matching Regular Expression.
* Custom BPF Filters.
* SIP session tracking (option `-s` or `--follow`).
* Offline analysis of tcpdump (`.pcap`) capture files.
* Filter by SIP method (`REGISTER`, `INVITE`, `OPTIONS`, `BYE`, etc).
* Filter by SIP response (`200`, `404`, `503`, etc).
* Offline analysis of tcpdump (`.pcap`) capture files.

### Installing

```sh
git clone https://github.com/xenomuta/SIPffer
cd SIPffer
make
sudo make install
```

_**NOTE**: SIPffer depends on `libpcap` (>= 0.8) and `libpcre` to compile_.

### Acknowledgment

* The word of God, Jesus: the first and best coder in the universe.
* The Digium / Asterisk community, which inspired the creation of this tool ( with its `sip set debug` feature in `chan_sip.c` ).
* Nathan Robles, my most notorious beta-tester... ;-)
* Juan Ases Garcia, for his excelent suggestions & feedback.

