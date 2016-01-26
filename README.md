# SIPffer
**SIPffer** (SIP + sniffer): A SIP protocol sniffer for quick and smart troubleshooting.

### What's SIPffer

SIPffer is an easy to use command line tool for troubleshooting issues with SIP traffic (switches, proxies, SBCs, VoIP Servers, PBXs, etc..).
It comes very handy in high traffic and other noisy environments to do quick and smart diagnostics on remote ends, compared to otherwise heavier and harder to run or install WireShark or other all-purpose traffic analysis tools.

It is distributed under the GPLv3 license.

### Features

* Filter SIP packets matching Regular Expression.
* Custom BPF Filters.
* SIP session tracking (option `-s` or `--follow`).
* Offline analysis of tcpdump (`.pcap`) capture files.
* Filter by SIP method (`REGISTER`, `INVITE`, `OPTIONS`, `BYE`, etc).
* Filter by SIP response (`200`, `302`, `404`, etc).

### Installing

```sh
git clone https://github.com/xenomuta/SIPffer
cd SIPffer
make
sudo make install
```

**NOTE**: _SIPffer depends on `libpcap` (>= 0.8) and `libpcre` to compile._

### Acknowledgment

* The word of God, Jesus: the first and best coder in the universe.
* The Digium / Asterisk community, which inspired the creation of this tool ( with its `sip set debug` feature in `chan_sip.c` ).
* Nathan Robles, my most notorious beta-tester... ;-)
* Juan Ases Garcia, for his excelent suggestions & feedback.
* The [Starvox](http://starvox.com) team and user base.

