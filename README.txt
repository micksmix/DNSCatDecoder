Parser/dissector/decoder for DNSCat captured traffic

This is a Python port of Diablo Horn's LUA script that accomplishes the
same task. Have a look at their script as well:
http://diablohorn.wordpress.com/2010/12/05/dnscat-traffic-post-dissector/

How to use
===========
This requires dpkt --- https://code.google.com/p/dpkt/

Provide a pcap file as input:
python ./dnscatdecoder.py dnscat_captured_traffic.pcap

Author: Mick Grove
License: The BSD 2-Clause License (http://opensource.org/licenses/bsd-license.php)

DNSCat can be dowloaded here: http://www.skullsecurity.org/wiki/index.php/Dnscat