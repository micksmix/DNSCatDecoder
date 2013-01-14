#!/usr/bin/env python
#
# dnscatdecoder.py
# v0.1
#
# Jan 14, 2013
#
# entirely based off of this script:
#     http://diablohorn.wordpress.com/2010/12/05/dnscat-traffic-post-dissector/
#
# author: Mick Grove
# http://micksmix.wordpress.com
#
#

import sys
import os
import re
import operator
import binascii
import dpkt


def decodeErr(data):
    ERR_SUCCESS = 0x00000000
    ERR_BUSY = 0x00000001
    ERR_INVSTATE = 0x00000002
    ERR_FIN = 0x00000003
    ERR_BADSEQ = 0x00000004
    ERR_NOTIMPLEMENTED = 0x00000005
    ERR_TEST = 0xFFFFFFFF

    if data == ERR_SUCCESS:
        errcode = "success"
    elif data == ERR_BUSY:
        errcode = "busy"
    elif data == ERR_INVSTATE:
        errcode = "invalidstate"
    elif data == ERR_FIN:
        errcode = "confin"
    elif data == ERR_BADSEQ:
        errcode = "badseqnum"
    elif data == ERR_NOTIMPLEMENTED:
        errcode = "not_implemented"
    elif data == ERR_TEST:
        errcode = "contest"

    return errcode

def decodeHex(data):
    data = data.upper()
    k = len(data)
    l = []
    for i in range(0, k, 2):
        try:
            l.append(binascii.unhexlify(data[i] + data[i+1]))
        except:
            pass

    return ''.join(l)

def decodeNetBios(data):
    data = data.upper()
    k = len(data)
    l = []
    for i in range(0, k, 2):
        try:
            l.append(chr(((ord(data[i]) - 0x41) << 4) |
                         ((ord(data[i+1]) - 0x41) & 0xf)))
        except:
            pass

    return ''.join(l)

def decodeFlags(data, fp):
    #-- protocol flags
    FLAG_STREAM = 0x00000001
    #-- deprecated
    FLAG_SYN = 0x00000002
    FLAG_ACK = 0x00000004
    #-- end of deprecated
    FLAG_RST = 0x00000008
    FLAG_HEX = 0x00000010
    FLAG_SESSION = 0x00000020
    FLAG_IDENTIFIER = 0x00000040

    blah = int(data,16)

    if operator.and_(blah, FLAG_STREAM) is not 0 :
        fp['stream'] = ""

    if operator.and_(blah, FLAG_SYN) is not 0 :
        fp['syn'] = ""

    if operator.and_(blah, FLAG_ACK) is not 0 :
        fp['ack'] = ""

    if operator.and_(blah, FLAG_RST) is not 0 :
        fp['rst'] = ""

    if operator.and_(blah, FLAG_HEX) is not 0 :
        fp['hex'] = ""

    if operator.and_(blah, FLAG_SESSION) is not 0 :
        fp['session'] = ""

    if operator.and_(blah, FLAG_IDENTIFIER) is not 0 :
        fp['identifier'] = ""


def getSubs(data):
    result = re.findall("(?im)[^%.]+", data)
    return result # = list

def main(data, fp):
    x = getSubs(data)
    x.pop(len(x)-1)
    fp['signature'] = x[0]
    x.pop(0)

    decodeFlags(x[0],fp)
    x.pop(0)

    if "identifier" in fp:
        fp['identifier'] = x[0]
        x.pop(0)

    if "session" in fp:
        fp['session'] = x[0]
        x.pop(0)

    if "stream" in fp:
        fp['seqnum'] = x[0]
        x.pop(0)

    if "rst" in fp:
        fp['err'] = decodeErr(x[0])
        x.pop(0)
        fp['garbage'] = x[0]
        fp['domain'] = x[1]
    else:
        fp['count'] = x[0]
        x.pop(0)

        fp['garbage'] = x[len(x)-1]
        fp['domain'] = x[len(x)-2]
        x.pop(len(x)-1)
        x.pop(len(x)-1)

        fp['asciidata'] = ""

        while len(x) > 0:
            if "hex" in fp:
                fp['asciidata'] = fp['asciidata'] + decodeHex(x[0])
            else:
                fp['asciidata'] = fp['asciidata'] + decodeNetBios(x[0])

            x.pop(0)

def parsePcapFile(pcap):
    fp ={}
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            #skip the frame if it doesn't contain IPv4 traffic
            if eth.type != 2048:
                continue

            ip = eth.data
             #let's only deal with udp
            if ip.p != 17:
                continue

            udp = ip.data
            #
            if udp.dport != 53:
                continue

            dns = dpkt.dns.DNS(udp.data)
            if len(dns.qd[0].name) < 1 :
                continue

            if dns.qd[0].type == 5:
                print "original line: %s\n" % dns.qd[0].name
                main(dns.qd[0].name, fp)
                print fp['asciidata']
                print("---")
                print("")
                fp.clear()

        except:
            pass

if __name__ == '__main__':
    if not os.path.exists(sys.argv[1]):
        sys.exit('ERROR: Pcap file <%s> was not found!' % sys.argv[1])

    inputfile = str(sys.argv[1])


    f = open(inputfile, "rb")
    pcap = dpkt.pcap.Reader(f)
    parsePcapFile(pcap)

