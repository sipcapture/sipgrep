SipGrep 2
=======

# Description:
  Sipgrep is a powerful command line tool to sniff, capture, display and troubleshoot SIP signaling over IP networks.
  
  The first version of this programm (2005) was a small wrapper for ngrep. Version 2.x provides a full standalone application, building upon the excellent ngrep code baseline.


# Usage:

```
./sipgrep  -V

sipgrep: V2.00, $Revision: 2.00 $

./sipgrep -h

usage: sipgrep <-ahNViwgGJpevxlDTRMmqCJ> <-IO pcap_dump> <-n num> <-d dev> <-A num>
             <-s snaplen> <-S limitlen> <-c contact user>
		 <-f from user>  <-t to user> <-H capture url> <-q seconds>
             <-P portrange> <-F file> <match expression> <bpf filter>
   -h  is help/usage
   -V  is version information
   -e  is show empty packets
   -i  is ignore case
   -v  is invert match
   -R  is don't do privilege revocation logic
   -w  is word-regex (expression must match as a word)
   -p  is don't go into promiscuous mode
   -l  is make stdout line buffered
   -D  is replay pcap_dumps with their recorded time intervals
   -T  is print delta timestamp every time a packet is matched
   -m  is don't do dialog match
   -M  is don't do multi-line match (do single-line match instead)
   -I  is read packet stream from pcap format file pcap_dump
   -O  is dump matched packets in pcap format to pcap_dump
   -n  is look at only num packets
   -A  is dump num packets after a match
   -s  is set the bpf caplen
   -S  is set the limitlen on matched packets
   -C  is no colors in stdout
   -c  is search user in Contact: header
   -f  is search user in From: header
   -t  is search user in To: header
   -F  is read the bpf filter from the specified file
   -H  is homer sipcapture URL (i.e. udp:10.0.0.1:9061)
   -N  is show sub protocol number
   -g  is disabled clean up dialogs during trace
   -G  is print dialog report during clean up
   -J  is kill friendly scanner automatically
   -q  is close sipgrep after some time
   -a  is enable reasembling
   -P  is use specified portrange instead of default 5060-5061
   -d  is use specified device instead of the pcap default


```

# Examples:

```
#Find a dialog there From user contains '2323232'
sipgrep -f 2323232

#Find a dialog there To user contains '1111' and print dialog report
sipgrep -f 1111 -G

#Display only 603 replies without dialog match
sipgrep '^SIP/2.0 603' -m

#Display only OPTIONS and NOTIFY requests
sipgrep '^(OPTIONS|NOTIFY)'

#Display only SUBSCRIBE dialog
sipgrep 'CSeq:\s?\d* (SUBSCRIBE|PUBLISH|NOTIFY)' -M

#Kill friendly-scanner
sipgrep -J

#Display dialogs and duplicate all traffic to HOMER sipcapture in HEPv3
sipgrep -f 23333 -H udp:10.0.0.1:9061

#collect all Calls/Regisrations dialogs during 120 seconds, print reports and exit.
sipgrep -g -G -q 120


```



## Reports

```
-----------------------------------------------
Dialog finished: [53342c3b200e-hgf9cyc7r0i2]
Type: Call
From: "From Work with Love" <sip:107@sip.xxx.com>;tag=fucueumi19
To: <sip:101@sip.xxx.com;user=phone>
UAC: snom360/8.7.3.25
CDR init ts: 1395928127
CDR ringing ts: 1395928128
SRD(PDD): 1 sec
CDR answer ts: 1395928136
WTA: 9 sec
CDT (duration): 70 sec
CDR termination ts: 1395928206
Was connected: YES
REASON: BYE
-----------------------------------------------

-----------------------------------------------
Dialog finished: [552E1549D6A9E0F3@192.168.178.1]
Type: Registration
From: <sip:102@sip.xxx.com>;tag=3598882807
To: <sip:102@sip.xxxx.com>
UAC: AVM FRITZ!Box Fon WLAN 7170 Annex A 58.04.67 (Dec 18 2008)
CDR init ts: 1395928251
CDR termination ts: 1395928251
SDT: 0 sec
Was registered: YES
REASON: 200
-----------------------------------------------

-----------------------------------------------
Dialog finished: [2d714880c68a824dae62049eecc91599]
Type: Call
From: 7001<sip:7001@xxxxxxx>;tag=1244ddd6
To: 448455915802<sip:448455915802@xxxxxxx>
UAC: sipcli/v1.8
CDR init ts: 1395928246
SDT: 8 sec
CDR termination ts: 1395928254
Was connected: NO
REASON: 407
-----------------------------------------------

```

## Colored SIP:

![Screenshot](https://cloud.githubusercontent.com/assets/4513061/2536095/2ca6e1f8-b599-11e3-9451-708b7c614f5f.png)


## License

Copyright (c) 2014 Alexandr Dubovikov

See the [COPYING](COPYING) for details.
