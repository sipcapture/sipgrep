sipgrep
=======

sipgrep

```
./sipgrep  -V

sipgrep: V2.00, $Revision: 2.00 $

./sipgrep -h

usage: sipgrep <-hNViwgGJpevxlDTRMmCJ> <-IO pcap_dump> <-n num> <-d dev> <-A num>
             <-s snaplen> <-S limitlen> <-c contact user>
		 <-f from user>  <-t to user> <-H capture url>
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
   -P  is use specified portrange instead of default 5060-5061
   -d  is use specified device instead of the pcap default

```


## Report

```
-----------------------------------------------
Dialog finished: [5333f1ffd238-71xi4jk51vfn]
Type: Call
From: "From Work with Love" <sip:107@sip.xxx.com>;tag=i61qxsf4jf
To: <sip:5000@sip.xxx.com;user=phone>
UAC: snom360/8.7.3.25
Init time: 1395913216
Connected time: 1395913216
Ringing delta: 0 sec
Connect delta: 0 sec
Call duration: 9 sec
Disconnected time: 1395913225
Was connected: YES
REASON: BYE
-----------------------------------------------

-----------------------------------------------
Dialog finished: [7763c89ac17a934882cb9025251e8605@192.168.233.87]
Type: Registration
From: "140" <sip:140@sip.xxx.com>;tag=1326110477
To: "140" <sip:140@sip.xxx.com>
UAC: SIPAUA/0.1.001
Init time: 1395913223
200 OK time: 1395913223
Registration transaction duration: 0 sec
Was registered: YES
REASON: 200
-----------------------------------------------
```

## Colored SIP:

![Screenshot](https://cloud.githubusercontent.com/assets/4513061/2536095/2ca6e1f8-b599-11e3-9451-708b7c614f5f.png)


## License

Copyright (c) 2014 Alexandr Dubovikov

See the [COPYING](COPYING) for details.
