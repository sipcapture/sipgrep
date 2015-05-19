/*
 *  sipgrep - Monitoring tools
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2014-15 (http://www.sipcapture.org)
 *
 * Sipgrep is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Sipgrep is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * base on NGREP of:
 *
 * Copyright (c) 2006  Jordan Ritter <jpr5@darkridge.com>
 *
 */

#if defined(BSD) || defined(SOLARIS) || defined(MACOSX)
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/tty.h>
#include <pwd.h>
#endif

#if defined(OSF1)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <sys/mbuf.h>
#include <arpa/inet.h>
#include <unistd>
#include <pwd.h>
#endif

#if defined(LINUX)
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#endif

#if defined(AIX)
#include <sys/machine.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#endif


#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <sys/ioctl.h>

#include <pcap.h>

#include <netdb.h>

/* reasambling */
#include "ipreasm.h"

#include "tcpreasm.h"

/* hash table */
#include "uthash.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if USE_IPv6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include <pcre.h>
#include "core_hep.h"
#include "sipgrep.h"
#include "sipparse.h"


/*
 * Configuration Options
 */

uint16_t snaplen = 65535, limitlen = 65535, promisc = 1, to = 100;
uint16_t match_after = 0, keep_matching = 0, matches = 0, max_matches = 0;

uint16_t stats_interval = 300;
uint32_t last_stats_dump = 0;

uint8_t debug = 0;

uint8_t re_match_word = 0, re_ignore_case = 0, re_multiline_match = 1;
uint8_t show_empty = 0, show_proto = 0, quiet = 1;
uint8_t invert_match = 0;
uint8_t live_read = 1, want_delay = 0;
uint8_t dont_dropprivs = 0, ignore_bad_sip = 0;

char *read_file = NULL, *dump_file = NULL;
char *usedev = NULL;

char nonprint_char = '.';

struct callid_table *dialogs = NULL;
struct callid_remove *dialogs_remove = NULL;
struct statistics_table *statstable = NULL;
/*
 * GNU PCRE
 */

int32_t err_offset;
char *re_err = NULL;

pcre *pattern = NULL;
pcre_extra *pattern_extra = NULL;

/*
 * Matching
 */

char *match_data = NULL, *bin_data = NULL;
uint16_t match_len = 0;
int8_t (*match_func) () = &blank_match_func;

int8_t dump_single = 0;
void (*dump_func) (unsigned char *, uint32_t) = &dump_byline;

/*
 * BPF/Network
 */

char *filter = NULL, *filter_file = NULL, *portrange = "5060-5061";
char pc_err[PCAP_ERRBUF_SIZE];
uint8_t link_offset;
uint8_t radiotap_present = 0;

pcap_t *pd = NULL;
pcap_dumper_t *pd_dump = NULL;
struct bpf_program pcapfilter;
struct in_addr net, mask;
int file_counter = 0;
/*
 * Timestamp/delay functionality
 */

struct timeval prev_ts = { 0, 0 }, prev_delay_ts = {
0, 0};

void (*print_time) () = NULL, (*dump_delay) () = dump_delay_proc_init;

uint32_t ws_row, ws_col = 80, ws_col_forced = 0;

/* ip reasm */
int8_t reasm_enable = 1;
struct reasm_ip *reasm = NULL;
int16_t stats_duration = 0;
int8_t stats_enable = 0;

int8_t tcpdefrag_enable = 1;
struct tcpreasm_ip *tcpreasm = NULL;

char *sip_from_filter = NULL, *sip_to_filter = NULL, *sip_contact_filter = NULL;
char *custom_filter = NULL, *homer_capture_url = NULL;

/* default dialog match */
uint8_t dialog_match = 1;

uint8_t use_color = 1, enable_dialog_remove = 1, print_report = 0, kill_friendlyscanner = 0;

/* homer socket */
int homer_sock = 0, use_homer = 0;

/* kill time */
unsigned int stop_working_value = 0, write_deadline = 0, stop_working_type = 0, split_file_value = 0, split_file_type = 0;

/* time to remove */
unsigned int time_dialog_remove = 0;

/* start time */
unsigned int start_time = 0;

/* default friendly scanner UAC */
char *friendly_scanner_uac = "friendly-scanner";
char *friendly_scanner_range;



int
main (int argc, char **argv)
{
  int32_t c;

  signal (SIGINT, clean_exit);
  signal (SIGABRT, clean_exit);

  /* default timestamp */
  print_time = &print_time_absolute;
  
  start_time = (unsigned) time (NULL);

  while ((c = getopt (argc, argv, "axNhCXViwmpevlDTRMGJgs:n:c:q:H:d:A:I:O:S:F:P:f:t:j:K:Q:z:"))
	 != EOF) {
    switch (c) {

    case 'x':
      ignore_bad_sip = 1;
      break;
    case 'F':
      filter_file = optarg;
      break;
    case 'S':
      limitlen = atoi (optarg);
      break;
    case 'z':
      quiet = 5;
      last_stats_dump = start_time;
      stats_duration = atoi (optarg);
      stats_enable = 1;      
      break;
    case 'a':
      reasm_enable = 0;
      tcpdefrag_enable = 0;
      break;
    case 'q':
      if (parse_stop_request (optarg) != 0) {
	usage (-1);
	exit (1);
      }
      break;
    case 'Q':
      if (parse_split_request (optarg) != 0) {
	usage (-1);
	exit (1);
      }
      /* we should keep our priv. to rotate files */
      dont_dropprivs = 1;
      break;
    case 'J':
      kill_friendlyscanner = 1;
      break;
    case 'K':
      friendly_scanner_range = optarg;
      kill_friendlyscanner = 2;
      break;
    case 'j':
      friendly_scanner_uac = optarg;
      kill_friendlyscanner = 1;
      break;
    case 'g':
      enable_dialog_remove = 0;
      break;
    case 'G':
      print_report = 1;
      break;
    case 'O':
      dump_file = optarg;
      break;
    case 'P':
      portrange = optarg;
      break;
    case 'I':
      read_file = optarg;
      break;
    case 'A':
      match_after = atoi (optarg) + 1;
      break;
    case 'd':
      usedev = optarg;
      break;
    case 't':
      sip_to_filter = optarg;
      re_multiline_match = 0;
      break;
    case 'f':
      sip_from_filter = optarg;
      re_multiline_match = 0;
      break;
    case 'c':
      sip_contact_filter = optarg;
      re_multiline_match = 0;
      break;
    case 'H':
      homer_capture_url = optarg;
      use_homer = 1;
      break;
    case 'n':
      max_matches = atoi (optarg);
      break;
    case 'm':
      dialog_match = 0;
      break;
    case 'C':
      use_color = 0;
      break;
    case 's':
      {
	uint16_t value = atoi (optarg);
	if (value > 0)
	  snaplen = value;
      }
      break;
    case 'M':
      re_multiline_match = 0;
      break;
    case 'R':
      dont_dropprivs = 1;
      break;
    case 'T':
      print_time = &print_time_diff;
      gettimeofday (&prev_ts, NULL);
      break;
    case 'D':
      want_delay = 1;
      break;
    case 'l':
      setvbuf (stdout, NULL, _IOLBF, 0);
      break;
    case 'v':
      invert_match++;
      break;
    case 'e':
      show_empty++;
      break;
    case 'p':
      promisc = 0;
      break;
    case 'w':
      re_match_word++;
      break;
    case 'i':
      re_ignore_case++;
      break;
    case 'V':
      version ();
      break;
    case 'N':
      show_proto++;
      break;
    case 'h':
      usage (0);
      break;
    default:
      usage (-1);
    }
  }





  /* make kill range */
  if (kill_friendlyscanner == 2) {
    mass_friendlyscanner_kill (friendly_scanner_range);
    clean_exit (-1);
  }

  /* missed -O flag for -q filessize or SPLIT FILE types */
  if ((stop_working_type == FILESIZE_SPLIT || split_file_type != 0)
      && !dump_file) {
    fprintf (stderr, "-O parameter missed\n");
    usage (-1);
    exit (1);
  }

  if (use_homer) {

    if (!homer_capture_url || make_homer_socket (homer_capture_url)) {
      fprintf (stderr, "bad homer url\n");
      usage (-1);
      exit (1);
    }
  }

  if (argv[optind])
    match_data = argv[optind++];

  if (read_file) {

    if (!(pd = pcap_open_offline (read_file, pc_err))) {
      perror (pc_err);
      clean_exit (-1);
    }

    live_read = 0;
    printf ("input: %s\n", read_file);

  }
  else {

    char *dev = usedev ? usedev : pcap_lookupdev (pc_err);

    if (!dev) {
      perror (pc_err);
      clean_exit (-1);
    }

    if ((pd = pcap_open_live (dev, snaplen, promisc, to, pc_err)) == NULL) {
      perror (pc_err);
      clean_exit (-1);
    }

    if (pcap_lookupnet (dev, &net.s_addr, &mask.s_addr, pc_err) == -1) {
      perror (pc_err);
      memset (&net, 0, sizeof (net));
      memset (&mask, 0, sizeof (mask));
    }

    if (quiet < 2) {
      printf ("interface: %s", dev);
      if (net.s_addr && mask.s_addr) {
	printf (" (%s/", inet_ntoa (net));
	printf ("%s)", inet_ntoa (mask));
      }
      printf ("\n");
    }
  }

  if (filter_file) {
    char buf[1024] = { 0 };
    FILE *f = fopen (filter_file, "r");

    if (!f || !fgets (buf, sizeof (buf) - 1, f)) {
      fprintf (stderr, "fatal: unable to get filter from %s: %s\n", filter_file, strerror (errno));
      usage (-1);
    }

    fclose (f);

    filter = get_filter_from_string (buf);

    if (pcap_compile (pd, &pcapfilter, filter, 0, mask.s_addr)) {
      pcap_perror (pd, "pcap compile");
      clean_exit (-1);
    }

  }
  else if (argv[optind]) {
    filter = get_filter_from_argv (&argv[optind]);

    if (pcap_compile (pd, &pcapfilter, filter, 0, mask.s_addr)) {
      free (filter);
      filter = get_filter_from_argv (&argv[optind - 1]);

      if (pcap_compile (pd, &pcapfilter, filter, 0, mask.s_addr)) {
	pcap_perror (pd, "pcap compile");
	clean_exit (-1);
      }
      else
	match_data = NULL;
    }

  }
  else {

    //char *default_filter = BPF_FILTER_IP;
    filter = get_filter_from_portrange (portrange);

    if (pcap_compile (pd, &pcapfilter, filter, 0, mask.s_addr)) {
      pcap_perror (pd, "pcap compile");
      clean_exit (-1);
    }
  }


  /* custom filter */

  if (sip_to_filter && sip_from_filter) {

    custom_filter = malloc (strlen (sip_to_filter) + strlen (sip_from_filter) + strlen (SIP_FROM_TO_MATCH));
    sprintf (custom_filter, SIP_FROM_TO_MATCH, sip_from_filter, sip_to_filter);
    match_data = custom_filter;
  }
  else if (sip_from_filter) {

    custom_filter = malloc (strlen (sip_from_filter) + strlen (SIP_FROM_MATCH));
    sprintf (custom_filter, SIP_FROM_MATCH, sip_from_filter);
    match_data = custom_filter;
  }
  else if (sip_to_filter) {

    custom_filter = malloc (strlen (sip_to_filter) + strlen (SIP_TO_MATCH));
    sprintf (custom_filter, SIP_TO_MATCH, sip_to_filter);
    match_data = custom_filter;
  }


  if (filter && quiet < 2)
    printf ("filter: %s\n", filter);

  if (pcap_setfilter (pd, &pcapfilter)) {
    pcap_perror (pd, "pcap set");
    clean_exit (-1);
  }

  if (match_data) {

    uint32_t pcre_options = PCRE_UNGREEDY;

    if (re_ignore_case)
      pcre_options |= PCRE_CASELESS;

    if (re_multiline_match)
      pcre_options |= PCRE_DOTALL;

    if (re_match_word) {
      char *word_regex = malloc (strlen (match_data) * 3 + strlen (WORD_REGEX));
      sprintf (word_regex, WORD_REGEX, match_data, match_data, match_data);
      match_data = word_regex;
    }

    pattern = pcre_compile (match_data, pcre_options, (const char **) &re_err, &err_offset, 0);

    if (!pattern) {
      fprintf (stderr, "compile failed: %s\n", re_err);
      clean_exit (-1);
    }

    pattern_extra = pcre_study (pattern, 0, (const char **) &re_err);

    match_func = &re_match_func;


    if (quiet < 2 && match_data && strlen (match_data))
      printf ("%smatch: %s%s\n", invert_match ? "don't " : "", (bin_data && !strchr (match_data, 'x')) ? "0x" : "", match_data);
  }

  if (filter)
    free (filter);
  if (re_match_word)
    free (match_data);
  if (custom_filter)
    free (custom_filter);

  switch (pcap_datalink (pd)) {
  case DLT_EN10MB:
    link_offset = ETHHDR_SIZE;
    break;

  case DLT_IEEE802:
    link_offset = TOKENRING_SIZE;
    break;

  case DLT_FDDI:
    link_offset = FDDIHDR_SIZE;
    break;

  case DLT_SLIP:
    link_offset = SLIPHDR_SIZE;
    break;

  case DLT_PPP:
    link_offset = PPPHDR_SIZE;
    break;

#if HAVE_DLT_LOOP
  case DLT_LOOP:
#endif
  case DLT_NULL:
    link_offset = LOOPHDR_SIZE;
    break;

#if HAVE_DLT_RAW
  case DLT_RAW:
    link_offset = RAWHDR_SIZE;
    break;
#endif

#if HAVE_DLT_LINUX_SLL
  case DLT_LINUX_SLL:
    link_offset = ISDNHDR_SIZE;
    break;
#endif

#if HAVE_DLT_IEEE802_11_RADIO
  case DLT_IEEE802_11_RADIO:
    radiotap_present = 1;
#endif

#if HAVE_DLT_IEEE802_11
  case DLT_IEEE802_11:
    link_offset = IEEE80211HDR_SIZE;
    break;
#endif

  default:
    fprintf (stderr, "fatal: unsupported interface type %u\n", pcap_datalink (pd));
    clean_exit (-1);
  }

  if (dump_file) {

    if (!(pd_dump = pcap_dump_open (pd, dump_file))) {
      fprintf (stderr, "fatal: %s\n", pcap_geterr (pd));
      clean_exit (-1);
    }
    else
      printf ("output: %s\n", dump_file);
  }

  update_windowsize (0);

#if USE_DROPPRIVS
  drop_privs ();
#endif

  if(stats_enable) 
        printf("starttime;stoptime;key;method;cseq;request;count\n");

  /* REASM */
  if (reasm_enable) {
    reasm = reasm_ip_new ();
    reasm_ip_set_timeout (reasm, 30000000);
  }
  
  /* TCP DEFR */
  if (tcpdefrag_enable) {
     tcpreasm = tcpreasm_ip_new ();
     tcpreasm_ip_set_timeout (tcpreasm, 30000000);
  }

  while (pcap_loop (pd, 0, (pcap_handler) process, 0));

  clean_exit (0);

  /* NOT REACHED */
  return 0;
}

void
create_dump (unsigned int now)
{

  struct tm *t;
  char file_ts[256];
  char *file_ext = NULL;
  unsigned int len = 0;

  if (!dump_file)
    return;

  if (check_split_deadline (now) == 0) {
    /* do close and create a new one */
    if (pd_dump) {
      pcap_dump_flush (pd_dump);
      pcap_dump_close (pd_dump);
    }
    else {
      fprintf (stderr, "fatal: file not opened\n");
      clean_exit (-1);
    }

    /* set counter */
    file_counter++;

    time_t epoch_time_as_time_t = write_deadline;

    t = localtime (&epoch_time_as_time_t);

    len = strlen (dump_file);

    if ((file_ext = strrchr (dump_file, '.'))) {
      if (file_ext == dump_file)
	file_ext = NULL;
      else
	len -= strlen (file_ext);
    }


    snprintf (file_ts, 256, "%.*s_%06d_%02u%02u%02u%02u%02u%02u%s",
	      len, dump_file, file_counter, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, file_ext ? file_ext : ".pcap");

    if ((len = rename (dump_file, file_ts)) != 0) {
      fprintf (stderr, "unable to rename the file '%s' to '%s' %d\n", dump_file, file_ts, len);
    }

    if (!(pd_dump = pcap_dump_open (pd, dump_file))) {
      fprintf (stderr, "fatal: %s\n", pcap_geterr (pd));
      clean_exit (-1);
    }
    else
      printf ("output: %s\n", dump_file);
  }
}

void
process (u_char * d, struct pcap_pkthdr *h, u_char * p)
{
  struct ip *ip4_pkt = (struct ip *) (p + link_offset);
#if USE_IPv6
  struct ip6_hdr *ip6_pkt = (struct ip6_hdr *) (p + link_offset);
#endif

  uint32_t ip_ver;
  uint8_t  psh = 0;

  uint8_t ip_proto = 0;
  uint32_t ip_hl = 0;
  uint32_t ip_off = 0;

  uint8_t fragmented = 0;
  uint16_t frag_offset = 0;
  uint32_t frag_id = 0;


  char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];

  unsigned char *data, *datatcp;
  uint32_t len = h->caplen;

#if HAVE_DLT_IEEE802_11_RADIO
  if (radiotap_present) {
    uint16_t radio_len = ((struct SIPGREP_rtaphdr_t *) (p))->it_len;
    ip4_pkt = (struct ip *) (p + link_offset + radio_len);
    len -= radio_len;
  }
#endif


  u_char *packet = NULL;
  if (reasm != NULL) {
    unsigned new_len;
    u_char *new_p = malloc (len - link_offset - ((ntohs ((uint16_t) * (p + 12)) == 0x8100) ? 4 : 0));
    memcpy (new_p, ip4_pkt, len - link_offset - ((ntohs ((uint16_t) * (p + 12)) == 0x8100) ? 4 : 0));
    packet =
      reasm_ip_next (reasm, new_p,
		     len - link_offset - ((ntohs ((uint16_t) * (p + 12)) == 0x8100) ? 4 : 0), (reasm_time_t) 1000000UL * h->ts.tv_sec + h->ts.tv_usec, &new_len);
    if (packet == NULL)
      return;
    len = new_len + link_offset + ((ntohs ((uint16_t) * (packet + 12)) == 0x8100) ? 4 : 0);
    h->len = new_len;
    h->caplen = new_len;

    ip4_pkt = (struct ip *) packet;
#if USE_IPv6
    ip6_pkt = (struct ip6_hdr *) packet;
#endif
  }


  ip_ver = ip4_pkt->ip_v;

  switch (ip_ver) {

  case 4:
    {
#if defined(AIX)
#undef ip_hl
      ip_hl = ip4_pkt->ip_ff.ip_fhl * 4;
#else
      ip_hl = ip4_pkt->ip_hl * 4;
#endif
      ip_proto = ip4_pkt->ip_p;
      ip_off = ntohs (ip4_pkt->ip_off);

      fragmented = ip_off & (IP_MF | IP_OFFMASK);
      frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
      frag_id = ntohs (ip4_pkt->ip_id);

      inet_ntop (AF_INET, (const void *) &ip4_pkt->ip_src, ip_src, sizeof (ip_src));
      inet_ntop (AF_INET, (const void *) &ip4_pkt->ip_dst, ip_dst, sizeof (ip_dst));
    }
    break;

#if USE_IPv6
  case 6:
    {
      ip_hl = sizeof (struct ip6_hdr);
      ip_proto = ip6_pkt->ip6_nxt;

      if (ip_proto == IPPROTO_FRAGMENT) {
	struct ip6_frag *ip6_fraghdr;

	ip6_fraghdr = (struct ip6_frag *) ((unsigned char *) (ip6_pkt) + ip_hl);
	ip_hl += sizeof (struct ip6_frag);
	ip_proto = ip6_fraghdr->ip6f_nxt;

	fragmented = 1;
	frag_offset = ntohs (ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
	frag_id = ntohl (ip6_fraghdr->ip6f_ident);
      }

      inet_ntop (AF_INET6, (const void *) &ip6_pkt->ip6_src, ip_src, sizeof (ip_src));
      inet_ntop (AF_INET6, (const void *) &ip6_pkt->ip6_dst, ip_dst, sizeof (ip_dst));
    }
    break;
#endif
  }

  if (quiet < 1) {
    printf ("#");
    fflush (stdout);
  }

  switch (ip_proto) {
  case IPPROTO_TCP:
    {
      struct tcphdr *tcp_pkt = (struct tcphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
      uint16_t tcphdr_offset = (frag_offset) ? 0 : (tcp_pkt->th_off * 4);

      data = (unsigned char *) (tcp_pkt) + tcphdr_offset;
      len -= link_offset + ip_hl + tcphdr_offset;

#if USE_IPv6
      if (ip_ver == 6)
	len -= ntohs (ip6_pkt->ip6_plen);
#endif

      if ((int32_t) len < 0)
	len = 0;
		
	 if(tcpreasm != NULL && tcpdefrag_enable && (len > 0) && (tcp_pkt->th_flags & TH_ACK)) {

			unsigned new_len;
			u_char *new_p_2 = malloc(len+10);
			memcpy(new_p_2, data, len);
	
			if((tcp_pkt->th_flags & TH_PUSH)) psh = 1;
			
			if(debug)		
        			printf("DEFRAG TCP process: EN:[%d], LEN:[%d], ACK:[%d], PSH[%d]\n", 
			                        tcpdefrag_enable, len, (tcp_pkt->th_flags & TH_ACK), psh);
			
	                datatcp = tcpreasm_ip_next_tcp(tcpreasm, new_p_2, len , (tcpreasm_time_t) 1000000UL * h->ts.tv_sec + h->ts.tv_usec, &new_len, &ip4_pkt->ip_src, &ip4_pkt->ip_dst, ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), psh);


        	        if (datatcp == NULL) return;
        	                	        
	                len = new_len;
	            
	                if(debug)     
	                {
	                    printf("========================================================\n");
	                    printf("COMPLETE TCP DEFRAG: LEN[%d], PACKET:[%s]\n", len, datatcp);
	                    printf("========================================================\n");
                        }

			dump_packet (h, p, ip_proto, datatcp, len,
				ip_src, ip_dst, ntohs (tcp_pkt->th_sport), ntohs (tcp_pkt->th_dport), tcp_pkt->th_flags, tcphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
	                
	                /* clear datatcp */
        	        free(datatcp);
                    
	   }

           else {
	
		dump_packet (h, p, ip_proto, data, len,
			ip_src, ip_dst, ntohs (tcp_pkt->th_sport), ntohs (tcp_pkt->th_dport), tcp_pkt->th_flags, tcphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
	   }
    }
    break;

  case IPPROTO_UDP:
    {
      struct udphdr *udp_pkt = (struct udphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
      uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof (*udp_pkt);

      data = (unsigned char *) (udp_pkt) + udphdr_offset;
      len -= link_offset + ip_hl + udphdr_offset;

#if USE_IPv6
      if (ip_ver == 6)
	len -= ntohs (ip6_pkt->ip6_plen);
#endif

      if ((int32_t) len < 0)
	len = 0;

      dump_packet (h, p, ip_proto, data, len, ip_src, ip_dst,
#if HAVE_DUMB_UDPHDR
		   ntohs (udp_pkt->source), ntohs (udp_pkt->dest), 0,
#else
		   ntohs (udp_pkt->uh_sport), ntohs (udp_pkt->uh_dport), 0,
#endif
		   udphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
    }
    break;

  case IPPROTO_ICMP:
    {
      struct icmp *icmp4_pkt = (struct icmp *) ((unsigned char *) (ip4_pkt) + ip_hl);
      uint16_t icmp4hdr_offset = (frag_offset) ? 0 : 4;

      data = (unsigned char *) (icmp4_pkt) + icmp4hdr_offset;
      len -= link_offset + ip_hl + icmp4hdr_offset;

      if ((int32_t) len < 0)
	len = 0;

      dump_packet (h, p, ip_proto, data, len, ip_src, ip_dst, icmp4_pkt->icmp_type, icmp4_pkt->icmp_code, 0, icmp4hdr_offset, fragmented, frag_offset, frag_id, ip_ver);
    }
    break;

#if USE_IPv6
  case IPPROTO_ICMPV6:
    {
      struct icmp6_hdr *icmp6_pkt = (struct icmp6_hdr *) ((unsigned char *) (ip6_pkt) + ip_hl);
      uint16_t icmp6hdr_offset = (frag_offset) ? 0 : 4;

      data = (unsigned char *) (icmp6_pkt) + icmp6hdr_offset;
      len -= link_offset + ip_hl + ntohs (ip6_pkt->ip6_plen) + icmp6hdr_offset;

      if ((int32_t) len < 0)
	len = 0;

      dump_packet (h, p, ip_proto, data, len, ip_src, ip_dst, icmp6_pkt->icmp6_type, icmp6_pkt->icmp6_code, 0, icmp6hdr_offset, fragmented, frag_offset, frag_id, ip_ver);
    }
    break;
#endif

  case IPPROTO_IGMP:
    {
      struct igmp *igmp_pkt = (struct igmp *) ((unsigned char *) (ip4_pkt) + ip_hl);
      uint16_t igmphdr_offset = (frag_offset) ? 0 : 4;

      data = (unsigned char *) (igmp_pkt) + igmphdr_offset;
      len -= link_offset + ip_hl + igmphdr_offset;

      if ((int32_t) len < 0)
	len = 0;

      dump_packet (h, p, ip_proto, data, len, ip_src, ip_dst, igmp_pkt->igmp_type, igmp_pkt->igmp_code, 0, igmphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
    }
    break;

  default:
    {
      data = (unsigned char *) (ip4_pkt) + ip_hl;
      len -= link_offset + ip_hl;

      if ((int32_t) len < 0)
	len = 0;

      dump_packet (h, p, ip_proto, data, len, ip_src, ip_dst, 0, 0, 0, 0, fragmented, frag_offset, frag_id, ip_ver);
    }
    break;

  }

  if (packet != NULL)
    free (packet);

  if (max_matches && matches >= max_matches)
    clean_exit (0);

  if (match_after && keep_matching)
    keep_matching--;
}

int
parse_stop_request (char *request)
{

  if (!memcmp (request, "duration:", 9)) {
    stop_working_type = DURATION_SPLIT;
  }
  else if (!memcmp (request, "filesize:", 9)) {
    stop_working_type = FILESIZE_SPLIT;
  }
  else
    goto error;

  if ((stop_working_value = atoi (request + 9)) > 0)
    return 0;

error:
  printf ("bad format, should be 'duration:NUM' or 'filesize:NUM'\n");
  return -1;

}

int
parse_split_request (char *request)
{

  if (!memcmp (request, "duration:", 9)) {
    split_file_type = DURATION_SPLIT;
  }
  else if (!memcmp (request, "filesize:", 9)) {
    split_file_type = FILESIZE_SPLIT;
  }
  else
    goto error;

  if ((split_file_value = atoi (request + 9)) > 0) {
    write_deadline = split_file_value + (unsigned) time (NULL);
    return 0;
  }

error:
  printf ("bad format, should be 'duration:NUM' or 'filesize:NUM'\n");
  return -1;

}


int
check_split_deadline (unsigned int now)
{

  struct stat st;

  switch (split_file_type) {

  case DURATION_SPLIT:
    {
      if (now >= write_deadline) {
	//printf("Timeout arrived. make new file...\n");
	write_deadline += split_file_value;
	return 0;
      }
      break;
    };

  case FILESIZE_SPLIT:
    {
      stat (dump_file, &st);
      int size = st.st_size;
      if (size >= split_file_value * 1024) {
	//printf("file size is [%d]. split file ...\n", split_file_value);
	return 0;
      }
      break;
    };

  default:
    break;
  }

  return -1;
}

int check_exit_statistics (unsigned int now)
{

  if (now >= (stats_duration + start_time)) {
	dump_statistics(last_stats_dump, now);
	printf ("Timeout arrived. go to exit...\n");
	return 0;
  }
  else if((now - last_stats_dump) > stats_interval) {
      dump_statistics(last_stats_dump, now);              
      last_stats_dump = now;
  }

  return -1;
}

int dump_statistics (unsigned int last, unsigned int now)
{

    struct statistics_table *st = NULL, *sttmp = NULL;
	
    HASH_ITER (hh, statstable, st, sttmp) {

	printf("%d;%d;%s;%s;%s;%d;%d\n", last, now, st->method, st->orig_method, st->cseq_method, st->req, st->count);
        HASH_DEL (statstable, st);
        free (st);
    }
    
    return 1;
}

int check_exit_deadline (unsigned int now)
{

  struct stat st;

  switch (stop_working_type) {

  case DURATION_SPLIT:
    {
      if (now >= (stop_working_value + start_time)) {
	printf ("Timeout arrived. go to exit...\n");
	return 0;
      }
      break;
    }

  case FILESIZE_SPLIT:
    {
      stat (dump_file, &st);
      int size = st.st_size;
      if (size >= (stop_working_value * 1024)) {
	printf ("file size is [%d]. go to exit...\n", stop_working_value);
	return 0;
      }
      break;
    }
  default:
    break;
  }

  return -1;
}


void
dump_packet (struct pcap_pkthdr *h, u_char * p, uint8_t proto, unsigned char *data, uint32_t len, const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport,
	     uint8_t flags, uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id, uint32_t ip_ver)
{

  rc_info_t *rcinfo = NULL;
  int now = (unsigned) time (NULL);
  unsigned char *d;

  if (!isalpha (data[0])) {
    return;
  }

  if (check_exit_deadline (now) == 0) {
    clean_exit (0);
    return;
  }

  if (!show_empty && len == 0)
    return;

  if (len > limitlen)
    len = limitlen;

  if (len == 0)
    return;

  /* send data to homer */
  if (use_homer) {
    rcinfo = malloc (sizeof (rc_info_t));
    memset (rcinfo, 0, sizeof (rc_info_t));

    rcinfo->src_port = sport;
    rcinfo->dst_port = dport;
    rcinfo->src_ip = ip_src;
    rcinfo->dst_ip = ip_dst;
    rcinfo->ip_family = ip_ver = 4 ? AF_INET : AF_INET6;
    rcinfo->ip_proto = proto;
    rcinfo->time_sec = h->ts.tv_sec;
    rcinfo->time_usec = h->ts.tv_usec;
    rcinfo->proto_type = 1;

    /* Duplicate */
    if (!send_hepv3 (rcinfo, data, (unsigned int) len)) {
      printf ("Not duplicated\n");
    }

    if (rcinfo)
      free (rcinfo);
  }
  
  if (stats_enable && check_exit_statistics(now) == 0) {
      clean_exit (0);
      return;          
  }


  // Loop until each and every byte of the message got parsed completely
  uint32_t total_bytes_parsed = 0;
  uint32_t remaining_bytes = len;
  
  //printf("LEN: %d vs %d\n", total_bytes_parsed, len);
  
  d =  data;
  
  while (total_bytes_parsed < len) 
  {

        preparsed_sip_t psip;
        char callid[256];
        char method[100];
        uint8_t local_match;
        struct callid_table *s = NULL;
        struct statistics_table *st = NULL;
        struct callid_remove *rm = NULL;
	uint32_t bytes_parsed = 0;

        if (dialog_match || stats_enable || kill_friendlyscanner) 
        {

          /* SIP parse */
            //printf("-------------------------------------------------\n");
            //printf("PACKET: [%.*s]\n", remaining_bytes, d);
            //printf("-------------------------------------------------\n");
      
            memset (&psip, 0, sizeof (struct preparsed_sip));
            bytes_parsed = 0;
            int message_parsed = parse_message ( d, remaining_bytes, &bytes_parsed, &psip);
            total_bytes_parsed += bytes_parsed;
            remaining_bytes = len - total_bytes_parsed;                  
      
            if (message_parsed == 0) 
            {
        	// incomplete packet encountered, will deal with it whenever next packet comes in.
        	printf("NOT PARSED!\n");
        	total_bytes_parsed = len;
        	continue;
            }            
            

            
            if(stats_enable) 
            {
                    
                  if(psip.is_method == SIP_REPLY) 
                  {
                      snprintf (method, sizeof (method), "%d:%s", psip.reply,psip.cseq_method);
                  }
                  else 
                  {
                      snprintf (method, sizeof (method), "%s:%s", psip.method,psip.cseq_method);
                  }                
          
                  HASH_FIND_STR (statstable, method, st);

                if (!st) 
                {
                    st = (struct statistics_table *) malloc (sizeof (struct statistics_table));
                    snprintf (st->method, sizeof(st->method), "%s", method);            
  
                    if(psip.is_method == SIP_REPLY) 
                    {
                          snprintf (st->orig_method, sizeof(st->orig_method), "%d", psip.reply);
                          st->req = 0;
                    }
                    else 
                    {
                          snprintf (st->orig_method, sizeof(st->orig_method), "%s", psip.method);
                          st->req = 1;
                    }
            
                    snprintf (st->cseq_method, sizeof(st->cseq_method), "%s", psip.cseq_method);
                    st->count = 1;                                                
                    st->time = (unsigned) time (NULL);
                    HASH_ADD_STR (statstable, method, st);
                }
                else 
                {
                    st->count++;	
                    st->time = (unsigned) time (NULL);
                }          
            }

            if (kill_friendlyscanner && psip.uac.len > 0 && (strstr (psip.uac.s, friendly_scanner_uac) != NULL)) 
            {
        	printf ("Killing friendly scanner [%s]...\n", friendly_scanner_uac);
        	send_kill_to_friendly_scanner (ip_src, sport);
            }

            if (!dialog_match) continue;

            if(psip.callid.len == 0) 
            {
                    printf("BAD M:[%s]\n", d);        
                    continue;
            }
      
            snprintf (callid, sizeof (callid), "%.*s", psip.callid.len, psip.callid.s);
            s = (struct callid_table *) malloc (sizeof (struct callid_table));
            HASH_FIND_STR (dialogs, callid, s);
            if (s) 
            {
        	// Sip Message found, update hash table
        	if (psip.is_method == SIP_REPLY) 
        	{	// This is a response
        	      if (!memcmp (psip.cseq_method, INVITE_METHOD, INVITE_LEN)) 
        	      {
        	            switch (psip.reply / 100) 
        	            {
        	                  case 1:
        	                        if (psip.reply >= 180) s->cdr_ringing = h->ts.tv_sec;
                                        break;
                                  case 2:
                                        s->cdr_connect = h->ts.tv_sec;
                                        break;
                                  case 3:
                                        if (psip.reply == 386) {
                                              s->terminated = CALL_MOVED_TERMINATION;
                                              s->termination_reason = psip.reply;
                                              s->cdr_disconnect = h->ts.tv_sec;
                                        }
                                        break;
                                  case 4:
                                        s->termination_reason = psip.reply;
                                        if (psip.reply == 401 || psip.reply == 407) s->terminated = CALL_AUTH_TERMINATION;
                                        else if (psip.reply == 487) s->terminated = CALL_CANCEL_TERMINATION;
                                        else s->terminated = CALL_4XX_TERMINATION;
                                        s->cdr_disconnect = h->ts.tv_sec;
                                        break;
                                  case 5:
                                        s->termination_reason = psip.reply;
                                        s->terminated = CALL_5XX_TERMINATION;
                                        s->cdr_disconnect = h->ts.tv_sec;
                                        break;
                                  case 6:
                                        s->termination_reason = psip.reply;
                                        s->terminated = CALL_6XX_TERMINATION;
                                        s->cdr_disconnect = h->ts.tv_sec;
                                        break;
                                  default:
                                        break;
                            }
                      }
                      else if (!strcmp (psip.cseq_method, REGISTER_METHOD)) 
                      {
                            switch (psip.reply / 100) 
                            {
                                  case 2:
                                      s->cdr_connect = h->ts.tv_sec;
                                      s->terminated = REGISTRATION_200_TERMINATION;
                                      s->termination_reason = psip.reply;
                                      s->registered = 1;
                                      break;
                                  case 3:
                                  case 4:
                                      s->termination_reason = psip.reply;
                                      if (psip.reply == 401 || psip.reply == 407) s->terminated = CALL_AUTH_TERMINATION;
                                      else s->terminated = CALL_4XX_TERMINATION;
                                      s->cdr_disconnect = h->ts.tv_sec;
                                      break;
                                  case 5:
                                      s->termination_reason = psip.reply;
                                      s->terminated = CALL_5XX_TERMINATION;
                                      s->cdr_disconnect = h->ts.tv_sec;
                                      break;
                                  case 6:
                                      s->termination_reason = psip.reply;
                                      s->terminated = REGISTRATION_6XX_TERMINATION;
                                      s->cdr_disconnect = h->ts.tv_sec;
                                      break;
                                  default:
                                        break;
                            }
                      }
                }
                /* REQUEST */
                else 
                {
                      if (!strcmp (psip.method, INVITE_METHOD)) 
                      {	// Re-Invite
                  	    /* if new invite without to-tag */
                              if (psip.has_totag == 0 && s->init_cseq < psip.cseq_num) 
                              {
                                      /* remove CALLID from remove hash */
                                      if (s->terminated != 0) delete_dialogs_remove_element (callid);
                                      s->init_cseq = psip.cseq_num;
                                      s->cdr_init = h->ts.tv_sec;
                                      s->cdr_ringing = 0;
                                      s->cdr_connect = 0;
                                      s->cdr_disconnect = 0;
                                      s->termination_reason = 0;
                                      s->terminated = 0;
                                }
                      }
                      else if (!strcmp (psip.method, REGISTER_METHOD)) 
                      {
                              if (s->init_cseq < psip.cseq_num) 
                              {
                                      s->init_cseq = psip.cseq_num;
                                      s->cdr_init = h->ts.tv_sec;
                                      s->cdr_ringing = 0;
                                      s->cdr_connect = 0;
                                      s->cdr_disconnect = 0;
                                      s->termination_reason = 0;
                                      s->terminated = 0;
                                      s->registered = 0;
                              }
                      }
                      else if (!strcmp (psip.method, BYE_METHOD)) 
                      {
                          s->cdr_disconnect = h->ts.tv_sec;
                          s->terminated = CALL_BYE_TERMINATION;
                          s->termination_reason = 900;
                      }
                      else if (!strcmp (psip.method, CANCEL_METHOD)) 
                      {
                          s->cdr_disconnect = h->ts.tv_sec;
                          s->terminated = CALL_CANCEL_TERMINATION;
                      }	
                }
              
                 //callid_remove
                if (s->terminated != 0) 
                {
                      HASH_FIND_STR (dialogs_remove, callid, rm);
                      if (!rm) 
                      {
                            rm = (struct callid_remove *) malloc(sizeof (struct callid_remove));
                            snprintf (rm->callid, 256, "%s", callid);
                            rm->removed = 1;
                            rm->time = (unsigned) time (NULL) + 5;
                            HASH_ADD_STR (dialogs_remove, callid, rm);

                            /* new remove time */
                            if (time_dialog_remove == 0) time_dialog_remove = rm->time;
                      }
                 }

                 /* check our Hashtable if need to delete something */
                 if (enable_dialog_remove) check_dialogs_delete ();
            }          

            if (!s) 
            {
                // Sip Message not found, add it to hash table
                local_match = match_func (d, len);
                if (local_match == 1 && !invert_match || local_match != invert_match) 
                {
                    if (dialog_match) 
                    {
                       if (psip.is_method == SIP_REQUEST)
                       {	  
                             if (!strcmp (psip.method, INVITE_METHOD)) 
                             {
                                 s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                 snprintf (s->callid, 256, "%s", callid);
                                 if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                 if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                 if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);
                          
                                 s->transaction = INVITE_TRANSACTION;
                                 s->init_cseq = psip.cseq_num;
                                 s->cdr_init = h->ts.tv_sec;
                                 s->cdr_ringing = 0;
                                 s->cdr_connect = 0;
                                 s->cdr_disconnect = 0;
                                 s->terminated = 0;
                                 s->termination_reason = 0;
                              }
                              else if (!strcmp (psip.method, REGISTER_METHOD)) 
                              {
                                    s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                    snprintf (s->callid, 256, "%s", callid);                        
                                    if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                    if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                    if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);

                                    s->transaction = REGISTER_TRANSACTION;
                                    s->init_cseq = psip.cseq_num;
                                    s->cdr_init = h->ts.tv_sec;
                                    s->cdr_ringing = 0;
                                    s->cdr_connect = 0;
                                    s->cdr_disconnect = 0;
                                    s->terminated = 0;
                                    s->termination_reason = 0;
                              }
                              else if (!strcmp (psip.method, NOTIFY_METHOD)) 
                              {
                                    s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                    snprintf (s->callid, 256, "%s", callid);
                                    if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                    if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                    if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);
                                    
                                    s->transaction = NOTIFY_TRANSACTION;
                                    s->init_cseq = psip.cseq_num;
                                    s->cdr_init = h->ts.tv_sec;
                                    s->cdr_ringing = 0;
                                    s->cdr_connect = 0;
                                    s->cdr_disconnect = 0;
                                    s->terminated = 0;
                                    s->termination_reason = 0;
                                }
                                else if (!strcmp (psip.method, OPTIONS_METHOD)) 
                                {
                                    s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                    snprintf (s->callid, 256, "%s", callid);
                                    if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                    if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                    if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);
                                    s->transaction = OPTIONS_TRANSACTION;
                                    s->init_cseq = psip.cseq_num;
                                    s->cdr_init = h->ts.tv_sec;
                                    s->cdr_ringing = 0;
                                    s->cdr_connect = 0;
                                    s->cdr_disconnect = 0;
                                    s->terminated = 0;
                                    s->termination_reason = 0;
                                }
                                else if (!strcmp (psip.method, ACK_METHOD)) 
                                {
                                      // Nothing to do (for now)
                                }
                                else if (!strcmp (psip.method, SUBSCRIBE_METHOD)) 
                                {
                                    s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                    snprintf (s->callid, 256, "%s", callid);
                                    if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                    if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                    if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);
                                    s->transaction = SUBSCRIBE_TRANSACTION;
                                    s->init_cseq = psip.cseq_num;
                                    s->cdr_init = h->ts.tv_sec;
                                    s->cdr_ringing = 0;
                                    s->cdr_connect = 0;
                                    s->cdr_disconnect = 0;
                                    s->terminated = 0;
                                    s->termination_reason = 0;
                                }
                                else if (!strcmp (psip.method, PUBLISH_METHOD)) {
                                      s = (struct callid_table *) malloc (sizeof (struct callid_table));
                                      snprintf (s->callid, 256, "%s", callid);
                                      if (psip.from.len) snprintf (s->from, 256, "%.*s", psip.from.len, psip.from.s);
                                      if (psip.to.len) snprintf (s->to, 256, "%.*s", psip.to.len, psip.to.s);
                                      if (psip.uac.len) snprintf (s->uac, 256, "%.*s", psip.uac.len, psip.uac.s);
                                      s->transaction = PUBLISH_TRANSACTION;
                                      s->init_cseq = psip.cseq_num;
                                      s->cdr_init = h->ts.tv_sec;
                                      s->cdr_ringing = 0;
                                      s->cdr_connect = 0;
                                      s->cdr_disconnect = 0;
                                      s->terminated = 0;
                                      s->termination_reason = 0;
                                }

                                if (s) HASH_ADD_STR (dialogs, callid, s);
                       }
                    }
                }
                else 
                {
                    return;
                }
            }
        }
        else {
            /* check if we have more than one SIP message here */
            if(light_parse_message ( d, remaining_bytes, &bytes_parsed) == 1)
	    {
		total_bytes_parsed += bytes_parsed;
		remaining_bytes = len - total_bytes_parsed;
	    }
	    else {
		total_bytes_parsed = len;
		break;		
	    }
        }

        if (!live_read && want_delay) dump_delay (h);

        {
                char ident;
                switch (proto) {
                    case IPPROTO_TCP:
                          ident = TCP;
                          break;
                    case IPPROTO_UDP:
                          ident = UDP;
                          break;
                    case IPPROTO_ICMP:
                          ident = ICMP;
                          break;
                    case IPPROTO_ICMPV6:
                          ident = ICMPv6;
                          break;
                    case IPPROTO_IGMP:
                          ident = IGMP;
                          break;
                    default:
                          ident = UNKNOWN;
                          break;
                  }

                  if (quiet < 2) printf ("\n%c", ident);
        }

        if (quiet < 3) 
        {
              if (show_proto) printf ("(%u)", proto);
              printf (" ");
              if (print_time) print_time (h);
              if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && (sport || dport) && (hdr_offset || frag_offset == 0))
                      printf ("%s:%u -> %s:%u\n", ip_src, sport, ip_dst, dport);
              else printf ("%s -> %s\n", ip_src, ip_dst);

              if (proto == IPPROTO_TCP && flags)
                      printf (" [%s%s%s%s%s%s%s%s]", (flags & TH_ACK) ? "A" : "", (flags & TH_SYN) ? "S" : "", (flags & TH_RST) ? "R" : "",
                            (flags & TH_FIN) ? "F" : "", (flags & TH_URG) ? "U" : "", (flags & TH_PUSH) ? "P" : "", (flags & TH_ECE) ? "E" : "", (flags & TH_CWR) ? "C" : "");

              switch (proto) 
              {
                  case IPPROTO_ICMP:
                  case IPPROTO_ICMPV6:
                  case IPPROTO_IGMP:
                      printf (" %u:%u", sport, dport);
              }

              if (frag) printf (" %s%u@%u:%u", frag_offset ? "+" : "", frag_id, frag_offset, len);
              if (dump_single) printf (" ");
              else printf ("\n");
         }

         if (quiet < 3) dump_func (d, bytes_parsed);	// dumps the packet held by data buffer

	 /* and now skip parsed data*/
         d+=bytes_parsed;
  	 bytes_parsed = 0;
    }

    if (pd_dump) 
    {
    	/* check rotation */
        create_dump (now);
        pcap_dump ((u_char *) pd_dump, h, p);
        pcap_dump_flush (pd_dump);
    }
}

int8_t
re_match_func (unsigned char *data, uint32_t len)
{

  switch (pcre_exec (pattern, 0, (char *)data, (int32_t) len, 0, 0, 0, 0)) {
  case PCRE_ERROR_NULL:
  case PCRE_ERROR_BADOPTION:
  case PCRE_ERROR_BADMAGIC:
  case PCRE_ERROR_UNKNOWN_NODE:
  case PCRE_ERROR_NOMEMORY:
    perror ("she's dead, jim\n");
    clean_exit (-2);
    break;

  case PCRE_ERROR_NOMATCH:
    return 0;
  }

  if (max_matches)
    matches++;

  if (match_after && keep_matching != match_after)
    keep_matching = match_after;

  return 1;
}


int8_t
blank_match_func (unsigned char *data, uint32_t len)
{
  if (max_matches)
    matches++;

  return 1;
}

// this dumps the given data which represents an actual packet.
void
dump_byline (unsigned char *data, uint32_t len)
{
  if (len > 0) {
    unsigned char *s = data;
    int offset = 0, left = 0, via_found = 0;
    const unsigned char *pch = NULL, *pca = NULL;
    char *color;
    int stop = -1, start = -1;

    while (s < data + len) {

      if (use_color) {

	offset = s - data;

	if (offset == 0 && len > 100) {

	  if (!memcmp ("SIP/2.0 ", s, 8)) {
	    start = 8;
	    stop = 0;
	    color = BOLDYELLOW;
	  }
	  else if ((pch = strchr ((const char*) s, ' ')) != NULL) {
	    start = 0;
	    stop = pch - s + 1;
	    color = BOLDRED;
	  }

	}
	else if ((left = (len - offset)) > 20) {

	  if (!memcmp (s, "Call-ID:", 8)) {
	    start = offset + 8;
	    stop = 0;
	    color = BOLDMAGENTA;
	  }
	  else if (!memcmp (s, "From:", 5) || !memcmp (s, "f:", 2)) {
	    pch = strstr ((char *)s, ";tag=");
	    if (pch != NULL) {
	      start = offset + (pch - s + 1);
	      stop = 0;
	      color = BOLDBLUE;
	    }
	  }
	  else if (!memcmp (s, "To:", 3) || !memcmp (s, "t:", 2)) {
	    pch = strstr ((char *)s, ";tag=");
	    if (pch != NULL) {
	      start = offset + (pch - s + 1);
	      stop = 0;
	      color = BOLDGREEN;
	    }
	  }
	  else if (via_found == 0 && (!memcmp (s, "Via:", 4) || !memcmp (s, "v:", 2))) {
	    pch = strstr ((char *)s, "branch=");
	    if (pch != NULL) {
	      start = offset + (pch - s);
	      pca = strchr ((char *)pch, ';');
	      if (pca != NULL) {
		stop = start + (pca - pch);
		pca = strchr ((char *)pch, '\n');
		if (pca != NULL && (start + (pca - pch)) < stop)
		  stop = start + (pca - pch);
	      }
	      else
		stop = 0;

	      color = BOLDCYAN;
	      via_found = 1;
	    }
	  }
	}

	/* stop color */
	if (stop && stop == offset) {
	  printf (RESET);
	  stop = -1;
	}
	else if (*s == '\n' && stop == 0) {
	  printf (RESET);
	  stop = -1;
	}

	if (start >= 0 && start == offset) {
	  printf ("%s", color);
	  start = -1;
	}
      }


      printf ("%c", (*s == '\n' || isprint (*s)) ? *s : nonprint_char);

      s++;

    }

    printf ("\n");
  }
}

void
dump_unwrapped (unsigned char *data, uint32_t len)
{
  if (len > 0) {
    const unsigned char *s = data;

    while (s < data + len) {
      printf ("%c", isprint (*s) ? *s : nonprint_char);
      s++;
    }

    printf ("\n");
  }
}

void
dump_formatted (unsigned char *data, uint32_t len)
{
  if (len > 0) {
    unsigned char *str = data;
    uint8_t width = (ws_col - 5);
    uint32_t i = 0, j = 0;

    while (i < len) {
      printf ("  ");

      for (j = 0; j < width; j++)
	if (i + j < len)
	  printf ("%c", isprint (str[j]) ? str[j] : nonprint_char);
	else
	  printf (" ");

      str += width;
      i += j;

      printf ("\n");
    }
  }
}

char *
get_filter_from_string (char *str)
{
  char *mine, *s;
  uint32_t len;

  if (!str || !*str)
    return NULL;

  len = (uint32_t) strlen (str);

  for (s = str; *s; s++)
    if (*s == '\r' || *s == '\n')
      *s = ' ';

  if (!(mine = (char *) malloc (len + sizeof (BPF_MAIN_FILTER))))
    return NULL;

  memset (mine, 0, len + sizeof (BPF_MAIN_FILTER));

  sprintf (mine, BPF_MAIN_FILTER, str);

  return mine;
}

char *
get_filter_from_portrange (char *str)
{
  char *mine, *s;
  uint32_t len;

  if (!str || !*str)
    return NULL;

  len = (uint32_t) strlen (str);

  for (s = str; *s; s++)
    if (*s == '\r' || *s == '\n')
      *s = ' ';

  if (!(mine = (char *) malloc (len + (reasm_enable ? sizeof (BPF_DEFRAGMENTION_FILTER) : sizeof (BPF_MAIN_PORTRANGE_FILTER)))))
    return NULL;

  memset (mine, 0, len + (reasm_enable ? sizeof (BPF_DEFRAGMENTION_FILTER) : sizeof (BPF_MAIN_PORTRANGE_FILTER)));

  sprintf (mine, (reasm_enable ? BPF_DEFRAGMENTION_FILTER : BPF_MAIN_PORTRANGE_FILTER), str);

  return mine;
}

char *
get_filter_from_argv (char **argv)
{
  char **arg = argv, *theirs, *mine;
  char *from, *to;
  uint32_t len = 0;

  if (!*arg)
    return NULL;

  while (*arg)
    len += (uint32_t) strlen (*arg++) + 1;

  if (!(theirs = (char *) malloc (len + 1)) || !(mine = (char *) malloc (len + sizeof (BPF_MAIN_FILTER))))
    return NULL;

  memset (theirs, 0, len + 1);
  memset (mine, 0, len + sizeof (BPF_MAIN_FILTER));

  arg = argv;
  to = theirs;

  while ((from = *arg++)) {
    while ((*to++ = *from++));
    *(to - 1) = ' ';
  }

  sprintf (mine, BPF_MAIN_FILTER, theirs);

  free (theirs);
  return mine;
}


uint8_t
strishex (char *str)
{
  char *s;

  if ((s = strchr (str, 'x')))
    s++;
  else
    s = str;

  while (*s)
    if (!isxdigit (*s++))
      return 0;

  return 1;
}


void
print_time_absolute (struct pcap_pkthdr *h)
{
  struct tm *t = localtime ((const time_t *) &h->ts.tv_sec);

  printf ("%02u/%02u/%02u %02u:%02u:%02u.%06u ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, (uint32_t) h->ts.tv_usec);
}


void
print_time_diff (struct pcap_pkthdr *h)
{
  uint32_t secs, usecs;

  secs = h->ts.tv_sec - prev_ts.tv_sec;
  if (h->ts.tv_usec >= prev_ts.tv_usec)
    usecs = h->ts.tv_usec - prev_ts.tv_usec;
  else {
    secs--;
    usecs = 1000000 - (prev_ts.tv_usec - h->ts.tv_usec);
  }

  printf ("+%u.%06u ", secs, usecs);

  prev_ts.tv_sec = h->ts.tv_sec;
  prev_ts.tv_usec = h->ts.tv_usec;
}

void
dump_delay_proc_init (struct pcap_pkthdr *h)
{
  dump_delay = &dump_delay_proc;

  prev_delay_ts.tv_sec = h->ts.tv_sec;
  prev_delay_ts.tv_usec = h->ts.tv_usec;

  dump_delay (h);
}

void
dump_delay_proc (struct pcap_pkthdr *h)
{
  uint32_t secs, usecs;

  secs = h->ts.tv_sec - prev_delay_ts.tv_sec;
  if (h->ts.tv_usec >= prev_delay_ts.tv_usec)
    usecs = h->ts.tv_usec - prev_delay_ts.tv_usec;
  else {
    secs--;
    usecs = 1000000 - (prev_delay_ts.tv_usec - h->ts.tv_usec);
  }

  sleep (secs);
  usleep (usecs);

  prev_delay_ts.tv_sec = h->ts.tv_sec;
  prev_delay_ts.tv_usec = h->ts.tv_usec;
}

void
update_windowsize (int32_t e)
{
  if (e == 0 && ws_col_forced)

    ws_col = ws_col_forced;

  else if (!ws_col_forced) {
    const struct winsize ws;

    if (!ioctl (0, TIOCGWINSZ, &ws)) {
      ws_row = ws.ws_row;
      ws_col = ws.ws_col;
    }
    else {
      ws_row = 24;
      ws_col = 80;
    }
  }
}

#if USE_DROPPRIVS
void
drop_privs (void)
{
  struct passwd *pw;
  uid_t newuid;
  gid_t newgid;

  if ((getuid () || geteuid ()) || dont_dropprivs)
    return;

  pw = getpwnam (DROPPRIVS_USER);
  if (!pw) {
    perror ("attempt to drop privileges failed: getpwnam failed");
    clean_exit (-1);
  }

  newgid = pw->pw_gid;
  newuid = pw->pw_uid;

  if (getgroups (0, NULL) > 0)
    if (setgroups (1, &newgid) == -1) {
      perror ("attempt to drop privileges failed");
      clean_exit (-1);
    }

  if (((getgid () != newgid) && (setgid (newgid) == -1)) ||
      ((getegid () != newgid) && (setegid (newgid) == -1)) ||
      ((getuid () != newuid) && (setuid (newuid) == -1)) || ((geteuid () != newuid) && (seteuid (newuid) == -1))) {

    perror ("attempt to drop privileges failed");
    clean_exit (-1);
  }
}

#endif

void
usage (int8_t e)
{
  printf ("usage: sipgrep <-"
	  "ahNViwgGJpevxlDTRMmqCJjxK> <-IO pcap_dump> <-n num> <-d dev> <-A num>\n"
	  "             <-s snaplen> <-S limitlen> <-c contact user> <-j user agent>\n"
	  "		 <-f from user>  <-t to user> <-H capture url> <-q autostop cond.>\n"
	  "		 <-Q split cond.> <-P portrange> <-F file> <-z duration>\n"
	  "		 <match expression> <bpf filter>\n"
	  "   -h  is help/usage\n"
	  "   -V  is version information\n"
	  "   -e  is show empty packets\n"
	  "   -i  is ignore case\n"
	  "   -x  is disable bad parsing notification\n"
	  "   -v  is invert match\n"
	  "   -R  is don't do privilege revocation logic\n"
	  "   -w  is word-regex (expression must match as a word)\n"
	  "   -p  is don't go into promiscuous mode\n"
	  "   -l  is make stdout line buffered\n"
	  "   -D  is replay pcap_dumps with their recorded time intervals\n"
	  "   -T  is print delta timestamp every time a packet is matched\n"
	  "   -m  is don't do dialog match\n"
	  "   -M  is don't do multi-line match (do single-line match instead)\n"
	  "   -I  is read packet stream from pcap format file pcap_dump\n"
	  "   -O  is dump matched packets in pcap format to pcap_dump\n"
	  "   -n  is look at only num packets\n"
	  "   -A  is dump num packets after a match\n"
	  "   -s  is set the bpf caplen\n"
	  "   -S  is set the limitlen on matched packets\n"
	  "   -C  is no colors in stdout\n"
	  "   -c  is search user in Contact: header\n"
	  "   -f  is search user in From: header\n"
	  "   -t  is search user in To: header\n"
	  "   -F  is read the bpf filter from the specified file\n"
	  "   -H  is homer sipcapture URL (i.e. udp:10.0.0.1:9061)\n"
	  "   -N  is show sub protocol number\n"
	  "   -g  is disabled clean up dialogs during trace\n"
	  "   -G  is print dialog report during clean up\n"
	  "   -J  is kill friendly scanner automatically\n"
	  "   -j  is kill friendly scanner automatically matching user agent string\n"
	  "   -K  is kill friendly scanner providing IP and port/portrange i.e.: 10.0.0.1:5060-5090\n"
	  "   -q  is auto stop condition:\n"
	  "    	duration:NUM - stop after NUM seconds\n"
	  "    	filesize:NUM - stop this file after NUM KB\n"
	  "   -Q  is pcap_dump split condition:\n"
	  "    	duration:NUM - switch to next file after NUM secs\n"
	  "    	filesize:NUM - switch to next file after NUM KB\n"
	  "   -a  is disable packet re-assemblation\n"
	  "   -P  is use specified portrange instead of default 5060-5061\n"
	  "   -d  is use specified device instead of the pcap default\n" "   -z  is make statistics count maximum <duration> seconds\n" "");

  exit (e);
}


void
version (void)
{
  printf ("sipgrep: V%s\n", VERSION);
  exit (0);
}


void
clean_exit (int32_t sig)
{
  struct pcap_stat s;

  signal (SIGINT, SIG_IGN);
  signal (SIGABRT, SIG_IGN);
  signal (SIGQUIT, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
  signal (SIGWINCH, SIG_IGN);

  if (quiet < 1 && sig >= 0)
    printf ("exit\n");

  if (pattern)
    pcre_free (pattern);
  if (pattern_extra)
    pcre_free (pattern_extra);

  if (bin_data)
    free (bin_data);

  if (quiet < 1 && sig >= 0 && !read_file && pd && !pcap_stats (pd, &s))
    printf ("%u received, %u dropped\n", s.ps_recv, s.ps_drop);

  if (pd)
    pcap_close (pd);
  if (pd_dump)
    pcap_dump_close (pd_dump);

  if (reasm != NULL)
    reasm_ip_free (reasm);

  if (tcpreasm != NULL) 
     tcpreasm_ip_free(tcpreasm);

  clear_all_dialogs_element ();

  exit (sig);
}


void
delete_dialogs_remove_element (char *callid)
{

  struct callid_remove *rm = NULL;

  HASH_FIND_STR (dialogs_remove, callid, rm);

  if (rm) {
    HASH_DEL (dialogs_remove, rm);
    free (rm);
  }
}

void
delete_dialogs_element (char *callid)
{

  struct callid_table *s = NULL;

  HASH_FIND_STR (dialogs, callid, s);

  if (s) {
    if (print_report)
      print_dialogs_stats (s);
    HASH_DEL (dialogs, s);
    if (s)
      free (s);
  }
}

void
clear_all_dialogs_element ()
{

  struct callid_table *s, *tmp = NULL;
  struct callid_remove *rm, *rtmp = NULL;

  HASH_ITER (hh, dialogs, s, tmp) {
    if (print_report)
      print_dialogs_stats (s);
    HASH_DEL (dialogs, s);
    free (s);
  }

  HASH_ITER (hh, dialogs_remove, rm, rtmp) {
    HASH_DEL (dialogs_remove, rm);
    free (rm);
  }
}


void
print_dialogs_stats (struct callid_table *s)
{

  if (!s)
    return;

  //unsigned int ringdelta = 0;
  unsigned int connectdelta = 0;
  unsigned int durationdelta = 0;
  int now = (unsigned) time (NULL);

  printf (BOLDMAGENTA "-----------------------------------------------\nDialog finished: [%s]\n" RESET, s->callid);
  printf (BOLDGREEN "Type: " RESET);
  switch (s->transaction) {

  case INVITE_TRANSACTION:
    {
      printf (BOLDGREEN "Call\n" RESET);
      printf (BOLDGREEN "From: %s\n" RESET, s->from);
      printf (BOLDGREEN "To: %s\n" RESET, s->to);
      printf (BOLDGREEN "UAC: %s\n" RESET, s->uac);
      printf (BOLDGREEN "CDR init ts: %d\n" RESET, s->cdr_init);

      if (s->cdr_ringing > 0) {
	printf (BOLDGREEN "CDR ringing ts: %d\n" RESET, s->cdr_ringing);
	printf (BOLDGREEN "SRD(PDD): %d sec\n" RESET, (s->cdr_ringing - s->cdr_init));
      }
      if (s->cdr_connect > 0) {
	printf (BOLDGREEN "CDR answer ts: %d\n" RESET, s->cdr_connect);
	connectdelta = s->cdr_connect - s->cdr_init;
	if (s->cdr_disconnect == 0)
	  s->cdr_disconnect = now;
	durationdelta = s->cdr_disconnect - s->cdr_connect;

	printf (BOLDGREEN "WTA: %d sec\n" RESET, connectdelta);
	printf (BOLDGREEN "CDT (duration): %d sec\n" RESET, durationdelta);
      }
      else {
	if (s->cdr_disconnect == 0)
	  s->cdr_disconnect = now;
	durationdelta = s->cdr_disconnect - s->cdr_init;
	printf (BOLDGREEN "SDT: %d sec\n" RESET, durationdelta);
      }

      printf (BOLDGREEN "CDR termination ts: %d\n" RESET, s->cdr_disconnect);
      printf (BOLDGREEN "Was connected: %s\n" RESET, s->cdr_connect > 0 ? "YES" : "NO");

      if (s->terminated == 0)
	printf (BOLDGREEN "REASON: NOT TERMINATED\n" RESET);
      else if (s->termination_reason == 900)
	printf (BOLDGREEN "REASON: BYE\n" RESET);
      else
	printf (BOLDGREEN "REASON: %d\n" RESET, s->termination_reason);

      break;
    }
  case REGISTER_TRANSACTION:
    {
      printf (BOLDBLUE "Registration\n" RESET);
      printf (BOLDGREEN "From: %s\n" RESET, s->from);
      printf (BOLDGREEN "To: %s\n" RESET, s->to);
      printf (BOLDGREEN "UAC: %s\n" RESET, s->uac);
      printf (BOLDGREEN "CDR init ts: %d\n" RESET, s->cdr_init);

      if (s->registered) {
	printf (BOLDGREEN "CDR termination ts: %d\n" RESET, s->cdr_connect);
	durationdelta = s->cdr_connect - s->cdr_init;
      }
      else {
	if (s->cdr_disconnect == 0)
	  s->cdr_disconnect = now;
	durationdelta = s->cdr_disconnect - s->cdr_init;
	printf (BOLDGREEN "CDR termination: %d\n" RESET, s->cdr_disconnect);
      }

      printf (BOLDGREEN "SDT: %d sec\n" RESET, durationdelta);
      printf (BOLDGREEN "Was registered: %s\n" RESET, s->registered ? "YES" : "NO");

      if (s->terminated == 0)
	printf (BOLDGREEN "REASON: NOT TERMINATED\n" RESET);
      else
	printf (BOLDGREEN "REASON: %d\n" RESET, s->termination_reason);

      break;
    }
  default:
    printf ("Unknown\n");
    break;
  }
  printf (BOLDMAGENTA "-----------------------------------------------\n\n" RESET);

}


void
check_dialogs_delete ()
{

  int now = (unsigned) time (NULL);

  if (time_dialog_remove != 0 && time_dialog_remove < now) {

    struct callid_remove *rm, *rtmp = NULL;

    time_dialog_remove = 0;

    HASH_ITER (hh, dialogs_remove, rm, rtmp) {

      if (rm->time < now) {
	delete_dialogs_element (rm->callid);
	HASH_DEL (dialogs_remove, rm);
	free (rm);
      }
      else if (time_dialog_remove == 0 || time_dialog_remove > rm->time)
	time_dialog_remove = rm->time;
    }
  }
}


void
send_kill_to_friendly_scanner (const char *ip, uint16_t port)
{

  struct sockaddr_in si_other;
  int s, slen = sizeof (si_other);

  if ((s = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    return;

  memset ((char *) &si_other, 0, sizeof (si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons (port);
  if (inet_aton (ip, &si_other.sin_addr) == 0) {
    fprintf (stderr, "inet_aton() failed\n");
    return;
  }

  printf ("Sending the kill packet\n");

  if (sendto (s, SIP_CRASH, strlen (SIP_CRASH), 0, (struct sockaddr *) &si_other, slen) == -1) {
    fprintf (stderr, "couldn't send\n");
  }

  close (s);
}


int
make_homer_socket (char *url)
{

  char *ip, *tmp;
  char port[20];
  struct addrinfo *ai, hints[1] = { {0} };
  int i;

  ip = strchr (url, ':');
  if (ip != NULL) {
    ip++;
    tmp = strchr (ip, ':');
    if (tmp != NULL) {
      i = (tmp - ip);
      tmp++;
      snprintf (port, 20, "%s", tmp);
      ip[i] = '\0';
    }
    else
      return 2;
  }
  else
    return 2;

  hints->ai_flags = AI_NUMERICSERV;
  hints->ai_family = AF_UNSPEC;
  hints->ai_socktype = SOCK_DGRAM;
  hints->ai_protocol = IPPROTO_UDP;

  if (getaddrinfo (ip, port, hints, &ai)) {
    fprintf (stderr, "capture: getaddrinfo() error");
    return 2;
  }

  homer_sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (homer_sock < 0) {
    fprintf (stderr, "Sender socket creation failed: %s\n", strerror (errno));
    return 3;
  }

  if (connect (homer_sock, ai->ai_addr, (socklen_t) (ai->ai_addrlen)) == -1) {
    if (errno != EINPROGRESS) {
      fprintf (stderr, "Sender socket creation failed: %s\n", strerror (errno));
      return 4;
    }
  }
  return 0;
}

int
send_hepv3 (rc_info_t * rcinfo, unsigned char *data, unsigned int len)
{

  struct hep_generic *hg = NULL;
  void *buffer;
  unsigned int buflen = 0, iplen = 0, tlen = 0;
  hep_chunk_ip4_t src_ip4, dst_ip4;
#ifdef USE_IPV6
  hep_chunk_ip6_t src_ip6, dst_ip6;
#endif
  hep_chunk_t payload_chunk;
  hep_chunk_t authkey_chunk;
  //static int errors = 0;
  char *capt_password = NULL;

  hg = malloc (sizeof (struct hep_generic));
  memset (hg, 0, sizeof (struct hep_generic));

  /* header set */
  memcpy (hg->header.id, "\x48\x45\x50\x33", 4);

  /* IP proto */
  hg->ip_family.chunk.vendor_id = htons (0x0000);
  hg->ip_family.chunk.type_id = htons (0x0001);
  hg->ip_family.data = rcinfo->ip_family;
  hg->ip_family.chunk.length = htons (sizeof (hg->ip_family));

  /* Proto ID */
  hg->ip_proto.chunk.vendor_id = htons (0x0000);
  hg->ip_proto.chunk.type_id = htons (0x0002);
  hg->ip_proto.data = rcinfo->ip_proto;
  hg->ip_proto.chunk.length = htons (sizeof (hg->ip_proto));


  /* IPv4 */
  if (rcinfo->ip_family == AF_INET) {
    /* SRC IP */
    src_ip4.chunk.vendor_id = htons (0x0000);
    src_ip4.chunk.type_id = htons (0x0003);
    inet_pton (AF_INET, rcinfo->src_ip, &src_ip4.data);
    src_ip4.chunk.length = htons (sizeof (src_ip4));

    /* DST IP */
    dst_ip4.chunk.vendor_id = htons (0x0000);
    dst_ip4.chunk.type_id = htons (0x0004);
    inet_pton (AF_INET, rcinfo->dst_ip, &dst_ip4.data);
    dst_ip4.chunk.length = htons (sizeof (dst_ip4));

    iplen = sizeof (dst_ip4) + sizeof (src_ip4);
  }
#ifdef USE_IPV6
  /* IPv6 */
  else if (rcinfo->ip_family == AF_INET6) {
    /* SRC IPv6 */
    src_ip6.chunk.vendor_id = htons (0x0000);
    src_ip6.chunk.type_id = htons (0x0005);
    inet_pton (AF_INET6, rcinfo->src_ip, &src_ip6.data);
    src_ip6.chunk.length = htonl (sizeof (src_ip6));

    /* DST IPv6 */
    dst_ip6.chunk.vendor_id = htons (0x0000);
    dst_ip6.chunk.type_id = htons (0x0006);
    inet_pton (AF_INET6, rcinfo->dst_ip, &dst_ip6.data);
    dst_ip6.chunk.length = htonl (sizeof (dst_ip6));

    iplen = sizeof (dst_ip6) + sizeof (src_ip6);
  }
#endif

  /* SRC PORT */
  hg->src_port.chunk.vendor_id = htons (0x0000);
  hg->src_port.chunk.type_id = htons (0x0007);
  hg->src_port.data = htons (rcinfo->src_port);
  hg->src_port.chunk.length = htons (sizeof (hg->src_port));

  /* DST PORT */
  hg->dst_port.chunk.vendor_id = htons (0x0000);
  hg->dst_port.chunk.type_id = htons (0x0008);
  hg->dst_port.data = htons (rcinfo->dst_port);
  hg->dst_port.chunk.length = htons (sizeof (hg->dst_port));


  /* TIMESTAMP SEC */
  hg->time_sec.chunk.vendor_id = htons (0x0000);
  hg->time_sec.chunk.type_id = htons (0x0009);
  hg->time_sec.data = htonl (rcinfo->time_sec);
  hg->time_sec.chunk.length = htons (sizeof (hg->time_sec));


  /* TIMESTAMP USEC */
  hg->time_usec.chunk.vendor_id = htons (0x0000);
  hg->time_usec.chunk.type_id = htons (0x000a);
  hg->time_usec.data = htonl (rcinfo->time_usec);
  hg->time_usec.chunk.length = htons (sizeof (hg->time_usec));

  /* Protocol TYPE */
  hg->proto_t.chunk.vendor_id = htons (0x0000);
  hg->proto_t.chunk.type_id = htons (0x000b);
  hg->proto_t.data = rcinfo->proto_type;
  hg->proto_t.chunk.length = htons (sizeof (hg->proto_t));

  /* Capture ID */
  hg->capt_id.chunk.vendor_id = htons (0x0000);
  hg->capt_id.chunk.type_id = htons (0x000c);
  hg->capt_id.data = htons (101);
  hg->capt_id.chunk.length = htons (sizeof (hg->capt_id));

  /* Payload */
  payload_chunk.vendor_id = htons (0x0000);
  payload_chunk.type_id = htons (0x000f);
  payload_chunk.length = htons (sizeof (payload_chunk) + len);

  tlen = sizeof (struct hep_generic) + len + iplen + sizeof (hep_chunk_t);

  /* auth key */
  if (capt_password != NULL) {

    tlen += sizeof (hep_chunk_t);
    /* Auth key */
    authkey_chunk.vendor_id = htons (0x0000);
    authkey_chunk.type_id = htons (0x000e);
    authkey_chunk.length = htons (sizeof (authkey_chunk) + strlen (capt_password));
    tlen += strlen (capt_password);
  }

  /* total */
  hg->header.length = htons (tlen);

  buffer = (void *) malloc (tlen);
  if (buffer == 0) {
    fprintf (stderr, "ERROR: out of memory\n");
    free (hg);
    return 1;
  }

  memcpy ((void *) buffer, hg, sizeof (struct hep_generic));
  buflen = sizeof (struct hep_generic);

  /* IPv4 */
  if (rcinfo->ip_family == AF_INET) {
    /* SRC IP */
    memcpy ((void *) buffer + buflen, &src_ip4, sizeof (struct hep_chunk_ip4));
    buflen += sizeof (struct hep_chunk_ip4);

    memcpy ((void *) buffer + buflen, &dst_ip4, sizeof (struct hep_chunk_ip4));
    buflen += sizeof (struct hep_chunk_ip4);
  }
#ifdef USE_IPV6
  /* IPv6 */
  else if (rcinfo->ip_family == AF_INET6) {
    /* SRC IPv6 */
    memcpy ((void *) buffer + buflen, &src_ip4, sizeof (struct hep_chunk_ip6));
    buflen += sizeof (struct hep_chunk_ip6);

    memcpy ((void *) buffer + buflen, &dst_ip6, sizeof (struct hep_chunk_ip6));
    buflen += sizeof (struct hep_chunk_ip6);
  }
#endif

  /* AUTH KEY CHUNK */
  if (capt_password != NULL) {

    memcpy ((void *) buffer + buflen, &authkey_chunk, sizeof (struct hep_chunk));
    buflen += sizeof (struct hep_chunk);

    /* Now copying payload self */
    memcpy ((void *) buffer + buflen, capt_password, strlen (capt_password));
    buflen += strlen (capt_password);
  }

  /* PAYLOAD CHUNK */
  memcpy ((void *) buffer + buflen, &payload_chunk, sizeof (struct hep_chunk));
  buflen += sizeof (struct hep_chunk);

  /* Now copying payload self */
  memcpy ((void *) buffer + buflen, data, len);
  buflen += len;

  /* send this packet out of our socket */
  if (send (homer_sock, buffer, buflen, 0) == -1) {
    printf ("send error\n");
  }

  /* FREE */
  if (buffer)
    free (buffer);
  if (hg)
    free (hg);

  return 1;
}

void
mass_friendlyscanner_kill (char *data)
{

  char *pch, *ports;
  char ip_src[200];
  int start_port = 0, stop_port = 0, st = 0;
  struct sockaddr_in si_other;
  int s, slen = sizeof (si_other);


  if ((pch = strchr (data, ':')) != NULL) {
    st = pch - data;
    snprintf (ip_src, 200, "%.*s", st, data);
    if ((ports = strchr (++pch, '-')) != NULL) {
      stop_port = atoi (++ports);
    }

    start_port = atoi (pch);

    if (stop_port == 0 || stop_port == start_port)
      stop_port = start_port + 1;

    if ((s = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
      printf ("Couldn't open udp socket\n");
      return;
    }

    st = start_port;

    for (; start_port < stop_port; start_port++) {
      //send_kill_to_friendly_scanner(ip_src, start_port);            
      memset ((char *) &si_other, 0, sizeof (si_other));
      si_other.sin_family = AF_INET;
      si_other.sin_port = htons (start_port);
      if (inet_aton (ip_src, &si_other.sin_addr) == 0) {
	fprintf (stderr, "inet_aton() failed\n");
	return;
      }
      if (sendto (s, SIP_CRASH, strlen (SIP_CRASH), 0, (struct sockaddr *) &si_other, slen) == -1) {
	fprintf (stderr, "couldn't send\n");
      }
    }

    close (s);

    printf ("Sent %d packets of death\n", (stop_port - st));
  }
  else {
    usage (-1);
  }

}
