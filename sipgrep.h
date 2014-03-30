#ifndef _SIPGREP_H
#define _SIPGREP_H

/*
 * sipgrep.h, v 2.0 2014/03/18    
 *
 * Copyright (c) 2013-14  Alexandr Dubovikov <alexandr.dubovikov@gmail.com> 
 *
 * Partly base on NGREP of:
 *
 * Copyright (c) 2006  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#define VERSION "2.01b"

/*
 * We cache the standard frame sizes here to save us time and
 * additional dependencies on more operating system include files.
 */

#define ETHHDR_SIZE 14
#define TOKENRING_SIZE 22
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#define ISDNHDR_SIZE 16
#define IEEE80211HDR_SIZE 32

/*
 * Default patterns for BPF and regular expression filters.
 */

#if USE_IPv6
#define BPF_FILTER_IP       "(ip or ip6)"
#else
#define BPF_FILTER_IP       "(ip)"
#endif

#define BPF_FILTER_OTHER    " and ( %s)"
#define BPF_MAIN_FILTER     BPF_FILTER_IP BPF_FILTER_OTHER

#define BPF_FILTER_PORTRANGE    " and ( portrange %s)"
#define BPF_MAIN_PORTRANGE_FILTER    BPF_FILTER_IP BPF_FILTER_PORTRANGE

#define BPF_DEFRAGMENTION_FILTER BPF_MAIN_PORTRANGE_FILTER " or (udp and ip[6:2] & 0x3fff != 0)"

#define WORD_REGEX "((^%s\\W)|(\\W%s$)|(\\W%s\\W))"

/*
 * For retarded operating systems like Solaris that don't have this,
 * when everyone else does.  Good job, Sun!
 */

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

/*
 * "Newer" flags that older operating systems don't yet recognize.
 */

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#define SIP_FROM_MATCH "(From:|f:) (.*)%s(.*)"
#define SIP_TO_MATCH "(To:|t:) (.*)%s(.*)"
#define SIP_CONTACT_MATCH "(Contact:|c:) (.*)%s(.*)"
#define SIP_REPLY_MATCH "^SIP/2.0 %s"
#define SIP_FROM_TO_MATCH "(" SIP_FROM_MATCH "|" SIP_TO_MATCH ")"

/* colors */
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define DURATION_SPLIT 1
#define FILESIZE_SPLIT 2

/*
 * Single-char packet "ident" flags.
 */

typedef enum {
    TCP = 'T', UDP = 'U', ICMP = 'I', ICMPv6 = 'I', IGMP = 'G', UNKNOWN = '?'
} netident_t;

/*
 * Prototypes function signatures.
 */

void process(u_char *, struct pcap_pkthdr *, u_char *);

void version(void);
void usage(int8_t);
void clean_exit(int32_t);

void dump_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, uint32_t,
                 const char *, const char *, uint16_t, uint16_t, uint8_t,
                 uint16_t, uint8_t, uint16_t, uint32_t,  uint32_t);

void dump_unwrapped(unsigned char *, uint32_t);
void dump_formatted(unsigned char *, uint32_t);
void dump_byline   (unsigned char *, uint32_t);

void dump_delay_proc_init(struct pcap_pkthdr *);
void dump_delay_proc     (struct pcap_pkthdr *);

int8_t re_match_func   (unsigned char *, uint32_t);
int8_t bin_match_func  (unsigned char *, uint32_t);
int8_t blank_match_func(unsigned char *, uint32_t);

void print_time_absolute(struct pcap_pkthdr *);
void print_time_diff    (struct pcap_pkthdr *);

char *get_filter_from_string(char *);
char *get_filter_from_argv  (char **);
char *get_filter_from_portrange(char *);

void create_dump(unsigned int now);

/* Call ID extract */
int extract_callid(char *msg, int len);


uint8_t strishex(char *);

void update_windowsize(int32_t);
void drop_privs(void);

int parse_stop_request(char *request);
int parse_split_request(char *request);
int check_split_deadline(unsigned int now);
int check_exit_deadline(unsigned int now);


struct SIPGREP_rtaphdr_t {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

/* HASH table */
struct callid_table {
    char callid[256];             /* key (string is WITHIN the structure) */
    uint32_t transaction;
    uint32_t init_cseq;
    uint8_t terminated;
    uint16_t termination_reason;
    uint32_t cdr_init;
    uint32_t cdr_ringing;
    uint32_t cdr_connect;
    uint32_t cdr_disconnect;
    uint8_t registered;
    char from[256];
    char to[256];
    char uac[256];
    UT_hash_handle hh;         /* makes this structure hashable */
};


/* HASH table */
struct callid_remove {
    char callid[256];             /* key (string is WITHIN the structure) */
    int removed;
    int time;
    UT_hash_handle hh;         /* makes this structure hashable */
};


void delete_dialogs_remove_element (char *callid);
void delete_dialogs_element (char *callid);
void check_dialogs_delete ();
void print_dialogs_stats(struct callid_table *s);
void clear_all_dialogs_element();
void send_kill_to_friendly_scanner(const char *ip, uint16_t port);
int make_homer_socket(char *url);
int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);

#define SIP_CRASH "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 8.7.6.5:5061;branch=z9hG4bK-573841574;rport\r\n\r\nContent-length: 0\r\n" \
		  "From: \"100\"<sip:100@localhost>; tag=683a653a7901746865726501627965\r\nUser-agent: Telkom Box 2.4\r\n" \
		  "To: \"100\"<sip:100@localhost>\r\nCseq: 1 REGISTER\r\nCall-id: 469585712\r\nMax-forwards: 70\r\n\r\n"

                                                       
                                                        
#endif /* _SIPGREP_H */
