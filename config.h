/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/* pseudo-user for running sipgrep (default "nobody") */
#define DROPPRIVS_USER "nobody"

/* presence of DLT_IEEE802_11 in bpf.h */
#define HAVE_DLT_IEEE802_11 0

/* presence of DLT_IEEE802_11_RADIO in bpf.h */
#define HAVE_DLT_IEEE802_11_RADIO 0

/* presence of DLT_LINUX_SLL in bpf.h */
#define HAVE_DLT_LINUX_SLL 0

/* presence of DLT_LOOP in bpf.h */
#define HAVE_DLT_LOOP 0

/* presence of DLT_RAW in bpf.h */
#define HAVE_DLT_RAW 0

/* whether to accommodate broken redhat-glibc udphdr declaration (default no)
   */
#define HAVE_DUMB_UDPHDR 0

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `pcap' library (-lpcap). */
#define HAVE_LIBPCAP 1

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "http://www.sipcapture.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "sipgrep"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "sipgrep trunk"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "sipgrep"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "trunk"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* whether to use privileges dropping (default yes) */
#define USE_DROPPRIVS 1

/* whether to use IPv6 (default off) */
#define USE_IPv6 0

/* whether to call pcap_restart() before subsequent invocations of
   pcap_compile() (default yes) */
#define USE_PCAP_RESTART 1

/* whether to use PCRE (default GNU Regex) */
#define USE_PCRE 0
