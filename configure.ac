AC_PREREQ(2.61)
AC_INIT(sipgrep,2.2.1,support@sipcapture.org,,[http://www.sipcapture.org])
AC_COPYRIGHT("SIP Capture Solution")
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign tar-ustar)
AC_CONFIG_HEADERS([src/config.h])
AC_MSG_CHECKING([whether to use compression])
enableCompression=no
AC_ARG_ENABLE(compression,
   [  --enable-compression	Enable compression support)],
   [ZLIB="$enableval"]
   enableCompression=yes,
   [ZLIB="no"]
)
AC_MSG_RESULT([$ZLIB])
AC_SUBST([ZLIB])

AC_MSG_CHECKING([whether to use ssl])
enableSSL=no
AC_ARG_ENABLE(ssl,
   [  --enable-ssl		Enable SSL support)],
   [SSL="$enableval"]
   enableSSL=yes,
   [SSL="no"]
)
AC_MSG_RESULT([$SSL])
AC_SUBST([SSL])

usePCRE2=yes
AC_SUBST([PCRE2])

useNCURSES=no
AC_MSG_CHECKING([whether to use ncurses])
AC_ARG_ENABLE(ncurses,
   [  --enable-ncurses		Enable ncurses support)],
   [NCURSES="$enableval"]
   useNCURSES=yes,
   [NCURSES="no"]
)
AC_MSG_RESULT([$NCURSES])
AC_SUBST([NCURSES])


useRedis=no
AC_MSG_CHECKING([whether to use redis])
AC_ARG_ENABLE(redis,
   [  --enable-redis		Enable redis support)],
   [REDIS="$enableval"]
   useRedis=yes,
   [REDIS="no"]
)
AC_MSG_RESULT([$REDIS])
AC_SUBST([REDIS])

dnl
dnl IPv6 (and ICMPv6) support
dnl

AC_ARG_ENABLE(ipv6,
[  --enable-ipv6		enable IPv6 (and ICMPv6) support],
[ 
  use_ipv6="$enableval"
],
[ 
  use_ipv6="no"
]) 

if test $use_ipv6 = yes; then
   AC_DEFINE(USE_IPv6, [1], [IPv6 (and ICMPv6) support])
   AC_SUBST(USE_IPv6, yes)
fi


enableHEP=yes
dnl
dnl HEP/EEP support
dnl

AC_ARG_ENABLE(hep,
[  --disable-hep		disable HEP/EEP support],
[ 
  use_hep="no"
],
[ 
  use_hep="yes"
]) 

if test $use_hep = yes; then
   AC_DEFINE(HAVE_HEP, 1, [HEP support])           
   AC_SUBST(HAVE_HEP, yes)   
else
   AC_DEFINE(HAVE_HEP, 0, [no HEP support])           
   AC_SUBST(HAVE_HEP, no)   
   enableHEP=no  
fi


CONFIG_CFLAGS="${CFLAGS}"
CONFIG_LDFLAGS="${LDFLAGS}"

MODULES='$$(grep -v "\#" $(sipgrep_builddir)/modules.list | sed -e "s|^.*/||" | sort | uniq )'
AM_MAKEFLAGS='"OUR_MODULES=$(MODULESS)" `test -n "$(VERBOSE)" || echo -s`'
AC_SUBST(OUR_MODS)

#AC_ENABLE_SHARED(yes)
#AC_ENABLE_STATIC(no)

#AC_CANONICAL_SYSTEM
#AM_INIT_AUTOMAKE()

LT_INIT

AC_CANONICAL_HOST
case "${host}" in
  *-*-darwin*)
        AC_DEFINE([OS_DARWIN], [1], [Define to 1 if Operating System is Darwin])
        AC_SUBST(OS_DARWIN, 1)
        ;;
  *-*-freebsd*)
        AC_DEFINE([OS_FREEBSD], [1], [Define to 1 if Operating System is FreeBSD])
        AC_SUBST(OS_FREEBSD, 1)
        ;;
  *-*-linux*)
        AC_DEFINE([OS_LINUX], [1], [Define to 1 if Operating System is Linux])
        AC_SUBST(OS_LINUX, 1)
        ;;
  *-*-netbsd*)
        AC_DEFINE([OS_NETBSD], [1], [Define to 1 if Operating System is NETBSD])
        AC_SUBST(OS_NETBSD, 1)
        ;;
  *-*-solaris*)
        AC_DEFINE([OS_SOLARIS], [1], [Define to 1 if Operating System is SOLARIS])
        AC_SUBST(OS_SOLARIS, 1)
        AC_CHECK_LIB(socket, socket,,
                     echo no socket in -lsocket\?; exit)
        AC_CHECK_LIB(nsl, gethostbyname,,
                     echo no gethostbyname in -lnsl\?; exit)

        EXTRA_LIBS="$EXTRA_LIBS -lnsl -lsocket"
        ;;
  *)
        AC_MSG_RESULT([Unsupported operating system: ${host}])
        ;;
esac

# Checks for programs
AC_PROG_CC
# AC_PROG_CC([gcc cc])

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

EXTRA_DEFINES="$EXTRA_DEFINES -D_BSD_SOURCE=1 -D__FAVOR_BSD=1"

# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create, , [AC_MSG_ERROR([sipgrep requires but cannot find pthread])])
if test "$OS_LINUX" = 1 ; then
  AC_CHECK_LIB(dl, dlopen, , [AC_MSG_ERROR([sipgrep requires but cannot find libdl])])
fi

AC_CHECK_LIB(pcap, pcap_open_live, ,[AC_CHECK_LIB(wpcap, pcap_open_live, ,[AC_MSG_ERROR([sipgrep requires but cannot find libpcap])])])

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(DL_LIBS)
AC_SUBST(PCAP_LIBS)


dnl
dnl check for pcre2 library
dnl

# Checks for libpcre2
AC_CHECKING([for pcre2 Library and Header files])
AC_CHECK_HEADER([pcre2.h], ,AC_MSG_ERROR([Could not find pcre2 headers !]), [#define PCRE2_CODE_UNIT_WIDTH 8])
AC_CHECK_LIB([pcre2-8], [pcre2_compile_8], ,[AC_MSG_ERROR([libpcre2 required])])
AC_DEFINE(USE_PCRE2, 1, [Use PCRE2 library])
AC_SUBST(PCRE2_LIBS)


dnl
dnl check for ncurses library
dnl

# Checks for ncurses
if test "$NCURSES" = "yes"; then
	AC_CHECKING([for ncurses Library and Header files])
	AC_CHECK_HEADER([ncurses.h], ,AC_MSG_ERROR([Could not find ncurses headers !]))
	AC_CHECK_LIB([ncurses], [initscr],, [AC_MSG_ERROR([libncurses required])])
	AC_DEFINE(USE_NCURSES, 1, [Use NCURSES library])
	AC_SUBST(NCURSES_LIBS)
	AC_SUBST(USE_NCURSES, yes)   
fi


dnl
dnl check for compression library
dnl
   
if test "$ZLIB" = "yes"; then
   AC_CHECKING([for zip Library and Header files])
   AC_CHECK_HEADER(zlib.h,,[AC_MSG_ERROR([zlib.h headers not found.])])
   AC_CHECK_LIB(z, inflate, , [AC_MSG_ERROR([sipgrep requires but cannot find lz])])
   AC_DEFINE(USE_ZLIB, 1, [Use ZIP library])
fi

dnl
dnl check for redis library
dnl
   
if test "$REDIS" = "yes"; then
   AC_CHECKING([for redis Library and Header files])
   AC_CHECK_HEADER(hiredis/hiredis.h,,[AC_MSG_ERROR([hiredis/hiredis.h headers not found.])])
   AC_CHECK_LIB(hiredis, redisCommand, , [AC_MSG_ERROR([sipgrep requires but cannot find lhiredis])])
   AC_DEFINE(USE_REDIS, 1, [Use REDIS library])
   AC_SUBST(HIREDIS_LIBS)
fi


dnl
dnl check for OpenSSL-SSL library
dnl

if test "$SSL" = "yes"; then
   AC_CHECKING([for OpenSSL SSL Library and Header files])
   AC_CHECK_HEADER(openssl/ssl.h,, [AC_MSG_ERROR([OpenSSL SSL headers not found.])])	
   AC_CHECK_LIB(ssl, SSL_accept, , [AC_MSG_ERROR([sipgrep requires but cannot find ssl])])
   AC_DEFINE(USE_SSL, 1, [Use OpenSSL SSL library])
fi

# Checks for header files.
AC_CHECK_HEADER(pcap.h,,[AC_MSG_ERROR([sipgrep cannot find pcap.h])])

# conditional checks
AM_CONDITIONAL([HAVE_HEP],[test "x$HAVE_HEP" == "xyes"])
AM_CONDITIONAL([USE_NCURSES],[test "x$USE_NCURSES" == "xyes"])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset select socket strdup strerror strndup])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT


echo
echo $PACKAGE $VERSION
echo
echo Build directory............. : $sipgrep_builddir
echo Installation prefix......... : $prefix
echo IPv6 support.................: $use_ipv6
echo HEP support................. : $enableHEP
echo HEP Compression............. : $enableCompression
echo SSL/TLS..................... : $enableSSL
echo Ncurses support............. : $useNCURSES

echo
echo Build with REDIS............ : $useRedis
echo Build with PCRE............. : $usePCRE2
echo

