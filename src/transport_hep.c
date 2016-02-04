/*
 *  sipgrep - Monitoring tools
 * 
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2014-16 (http://www.sipcapture.org)
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
 */

#include <sys/socket.h>
#include <stdlib.h>       
#include <stdio.h>       
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <memory.h>
#include <unistd.h>

#include "include/core_hep.h"
#include "include/transport_hep.h"

int hep_version = 3;
int usessl = 0;
int pl_compress = 0;
/* homer socket */
int homer_sock = 0;

int send_hepv3 (rc_info_t * rcinfo, unsigned char *data, unsigned int len)
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
    src_ip6.chunk.length = htons (sizeof (src_ip6));

    /* DST IPv6 */
    dst_ip6.chunk.vendor_id = htons (0x0000);
    dst_ip6.chunk.type_id = htons (0x0006);
    inet_pton (AF_INET6, rcinfo->dst_ip, &dst_ip6.data);
    dst_ip6.chunk.length = htons (sizeof (dst_ip6));

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

int make_homer_socket (char *url)
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



