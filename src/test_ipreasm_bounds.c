/*
 * Regression tests for IPv4 fragment lengths in the reassembler.
 * Build (from src/):
 *   gcc -fsanitize=address,undefined -O1 -g -I. \
 *     -o test_ipreasm_bounds test_ipreasm_bounds.c ipreasm.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "include/ipreasm.h"

static int failures = 0;

static void
expect (int ok, const char *msg)
{
  if (!ok) {
    fprintf (stderr, "FAIL: %s\n", msg);
    failures++;
  }
}

/* ip_len is the value stored in the header, which may be shorter than the
 * bytes we actually allocate. payload is the number of bytes after a
 * 20-byte header present in the buffer. */
static unsigned char *
make_frag (unsigned ip_len, unsigned ip_off, unsigned ip_id,
	   unsigned payload, unsigned char fill, unsigned *out_len)
{
  unsigned total = 20 + payload;
  unsigned char *p = calloc (1, total);
  struct ip *ip = (struct ip *) p;

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_len = htons (ip_len);
  ip->ip_id = htons (ip_id);
  ip->ip_off = htons (ip_off);
  ip->ip_ttl = 64;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src.s_addr = htonl (0x0a000001);
  ip->ip_dst.s_addr = htonl (0x0a000002);
  if (payload)
    memset (p + 20, fill, payload);
  *out_len = total;
  return p;
}

static void
free_if_returned (unsigned char *in, unsigned char *out)
{
  if (out == NULL)
    return;
  free (out == in ? in : out);
}

int
main (void)
{
  struct reasm_ip *reasm;
  unsigned char *bad, *first, *last, *out;
  unsigned bad_len, first_len, last_len, out_len;
  const reasm_time_t ts = 1000;

  expect (sizeof (struct ip) == 20, "IPv4 header is 20 bytes");

  /* Legitimate 8 + 8 byte reassembly still produces one packet. */
  reasm = reasm_ip_new ();
  reasm_ip_set_timeout (reasm, 1000000);
  first = make_frag (28, IP_MF, 1, 8, 'A', &first_len);
  out = reasm_ip_next (reasm, first, first_len, ts, &out_len);
  expect (out == NULL, "first fragment waits");
  last = make_frag (28, 1, 1, 8, 'B', &last_len);
  out = reasm_ip_next (reasm, last, last_len, ts, &out_len);
  expect (out != NULL && out != last, "two fragments reassemble");
  expect (out_len == 36, "reassembled length is header + 16");
  if (out != NULL && out_len >= 36) {
    expect (memcmp (out + 20, "AAAAAAAABBBBBBBB", 16) == 0, "reassembled payload");
    free (out);
  }
  reasm_ip_free (reasm);

  /* ip_len shorter than the header must not be reassembled with a neighbour. */
  reasm = reasm_ip_new ();
  reasm_ip_set_timeout (reasm, 1000000);
  bad = make_frag (12, 1, 2, 0, 0, &bad_len);
  out_len = 0;
  out = reasm_ip_next (reasm, bad, bad_len, ts, &out_len);
  expect (out == bad, "short ip_len is not a fragment");
  expect (out_len == bad_len, "short ip_len keeps the captured length");
  free_if_returned (bad, out);

  first = make_frag (28, IP_MF, 2, 8, 'A', &first_len);
  out = reasm_ip_next (reasm, first, first_len, ts, &out_len);
  expect (out == NULL, "valid fragment after a short ip_len waits");
  last = make_frag (28, 1, 2, 8, 'B', &last_len);
  out = reasm_ip_next (reasm, last, last_len, ts, &out_len);
  expect (out != NULL && out != last, "valid pair still reassembles");
  expect (out_len == 36, "valid pair length");
  if (out != NULL && out_len >= 36) {
    expect (memcmp (out + 20, "AAAAAAAABBBBBBBB", 16) == 0, "valid pair payload");
    free (out);
  }
  reasm_ip_free (reasm);

  if (failures) {
    fprintf (stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf ("ok\n");
  return 0;
}
