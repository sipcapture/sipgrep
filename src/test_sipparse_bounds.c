/*
 * Regression tests for bounded copies in parse_message().
 * Build (from src/):
 *   gcc -fsanitize=address,undefined -O1 -g -I. \
 *     -o test_sipparse_bounds test_sipparse_bounds.c sipparse.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "include/sipparse.h"

static int failures = 0;

static void
expect (int ok, const char *msg)
{
  if (!ok) {
    fprintf (stderr, "FAIL: %s\n", msg);
    failures++;
  }
}

static void
parse_buf (const char *msg, struct preparsed_sip *psip)
{
  unsigned int bytes_parsed = 0;

  memset (psip, 0, sizeof (*psip));
  parse_message ((unsigned char *) msg, (unsigned int) strlen (msg), &bytes_parsed, psip);
}

int
main (void)
{
  struct preparsed_sip psip;
  char buf[1024];
  char long_reason[301];
  char long_cl[102];

  /* Well-formed reply: reason must parse as "OK". */
  parse_buf ("SIP/2.0 200 OK\r\n"
	     "Call-ID: abc-123\r\n"
	     "CSeq: 1 INVITE\r\n"
	     "Content-Length: 0\r\n"
	     "\r\n", &psip);
  expect (psip.is_method == SIP_REPLY, "valid: is SIP_REPLY");
  expect (psip.reply == 200, "valid: reply 200");
  expect (strcmp (psip.reason, "OK") == 0, "valid: reason OK");
  expect (psip.callid.len > 0 && psip.callid.s != NULL, "valid: callid present");

  /* Oversized reason phrase must truncate, not overflow adjacent callid. */
  memset (long_reason, 'A', sizeof (long_reason) - 1);
  long_reason[sizeof (long_reason) - 1] = '\0';
  snprintf (buf, sizeof (buf),
	    "SIP/2.0 200 %s\r\n"
	    "Call-ID: abc-123\r\n"
	    "CSeq: 1 INVITE\r\n"
	    "Content-Length: 0\r\n"
	    "\r\n", long_reason);
  parse_buf (buf, &psip);
  expect (psip.reply == 200, "long reason: reply 200");
  expect (strlen (psip.reason) == 31, "long reason: truncated to 31");
  expect (strspn (psip.reason, "A") == 31, "long reason: only A's");
  expect (psip.callid.s != NULL && psip.callid.len > 0, "long reason: callid intact");
  expect (psip.callid.len >= 7 && memcmp (psip.callid.s, "abc-123", 7) == 0,
	  "long reason: callid value");

  /* Oversized Content-Length value must not overflow the local buffer. */
  memset (long_cl, '9', sizeof (long_cl) - 1);
  long_cl[sizeof (long_cl) - 1] = '\0';
  snprintf (buf, sizeof (buf),
	    "SIP/2.0 200 OK\r\n"
	    "Call-ID: abc-123\r\n"
	    "CSeq: 1 INVITE\r\n"
	    "Content-Length: %s\r\n"
	    "\r\n", long_cl);
  parse_buf (buf, &psip);
  expect (psip.reply == 200, "long Content-Length: reply 200");
  expect (strcmp (psip.reason, "OK") == 0, "long Content-Length: reason OK");
  expect (psip.callid.s != NULL && psip.callid.len > 0, "long Content-Length: callid intact");

  if (failures) {
    fprintf (stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf ("ok\n");
  return 0;
}
