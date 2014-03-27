/*
 * $Id: getopt.h,v 1.1 2005/02/16 05:14:42 jpr5 Exp $ 
 */

#define _next_char(string)  (char)(*(string+1))

extern char * optarg; 
extern int    optind; 

int getopt(int, char**, char*);

