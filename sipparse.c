/*
 *
 *  sipgrep - Monitoring tools
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2014 (http://www.sipcapture.org)
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
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>       
#include "sipparse.h"


int set_hname(str *hname, int len, char *s) {
                
        char *end;

        if(hname->len  > 0) {
                return 0;
        }		
	
        end = s + len;
        for(; s < end; s++) {
                len--;
                if ((*s != ' ') && (*s != ':') && (*s != '\t')) {
                        len--;
                        break;
                }
        }           
        
        hname->s = s;        
        hname->len = len;        
        return 1;
}


int parse_request(unsigned char *body, unsigned int blen, struct preparsed_sip *psip)
{
        int offset, last_offset, ret, cut = 0;
        unsigned char *c;
        unsigned char *tmp, *pch;
              

	if (blen <= 100 ) {
                //printf("ERROR: parse_first_line: message too short: %ui\n", blen);
		return 0;
        }
                
        c = body;
        last_offset = 0;
        offset = 0;

        /* FIRST LINE */
        for (; *c; c++) {
                if (*c == '\n' && *(c-1) == '\r') {       
                        offset = (c +1) - body;
                        break;
                }
        }        
                        
        if(offset == 0) {
                printf("BAD tmp[%s] BLEN: [%d]", body, blen);                                
                return 0;
        }
        else if(offset < 10) {
                printf("BAD tmp: too short: %d == [%s]", offset, body);                                
                return 0;
        }

        psip->reply = 0;
        memset(psip->reason, 0, sizeof(psip->reason));
        psip->has_totag = 0;

        tmp = (char *) body;

        if(!strncmp("SIP/2.0 ", tmp, 8)) {
                psip->reply = atoi(tmp+8);
                psip->is_method = SIP_REPLY;
                unsigned char *reason = tmp+12;
                for (; *reason; reason++) {
                        if (*reason == '\n' && *(reason-1) == '\r') {
                                break;
                        }
                }
                strncpy(psip->reason, tmp+12, reason-(tmp+12));
                
	}
        else {
                psip->is_method = SIP_REQUEST;
                
		if(!strncmp(tmp, REGISTER_METHOD, REGISTER_LEN)) psip->method = REGISTER_METHOD;    
                else if(!strncmp(tmp, INVITE_METHOD, INVITE_LEN)) psip->method = INVITE_METHOD;
                else if(!strncmp(tmp, BYE_METHOD, BYE_LEN)) psip->method = BYE_METHOD;
                else if(!strncmp(tmp, CANCEL_METHOD, CANCEL_LEN)) psip->method = CANCEL_METHOD;
                else if(!strncmp(tmp, NOTIFY_METHOD, NOTIFY_LEN)) psip->method = NOTIFY_METHOD;
                else if(!strncmp(tmp, OPTIONS_METHOD, OPTIONS_LEN)) psip->method = OPTIONS_METHOD;
                else
                	{
                		printf("UNKNOW METHOD: %s", tmp);
                		psip->method = UNKNOWN_METHOD;
                	}
	}
	
        c=body+offset;

        for (; *c; c++) {
                /* END MESSAGE and START BODY */        
        	if (*c == '\r' && *(c+1) == '\n') {        /* end of this line */

       	                last_offset = offset;
                        offset = (c+2) - body;
                       
       	                tmp = (char *) (body + last_offset);                                                                        

       	                /* BODY */                
		        if((offset - last_offset) == 2) return 1;

                        /* To tag */
		        if((*tmp == 'T' && *(tmp+1) == 'o' && *(tmp+TO_LEN) == ':') || (*tmp == 't' && *(tmp+1) == ':')) {

		                if(!strncmp(tmp, "tag=", 4)) psip->has_totag = 1;

		                if( *(tmp+1) == ':') cut = 2;
		                else cut = TO_LEN;                              
		                
		                ret = set_hname(&psip->to, (offset - last_offset - cut), tmp+cut);
                        }                                                                                                                                          
                        else if (((*tmp == 'U' || *tmp == 'u') && (*(tmp + 4) == '-' || *(tmp + 4) == '-') && (*(tmp + 5) == 'A' || *(tmp + 4) == 'a') && *(tmp + USERAGENT_LEN) == ':')) {                        
				ret = set_hname(&psip->uac, (offset - last_offset - USERAGENT_LEN), tmp + USERAGENT_LEN);
			}
                        else if((*tmp == 'F' && *(tmp+1) == 'r' && *(tmp+2) == 'o' && *(tmp+FROM_LEN) == ':') || (*tmp == 'f' && *(tmp+1) == ':')) {

                              if( *(tmp+1) == ':') cut = 2;
                              else cut = FROM_LEN;                              
                              ret = set_hname(&psip->from, (offset - last_offset - cut), tmp+cut);
                                                                                    
                        }
                        /* CSeq: 21 INVITE */
                        else if(*tmp == 'C' && *(tmp+1) == 'S' && *(tmp+CSEQ_LEN) == ':') {

                                if((pch = strchr((tmp+CSEQ_LEN+2),' ')) != NULL) {

                                      pch++;

                                      if(!strncmp(pch, INVITE_METHOD, INVITE_LEN)) {
                                            psip->transaction = INVITE_TRANSACTION;                            
                                            psip->cseq_method = INVITE_METHOD;                                              
                                      }
                                      else if(!strncmp(pch, REGISTER_METHOD, REGISTER_LEN)) {
                                            psip->transaction = REGISTER_TRANSACTION;                                                        
                                            psip->cseq_method = REGISTER_METHOD;                                                                
                                      }
                                      else if(!strncmp(pch, BYE_METHOD, BYE_LEN)) {
                                            psip->transaction = BYE_TRANSACTION;                                                                          
                                            psip->cseq_method = BYE_METHOD; 
                                      }
                                      else if(!strncmp(pch, CANCEL_METHOD, CANCEL_LEN)) {
                                            psip->transaction = CANCEL_TRANSACTION;                                                                          
                                            psip->cseq_method = CANCEL_METHOD; 
                                      }
                                      else if(!strncmp(pch, NOTIFY_METHOD, NOTIFY_LEN)) {
                                            psip->transaction = NOTIFY_TRANSACTION;
                                            psip->cseq_method = NOTIFY_METHOD;
                                      }
                                      else if(!strncmp(pch, OPTIONS_METHOD, OPTIONS_LEN)) {
                                            psip->transaction = OPTIONS_TRANSACTION;
                                            psip->cseq_method = OPTIONS_METHOD;
                                      }
                                      else {
                                    	    printf("UNKNOW METHOD: %s", pch);
                                            psip->transaction = UNKNOWN_TRANSACTION;
                                            psip->cseq_method = UNKNOWN_METHOD;
                                      }                                                                
      
                                      psip->cseq_num = atoi(tmp+CSEQ_LEN+1);                                      
                              }
                                                                
                        }  
                	/* Call-ID: */
        	        else if(*tmp == 'C' && (*(tmp+5) == 'I' || *(tmp+5) == 'i') && *(tmp+CALLID_LEN) == ':') {
        	              
                              ret = set_hname(&psip->callid, (offset - last_offset - CALLID_LEN), tmp+CALLID_LEN);                                                                                         
                               
                              /* if(psip->callid.len > 6 && !strncmp(psip->callid.s + (psip->callid.len - 6), "_b2b-1", 6)) {
                                         psip->callid.len-=6;
                              }  
                              */                         
                        }
		}
        }                        

        return 1;
}

