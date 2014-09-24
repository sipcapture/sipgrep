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


static unsigned char *packet = NULL;
static unsigned int packet_len = 0;

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


int parse_message(unsigned char *message, unsigned int blen, unsigned int* bytes_parsed, struct preparsed_sip *psip)
{
		unsigned char* new_message = message;
		unsigned int new_len = blen;
		if (blen <= 2 && packet_len == 0) {

			// We seem to be getting garbage packets from
			// from some SIP UACs: skip them altogether.
            *bytes_parsed = blen;
            return 0;
		}
		else if (packet_len > 0) { // content was previously left unparsed.

			new_len = packet_len + blen;
			new_message = malloc(new_len);
			memcpy(new_message, packet, packet_len);
			memcpy(&new_message[packet_len], message, blen);
		}

        int offset, last_offset, ret, cut = 0;
        unsigned char *c;
        unsigned char *tmp, *pch;

        c = new_message;
        last_offset = 0;
        offset = 0;

        /* Request/Response line */
        for (; *c && c-new_message < new_len; c++) {
                if (*c == '\n' && *(c-1) == '\r') {
                        offset = (c + 1) - new_message;
                        break;
                }
        }        
                        
        if(offset == 0) { // likely Sip Message Body only...

            *bytes_parsed = (unsigned int)c-(unsigned int)new_message;
            return 0;
        }

        psip->reply = 0;
        memset(psip->reason, 0, sizeof(psip->reason));
        psip->has_totag = 0;

        tmp = (char *) new_message;

        if(!strncmp("SIP/2.0 ", tmp, 8)) {
                psip->reply = atoi(tmp+8);
                psip->is_method = SIP_REPLY;

                // Extract Response code's reason
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
						else if(!strncmp(tmp, ACK_METHOD, ACK_LEN)) psip->method = ACK_METHOD;
						else if(!strncmp(tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN)) psip->method = SUBSCRIBE_METHOD;
						else if(!strncmp(tmp, PUBLISH_METHOD, PUBLISH_LEN)) psip->method = PUBLISH_METHOD;
						else
							{
								int offset2 = 0;
								unsigned char *c = tmp;
								for (; *c; c++) {
									if (*c == ' ' || (*c == '\n' && *(c-1) == '\r') || c-tmp > 31) {
										offset2 = c - tmp;
										break;
									}
								}
								char method[32] = {0};
								strncpy(method, tmp, offset2);

								printf("UNKNOWN METHOD: %s\n", method);
								psip->method = UNKNOWN_METHOD;
							}
		}
	
        c=new_message+offset;

        char request_line[1024] = {0};
        strncpy(request_line, new_message, offset);
        printf("Request/Response line: %s\n", request_line);

        int contentLengthFound = 0;
        int contentLength = 0;

        for (; *c && c-new_message < new_len; c++) {

        	/* END of Request line and START of all other headers */
        	if (*c == '\r' && *(c+1) == '\n') {        /* end of this line */

				last_offset = offset;
				offset = (c+2) - new_message;

				tmp = (char *) (new_message + last_offset);

				/* BODY */
		        if((offset - last_offset) == 2) {
		        	break; // Done parsing, bail out.
		        }

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
                                      else if(!strncmp(pch, ACK_METHOD, ACK_LEN)) {
                                            psip->transaction = ACK_TRANSACTION;
                                            psip->cseq_method = ACK_METHOD;
                                      }
                                      else if(!strncmp(pch, SUBSCRIBE_METHOD, SUBSCRIBE_LEN)) {
                                            psip->transaction = SUBSCRIBE_TRANSACTION;
                                            psip->cseq_method = SUBSCRIBE_METHOD;
                                      }
                                      else if(!strncmp(pch, PUBLISH_METHOD, PUBLISH_LEN)) {
                                            psip->transaction = PUBLISH_TRANSACTION;
                                            psip->cseq_method = PUBLISH_METHOD;
                                      }
                                      else {
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
                /* Content-Length: */
        	    else if(strncasecmp(tmp, "Content-Length:", 15) == 0) {

        	        contentLengthFound = 1;
            	    int offset4 = 0;
                    unsigned char *c = (tmp+16);
                    for (; *c; c++) {
                    	if (*c == '\n' && *(c-1) == '\r') {
                    		offset4 = c-(tmp+16);
                    		break;
                    	}
                    }
                    char contentLengthStr[32] = {0};
                    strncpy(contentLengthStr, tmp+16, offset4);
                    contentLength = atoi(contentLengthStr);
                }
		    }
        }

        int message_parsed = 1;
        *bytes_parsed = (unsigned int)c+2-(unsigned int)new_message;
        if (contentLengthFound == 0) {

        	// incomplete packet encountered
        	unsigned char *tmp = malloc(new_len);
        	memcpy(tmp, new_message, new_len);

        	if (packet_len)
        	{
				free(packet);
        	}

			packet = tmp;
			packet_len = new_len;
            *bytes_parsed = (unsigned int)c-(unsigned int)new_message;
            message_parsed = 0;
        }
        else if (((unsigned int)c+2-(unsigned int)new_message + contentLength) < new_len) {

            // 2 packets or more merged together encountered
            *bytes_parsed = (unsigned int)c+2-(unsigned int)new_message + contentLength;
        }
        else if (packet) {

            // free up memory
            free(packet);
            packet = NULL;
            packet_len = 0;
            *bytes_parsed = blen;
        }
        else if (blen > *bytes_parsed) {

        	// Skip message body.
        	*bytes_parsed = blen;
        }

        return message_parsed;
}

