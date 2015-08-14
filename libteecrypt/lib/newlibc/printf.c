/* 
 * Copyright (C) 2013 - 2014 TrustKernel Team - All Rights Reserved
 *
 * This file is part of T6.
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * A full copy of license could be obtained from 
 *
 * 		http://www.trustkernel.org/license/license.txt
 *
 * Written by Wenhao Li <liwenhaosuper@gmail.com>
 *
 */
#include "types.h"
#include "stat.h"
#include "user.h"

/*  move to  "mytypes.h"

#define  ALIGNBND           (sizeof (signed int) - 1)
#define bnd(X, bnd)         (((sizeof (X)) + (bnd)) & (~(bnd)))
#define va_arg(ap, T)  (*(T *)(((ap) += (bnd (T, ALIGNBND))) - (bnd (T,ALIGNBND))))
*/

static void
putc(int fd, char c)
{
    write(fd, &c, 1);
}

static void
printint(int fd, int xx, int base, int sgn)
{
    static char digits[] = "0123456789ABCDEF";
    char buf[16];
    int i, neg;
    uint x;
    
    neg = 0;
    if(sgn && xx < 0){
        neg = 1;
        x = -xx;
    } else {
        x = xx;
    }
    
    i = 0;
    do{
        buf[i++] = digits[x % base];
    }while((x /= base) != 0);
    if(neg)
        buf[i++] = '-';
    
    while(--i >= 0)
        putc(fd, buf[i]);
}

void 
uvsprintf(char *buf, const char *fmt, char* args){
	char *str;
	str = buf;
	for(; *fmt ; ++fmt){
		if((*fmt != '%') && (*fmt != '\n') && (*fmt != '\t')){
			*str++ = *fmt;
			continue;
		}
		if(*fmt == '%'){
			/* skip % */
			++fmt;
			unsigned int is_unsigned = 0;
			unsigned int zero_padding = 1;
			if(*fmt == '0'){
				/* zero padding!*/
				/* skip 0 */
				++fmt;
				zero_padding = *fmt++;
				if((zero_padding < 0x31) || (zero_padding > 0x38)){
					//invalid padding bits
				}
				zero_padding -= 0x30;
			}
			switch(*fmt){
			case 'l':{   
					++fmt;
					break;
				}
			}
			switch(*fmt){
			case 'x':{   
					unsigned int number = va_arg(args, int);
					int length = 8;
					int length_in_bits = 32;
					int byte = 0;
					int i = 0;
					int keep_zeros = 0;

					for(i = 0; i < length; i++){
						byte = number >> (length_in_bits - ((i+1) * 4));
						byte = byte & 0xF;
						if(byte != 0){
							keep_zeros = 1;
						}
						if(keep_zeros || i >= (7-(zero_padding-1))){
							if((byte >= 0) && (byte <= 9)){
								byte = byte + 0x30;
							}
							else{
								switch(byte){
								case 0xa:
									byte = 0x61;
									break;
								case 0xb:
									byte = 0x62;
									break;
								case 0xc:
									byte = 0x63;
									break;
								case 0xd:
									byte = 0x64;
									break;
								case 0xe:
									byte = 0x65;
									break;
								case 0xf:
									byte = 0x66;
									break;
								} /* switch ends */
							} /* else ends */
							*str++ = byte;
						}
					} /* for ends - whole number is now done */
					break;
				}
			case 'u':
				is_unsigned = 1;
			case 'i':
			case 'd':
				{   
					unsigned int i,j,max_num_zeros,num_of_digits_u32,number_u32,
								 divisor_value_u32,new_div_val = 1,sw_quotient_value = 0;
					int keep_zeros = 0;

					if(!is_unsigned){
						int signed_num_32 = va_arg(args,int);
						if(signed_num_32 < 0){
							*str++ = 0x2d;
							signed_num_32 = -(signed_num_32);
						}
						number_u32 = (unsigned int)signed_num_32;
					}
					else{
						unsigned int unsigned_value_32 = va_arg(args,unsigned int);
						number_u32 = unsigned_value_32;
					}

					divisor_value_u32 = 1000000000;
					num_of_digits_u32 = 10;
					max_num_zeros = num_of_digits_u32 - 1;

					for(i = 0; i < max_num_zeros; i++){
						while(number_u32 >= divisor_value_u32){
							number_u32 -= divisor_value_u32;
							++sw_quotient_value;
						}
						if(sw_quotient_value != 0)
							keep_zeros = 1;
						if(keep_zeros || i > ((max_num_zeros-1)-(zero_padding-1))){
							sw_quotient_value += 0x30;
							*str++ = sw_quotient_value;
						}
						j = i;
						while(j < (max_num_zeros-1)){
							new_div_val *= 10;
							j++;
						}
						sw_quotient_value = 0;
						divisor_value_u32 = new_div_val;
						new_div_val = 1;
					}
					*str++ = (number_u32 + 0x30);
					break;
				}
			case 'o':{   
					unsigned int number,length = 10,length_in_bits = 32,byte = 0,i = 0;
					int keep_zeros = 0;

					number = va_arg(args, int);
					byte = number >> 30;
					byte &= 0x3;
					if(byte != 0){
						keep_zeros = 1;
					}
					if(keep_zeros || zero_padding > length){
						byte = byte + 0x30;
						*str++ = byte;
					}

					number <<= 2;
					for(i = 0; i < length; i++){
						byte = number >> (length_in_bits - ((i+1) * 3));
						byte &= 0x7;
						if(byte != 0){
							keep_zeros = 1;
						}
						if(keep_zeros || i >= (9-(zero_padding-1))){
							byte = byte + 0x30;
							*str++ = byte;
						}
					}
					break;
				}
			case 's':
				{
					char *arg_string = va_arg(args, char *);
					while((*str = *arg_string++)){
						++str;
					}
					break;
				}
			case 'c':
				{
					char character = va_arg(args, char);
					*str++ = character;
					break;
				}
			case '%':
				{
					*str++ = *fmt;
					break;
				}
			case '\t':
				{
					*str++ = '%';
					*str++ = *fmt;
					break;
				}
			case '\n':
				{   
					*str++ = '%';
					*str++ = '\r';
					*str++ = '\n';
					break;
				}
			default:{}
			} /* switch ends             */
		} /* if % character found      */

		if(*fmt == '\n'){
			*str++ = '\r';
			*str++ = '\n';
		}
		if(*fmt == '\t')
			*str++ = *fmt;
	} /* for ends */
	*str = '\0';
	return ;

}


// Print to the given fd. Only understands %d, %x, %p, %s.
void
uprintf(int fd, char *fmt, ...)
{
    char *s;
    int c, i, state;
    uint *ap;
    
    state = 0;
    ap = (uint*)(void*)&fmt + 1;
    for(i = 0; fmt[i]; i++){
        c = fmt[i] & 0xff;
		if(c == '\n'){
			putc(fd,'\r');
			putc(fd,'\n');
			continue;
		}
        if(state == 0){
            if(c == '%'){
                state = '%';
            } else {
                putc(fd, c);
            }
        } else if(state == '%'){
            if(c == 'd'){
                printint(fd, *ap, 10, 1);
                ap++;
            } else if(c == 'x' || c == 'p'){
                printint(fd, *ap, 16, 0);
                ap++;
            } else if(c == 's'){
                s = (char*)*ap;
                ap++;
                if(s == 0)
                    s = "(null)";
                while(*s != 0){
                    putc(fd, *s);
                    s++;
                }
            } else if(c == 'c'){
                putc(fd, *ap);
                ap++;
            } else if(c == '%'){
                putc(fd, c);
            } else {
                // Unknown % sequence.  Print it to draw attention.
                putc(fd, '%');
                putc(fd, c);
            }
            state = 0;
        }
    }
}



/********************** append ***************************/


#ifndef STDOUT
#define STDOUT	1
#endif


/* zero padding on left !*/
static int
printint_zpad(int fd, int xx, int base, int sgn, int zero_padding)
{
    static char digits[] = "0123456789ABCDEF";
    char buf[16];
    int i, neg;
    uint x;
    int count = 0;

    neg = 0;
    if(sgn && xx < 0){
        neg = 1;
        x = -xx;
    } else {
        x = xx;
    }
    
    i = 0;
    do{
        buf[i++] = digits[x % base];
    }while((x /= base) != 0);
    while(i < zero_padding) {
    	buf[i++] = '0';
    }
    if(neg) {
        buf[i++] = '-';
    }
    count = i;
    while(--i >= 0)
        putc(fd, buf[i]);

    return count;
}

// Only understands %d, %x, %p, %s.
void
printf(char *fmt, ...)
{
	int fd;
    char *s;
    int c, i, state;
    uint *ap;
	int zero_padding = 1;
	char *err_padding = "error printf padding: ";

    fd = STDOUT;
    state = 0;
    ap = (uint*)(void*)&fmt + 1;

    for(i = 0; fmt[i]; i++){
        c = fmt[i] & 0xff;
		if(c == '\n'){
			putc(fd,'\r');
			putc(fd,'\n');
			continue;
		}
        if(state == 0){
            if(c == '%'){
                state = '%';
            } else {
                putc(fd, c);
            }
        } else if(state == '%'){
        	/* zero padding on left !*/
			if(c == '0'){
				/* skip 0 */
				zero_padding = fmt[++i];
				if((zero_padding < 0x31) || (zero_padding > 0x38)){
					//invalid padding bits
					putc(fd,'\n');
					while(*err_padding != 0){
						putc(fd, *err_padding);
						err_padding++; 
					}
					putc(fd, '0');putc(fd, zero_padding);putc(fd, '\n');
					exit(0);
				}
				zero_padding -= 0x30;
				continue;
			}
			else if(c == 'd'){
				printint_zpad(fd, *ap, 10, 1, zero_padding);
                //printint(fd, *ap, 10, 1);
                ap++;
            } 
            else if(c == 'x' || c == 'p'){
            	printint_zpad(fd, *ap, 16, 0, zero_padding);
                //printint(fd, *ap, 16, 0);
                ap++;
            } 
            else if(c == 's'){
                s = (char*)*ap;
                ap++;
                if(s == 0)
                    s = "(null)";
                while(*s != 0){
                    putc(fd, *s);
                    s++;
                }
            } 
            else if(c == 'c'){
                putc(fd, *ap);
                ap++;
            } 
            else if(c == '%'){
                putc(fd, c);
            } 
            else {
                // Unknown % sequence.  Print it to draw attention.
                putc(fd, '%');
                putc(fd, c);
            }
            state = 0;
        }

    }

}