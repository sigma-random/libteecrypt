#include <tee_config.h>


/*
#ifndef VALIST 
#define VALIST 
typedef char *va_list; 
#endif 


#define  _AUPBND        ( sizeof (signed int) - 1 ) 
#define  _ADNBND        ( sizeof (signed int) - 1 ) 

#define _ALIGN_BND      ( sizeof (_AUPBND) - 1 )
#define _BND(X, bnd)    ( ((sizeof (X)) + (bnd)) & (~(bnd)) )
#define _va_arg(ap,T)   ( *(T *)(((ap) += (_BND (T, _ALIGN_BND))) - (_BND (T,_ALIGN_BND))) )
#define _va_end(ap)     ( (void)0 )
#define _va_start(ap,A) ( (void) ((ap) = (((char *) &(A)) + (_BND (A,_AUPBND)))) )

*/

#ifndef STDOUT
#define STDOUT  1
#endif 


int isprintable(int c) {
    return (c <= 0x1F || c >= 0x7F) ? 0 : 1;
}

static void
utee_putc(int fd, char c)
{
    write(fd, &c, 1);
}

/* zero padding on left !*/
static int
utee_printint_zpad(int fd, int xx, int base, int sgn, int zero_padding)
{
    static char digits[] = "0123456789ABCDEF";
    char buf[16];
    int i, neg;
    unsigned int x;
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
        utee_putc(fd, buf[i]);

    return count;
}


// Only understands %d, %x, %p, %s.
int
utee_printf(char *fmt, ...)
{
	int fd;
    char *s;
    int c, i, state;
    unsigned int *ap;
	int zero_padding = 1;
	int count = 0;
	char *err_padding = "error printf padding: ";

    fd = STDOUT;
    state = 0;
    ap = (unsigned int*)(void*)&fmt + 1;

    for(i = 0; fmt[i]; i++){
        c = fmt[i] & 0xff;
		if(c == '\n'){
			utee_putc(fd,'\r');
			count++;
			utee_putc(fd,'\n');
			count++;
			continue;
		}
        if(state == 0){
            if(c == '%'){
                state = '%';
            } else {
                utee_putc(fd, c);
                count++;
            }
        } else if(state == '%'){
        	/* zero padding on left !*/
			if(c == '0'){
				/* skip 0 */
				zero_padding = fmt[++i];
				if((zero_padding < 0x31) || (zero_padding > 0x38)){
					//invalid padding bits
					utee_putc(fd,'\n');
					while(*err_padding != 0){
						utee_putc(fd, *err_padding);
						err_padding++; 
					}
					utee_putc(fd, '0');utee_putc(fd, zero_padding);utee_putc(fd, '\n');
					return 0;
				}
				zero_padding -= 0x30;
				continue;
			}
			else if(c == 'd'){
				count += utee_printint_zpad(fd, *ap, 10, 1, zero_padding);
                ap++;
            } 
            else if(c == 'x' || c == 'p'){
            	count += utee_printint_zpad(fd, *ap, 16, 0, zero_padding);
                ap++;
            } 
            else if(c == 's'){
                s = (char*)*ap;
                ap++;
                if(s == 0)
                    s = "(null)";
                while(*s != 0){
                    utee_putc(fd, *s);
                    s++;
                    count++;
                }
            } 
            else if(c == 'c'){
                utee_putc(fd, *ap);
                ap++;
            } 
            else if(c == '%'){
                utee_putc(fd, c);
                count++;
            } 
            else {
                // Unknown % sequence.  Print it to draw attention.
                utee_putc(fd, '%');
                utee_putc(fd, c);
                return 0;
            }
            state = 0;
        }

    }


   return count;
}



/*
 * print data by hex-format
 */
static void hexdump(char *title, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp) {
    
    uint32_t line;
    uint32_t i, j, count;

    if(data == NULL || size <= 0 ) {
        return;
    }

    if( linenum <= 0 ) {
        linenum = 16;
    }
    line = 0;
    count = 0;
    i = 0;
    if(isUp) {
        i = 0;
    }else {
        i = size - 1;
    }
    while(true) {
        while(0 == count % linenum) {
            if(0 == count) {
                utee_printf("\n<%s>\n", title);
                utee_printf("%08x\t",line);   
                break;   
            }
            line += linenum;
            utee_printf("\t|");
            for(j=linenum; j>0; j--){
                utee_printf("%c",isprintable(data[count-j])?data[count-j]:'.');
            }
            utee_printf("|");
            utee_printf("\n%08x\t",line);   
            break;    
        } 
        utee_printf("%02x ", *(data+i));
        count++;
        if( isUp && ((++i) == size) ) {
            break;
        }
        if( !isUp && ((i--) == 0) ){
            break;
        }                    
    }

    if( 1 ) {
        i = size % linenum == 0 ? linenum : size % linenum;
        for(j = linenum - i; j>0; j--){
            utee_printf("   ");         
        }
        utee_printf("\t|");
        for(j=i; j>0; j--){
            utee_printf("%c",isprintable(data[count-j])?data[count-j]:'.');
        }
        for(j = linenum - i; j>0; j--){
            utee_printf(" ");       
        }
        utee_printf("|");       
    } 

    utee_printf("\n%08x\n",line + linenum);

}



static void hexdump_C(char *var, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp) {
    
    uint32_t line;
    uint32_t i, count;

    if(data == NULL || size <= 0 ) {
        return;
    }
    
    if( linenum <= 0 ) {
        linenum = 16;
    }

    line = 0;
    count = 0;
    i = 0;
    while(true) {
        while(0 == count % linenum) {
            if(0 == count) {
                utee_printf("\nvoid *%s =  \\\n\"", var);    
                break;   
            }
            line += linenum;
            utee_printf("\"\\\n\"");       
            break;    
        } 
        utee_printf("\\x%02x", *(data+i));
        count++;
        if( isUp && ((++i) == size) ) {
            break;
        }
        if( !isUp && ((i--) == 0) ){
            break;
        }                    
    }
    utee_printf("\";\n\n");  
}


