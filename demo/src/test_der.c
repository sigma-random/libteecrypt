#include <tee_api.h>
#include <utee_api.h>

#ifdef MACRO_NEWLIBC_FUNCS


int main() {
   TEE_Printf("Not support In ARM!\n");
   return 0;
}


#else

#include <tomcrypt.h>
static void der_flexi_test(void);
static void der_set_test(void);

int main() {
   if(TEE_InitCryptContext() != TEE_SUCCESS) {
      TEE_Printf("[err] TEE_InitCryptContext\n");
      return 0;
   }

   der_flexi_test();
   der_set_test();

   if(TEE_FiniCryptContext() != TEE_SUCCESS) {
      TEE_Printf("[err] TEE_FiniCryptContext\n");
   }

   return 0;
}


/* we are encoding 

  SEQUENCE {
     PRINTABLE "printable"
     IA5       "ia5"
     SEQUENCE {
        INTEGER 12345678
        UTCTIME { 91, 5, 6, 16, 45, 40, 1, 7, 0 }
        SEQUENCE {
           OCTET STRING { 1, 2, 3, 4 }
           BIT STRING   { 1, 0, 0, 1 }
           SEQUENCE {
              OID       { 1, 2, 840, 113549 }
              NULL
              SET OF {
                 PRINTABLE "333"  // WILL GET SORTED
                 PRINTABLE "222"
           }
        }
     }
  }     

*/  

static void der_flexi_test(void)
{
   static const char printable_str[]    = "printable";
   static const char set1_str[]         = "333";
   static const char set2_str[]         = "222";
   static const char ia5_str[]          = "ia5";
   static const unsigned long int_val   = 12345678UL;
   static const ltc_utctime   utctime   = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };
   static const unsigned char oct_str[] = { 1, 2, 3, 4 };
   static const unsigned char bit_str[] = { 1, 0, 0, 1 };
   static const unsigned long oid_str[] = { 1, 2, 840, 113549 };
   
   unsigned char encode_buf[192];
   unsigned long encode_buf_len, decode_len;
   int           err;
   
   ltc_asn1_list static_list[5][3], *decoded_list, *l;
   
   /* build list */
   LTC_SET_ASN1(static_list[0], 0, LTC_ASN1_PRINTABLE_STRING, (void *)printable_str, strlen(printable_str));
   LTC_SET_ASN1(static_list[0], 1, LTC_ASN1_IA5_STRING,       (void *)ia5_str,       strlen(ia5_str));
   LTC_SET_ASN1(static_list[0], 2, LTC_ASN1_SEQUENCE,         static_list[1],   3);
   
   LTC_SET_ASN1(static_list[1], 0, LTC_ASN1_SHORT_INTEGER,    (void *)&int_val,         1);
   LTC_SET_ASN1(static_list[1], 1, LTC_ASN1_UTCTIME,          (void *)&utctime,         1);
   LTC_SET_ASN1(static_list[1], 2, LTC_ASN1_SEQUENCE,         static_list[2],   3);

   LTC_SET_ASN1(static_list[2], 0, LTC_ASN1_OCTET_STRING,     (void *)oct_str,          4);
   LTC_SET_ASN1(static_list[2], 1, LTC_ASN1_BIT_STRING,       (void *)bit_str,          4);
   LTC_SET_ASN1(static_list[2], 2, LTC_ASN1_SEQUENCE,         static_list[3],   3);

   LTC_SET_ASN1(static_list[3], 0, LTC_ASN1_OBJECT_IDENTIFIER,(void *)oid_str,          4);
   LTC_SET_ASN1(static_list[3], 1, LTC_ASN1_NULL,             NULL,             0);
   LTC_SET_ASN1(static_list[3], 2, LTC_ASN1_SETOF,            static_list[4],   2);

   LTC_SET_ASN1(static_list[4], 0, LTC_ASN1_PRINTABLE_STRING, set1_str, strlen(set1_str));
   LTC_SET_ASN1(static_list[4], 1, LTC_ASN1_PRINTABLE_STRING, set2_str, strlen(set2_str));

   /* encode it */
   encode_buf_len = sizeof(encode_buf);
   if ((err = der_encode_sequence(&static_list[0][0], 3, encode_buf, &encode_buf_len)) != CRYPT_OK) {
      fprintf(stderr, "Encoding static_list: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }

   TEE_Hexdump("encode_buf", encode_buf, encode_buf_len, 16, 1);

#if 1
   {
     FILE *f;
     f = fopen("t.bin", "wb");
     fwrite(encode_buf, 1, encode_buf_len, f);
     fclose(f);
   } 
#endif    

   /* decode with flexi */
   decode_len = encode_buf_len;
   if ((err = der_decode_sequence_flexi(encode_buf, &decode_len, &decoded_list)) != CRYPT_OK) {
      fprintf(stderr, "decoding static_list: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }

   if (decode_len != encode_buf_len) {
      fprintf(stderr, "Decode len of %lu does not match encode len of %lu \n", decode_len, encode_buf_len);
      exit(EXIT_FAILURE);
   }


   /* we expect l->next to be NULL and l->child to not be */
   l = decoded_list;
   if (l->next != NULL || l->child == NULL) {
      fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
      exit(EXIT_FAILURE);
   }
   
   /* we expect a SEQUENCE */
      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;

   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != strlen(printable_str) || memcmp(printable_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("PRINTABLE STRING", l->data, l->size, 16, 1);

   
      /* move to next */
      l = l->next;
      
   /* IA5 STRING */      
      /* we expect ia5_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_IA5_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != strlen(ia5_str) || memcmp(ia5_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("IA5 STRING", l->data, l->size, 16, 1);

   
      /* move to next */
      l = l->next;

   
   /* expect child anve move down */
      
      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }


      l = l->child;
      

   /* INTEGER */
   
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_INTEGER) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (mp_cmp_d(l->data, 12345678UL) != LTC_MP_EQ) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
#define BIG_INT_MIN_SIZE   2048
#define BIG_INT_RAW_DATA   true
#define BIG_INT_REAL_DATA  false
TEE_HexdumpBigInt("INTEGER", l->data, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 16, BIG_INT_REAL_DATA); // BIG_INT_RAW_DATA  BIG_INT_REAL_DATA
   
      /* move to next */
      l = l->next;

      
   /* UTCTIME */
         
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_UTCTIME) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (memcmp(l->data, &utctime, sizeof(utctime))) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("UTCTIME", l->data, sizeof(utctime), 16, 1);


      /* move to next */
      l = l->next;
      
   /* expect child anve move down */
      
      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;
      
      
   /* OCTET STRING */      
      /* we expect oct_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_OCTET_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != sizeof(oct_str) || memcmp(oct_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("OCTET STRING", l->data, l->size, 16, 1);
   
      /* move to next */
      l = l->next;

   /* BIT STRING */      
      /* we expect oct_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_BIT_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != sizeof(bit_str) || memcmp(bit_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("BIT STRING", l->data, l->size, 16, 1);
   
      /* move to next */
      l = l->next;

   /* expect child anve move down */
      
      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_SEQUENCE) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;


   /* OID STRING */      
      /* we expect oid_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_OBJECT_IDENTIFIER) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != sizeof(oid_str)/sizeof(oid_str[0]) || memcmp(oid_str, l->data, l->size*sizeof(oid_str[0]))) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("OID STRING", l->data, l->size*sizeof(oid_str[0]), 16, 1);
   
      /* move to next */
      l = l->next;
      
   /* NULL */
      if (l->type != LTC_ASN1_NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      /* move to next */
      l = l->next;
      
   /* expect child anve move down */
      if (l->next != NULL || l->child == NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      
      if (l->type != LTC_ASN1_SET) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
      l = l->child;
      
   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->next == NULL || l->child != NULL) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
/* note we compare set2_str FIRST because the SET OF is sorted and "222" comes before "333" */   
      if (l->size != strlen(set2_str) || memcmp(set2_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("PRINTABLE STRING", l->data, l->size, 16, 1);
   
      /* move to next */
      l = l->next;

   /* PRINTABLE STRING */
      /* we expect printable_str */
      if (l->type != LTC_ASN1_PRINTABLE_STRING) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
   
      if (l->size != strlen(set1_str) || memcmp(set1_str, l->data, l->size)) {
         fprintf(stderr, "(%d), %d, %lu, next=%p, prev=%p, parent=%p, child=%p\n", __LINE__, l->type, l->size, l->next, l->prev, l->parent, l->child);
         exit(EXIT_FAILURE);
      }
TEE_Hexdump("PRINTABLE STRING", l->data, l->size, 16, 1);
   

   der_sequence_free(l);
   printf("ok!\n");

}
 


static void der_set_test(void)
{
   ltc_asn1_list list[10];
   static const unsigned char oct_str[] = { 1, 2, 3, 4 };
   static const unsigned char bin_str[] = { 1, 0, 0, 1 };
   static const unsigned long int_val   = 12345678UL;

   unsigned char strs[10][10], outbuf[128];
   unsigned long x, val, outlen;
   int           err;
   
   /* make structure and encode it */
   LTC_SET_ASN1(list, 0, LTC_ASN1_OCTET_STRING,  oct_str, sizeof(oct_str));
   LTC_SET_ASN1(list, 1, LTC_ASN1_BIT_STRING,    bin_str, sizeof(bin_str));
   LTC_SET_ASN1(list, 2, LTC_ASN1_SHORT_INTEGER, &int_val, 1);
   
   /* encode it */
   outlen = sizeof(outbuf);
   if ((err = der_encode_set(list, 3, outbuf, &outlen)) != CRYPT_OK) {
      fprintf(stderr, "error encoding set: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }
   
  
   /* first let's test the set_decoder out of order to see what happens, we should get all the fields we expect even though they're in a diff order */
   LTC_SET_ASN1(list, 0, LTC_ASN1_BIT_STRING,    strs[1], sizeof(strs[1]));
   LTC_SET_ASN1(list, 1, LTC_ASN1_SHORT_INTEGER, &val, 1);
   LTC_SET_ASN1(list, 2, LTC_ASN1_OCTET_STRING,  strs[0], sizeof(strs[0]));
   
   if ((err = der_decode_set(outbuf, outlen, list, 3)) != CRYPT_OK) {
      fprintf(stderr, "error decoding set using der_decode_set: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }
   
   /* now compare the items */
   if (memcmp(strs[0], oct_str, sizeof(oct_str))) {
      fprintf(stderr, "error decoding set using der_decode_set (oct_str is wrong):\n");
      exit(EXIT_FAILURE);
   }
      
   if (memcmp(strs[1], bin_str, sizeof(bin_str))) {
      fprintf(stderr, "error decoding set using der_decode_set (bin_str is wrong):\n");
      exit(EXIT_FAILURE);
   }
   
   if (val != int_val) {
      fprintf(stderr, "error decoding set using der_decode_set (int_val is wrong):\n");
      exit(EXIT_FAILURE);
   }
   
   strcpy((char*)strs[0], "one");
   strcpy((char*)strs[1], "one2");
   strcpy((char*)strs[2], "two");
   strcpy((char*)strs[3], "aaa");
   strcpy((char*)strs[4], "aaaa");
   strcpy((char*)strs[5], "aab");
   strcpy((char*)strs[6], "aaab");
   strcpy((char*)strs[7], "bbb");
   strcpy((char*)strs[8], "bbba");
   strcpy((char*)strs[9], "bbbb");
   
   for (x = 0; x < 10; x++) {
       LTC_SET_ASN1(list, x, LTC_ASN1_PRINTABLE_STRING, strs[x], strlen((char*)strs[x]));
   }
   
   outlen = sizeof(outbuf);
   if ((err = der_encode_setof(list, 10, outbuf, &outlen)) != CRYPT_OK) {       
      fprintf(stderr, "error encoding SET OF: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }
   
   for (x = 0; x < 10; x++) {
       LTC_SET_ASN1(list, x, LTC_ASN1_PRINTABLE_STRING, strs[x], sizeof(strs[x]) - 1);
   }
   XMEMSET(strs, 0, sizeof(strs));
   
   if ((err = der_decode_set(outbuf, outlen, list, 10)) != CRYPT_OK) {
      fprintf(stderr, "error decoding SET OF: %s\n", error_to_string(err));
      exit(EXIT_FAILURE);
   }
   
   /* now compare */
   for (x = 1; x < 10; x++) {
      if (!(strlen((char*)strs[x-1]) <= strlen((char*)strs[x])) && strcmp((char*)strs[x-1], (char*)strs[x]) >= 0) {
         fprintf(stderr, "error SET OF order at %lu is wrong\n", x);
         exit(EXIT_FAILURE);
      }
   }      
   
}



#endif