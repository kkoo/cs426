/*
 * DES encryption and decryption
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>
 
 
char *
des_encrypt( char *Key, char *Msg, int size)
{	
 	static char*    Res;
        int             n=0;
        DES_cblock      Key2;
        DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size )+1;
	memset(Res,0,size+1);
 
        /* Prepare the key for use with DES_cfb64_encrypt */
	DES_string_to_key(Key,&Key2);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );
 
        /* Encryption occurs here */
        DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &schedule, &Key2, &n, DES_ENCRYPT );
 
         return (Res);
}
 
 
char *
des_decrypt( char *Key, char *Msg, int size)
{
 	static char*    Res;
        int             n=0;
 
        DES_cblock      Key2;
        DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size )+1;
	   memset(Res,0,size+1);
 
        /* Prepare the key for use with DES_cfb64_encrypt */
        DES_string_to_key(Key, &Key2);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );
 
        /* Decryption occurs here */
        DES_cfb64_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &schedule, &Key2, &n, DES_DECRYPT );
 
        return (Res);
}

