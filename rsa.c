#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

char* rsa_encrypt(char *msg, char *keyfile)
{
	FILE *fp=fopen(keyfile,"rb");
	RSA *rsa;
	rsa=PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
	int rsa_len=RSA_size(rsa);
	int len=strlen(msg);

	char *ret=(char *)malloc(rsa_len+1);
	memset(ret,0,rsa_len+1);

	RSA_public_encrypt(rsa_len,msg,ret,rsa,RSA_NO_PADDING);

	fclose(fp);
	return ret;

}
