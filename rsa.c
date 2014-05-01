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

	int result = RSA_public_encrypt(rsa_len,msg,ret,rsa,RSA_NO_PADDING);
	//int result = RSA_public_encrypt(rsa_len,msg,ret,rsa,RSA_PKCS1_PADDING);
	/*
	if(result < 0 ){
		ERR_load_crypto_strings();  
		char buff[1000] ="";
		ERR_error_string(ERR_get_error(), buff);
		printf("ERROR: %s\n", buff);
	}
	*/
	fclose(fp);
	RSA_free(rsa);
	return ret;
}

char* rsa_decrypt(char *msg, char *keyfile)
{
	FILE *fp=fopen(keyfile,"rb");
	RSA *rsa;
	rsa=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
	int rsa_len=RSA_size(rsa);
	int len=strlen(msg);

	char *ret=(char *)malloc(rsa_len+1);
	memset(ret,0,rsa_len+1);

	RSA_private_decrypt(rsa_len,msg,ret,rsa,RSA_NO_PADDING);

	fclose(fp);
	RSA_free(rsa);
	return ret;

}

char *rsa_sign(char *msg, char *keyfile, int *len)
{
	RSA *rsa;
	FILE *fp=fopen(keyfile,"rb");
	rsa=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
	char *ret=(char *)calloc(RSA_size(rsa)+1,sizeof(unsigned char));
	memset(ret,0,RSA_size(rsa) +1); 					
	char *digest=sha1_digest(msg);
	RSA_sign(NID_sha1,(unsigned char *)msg,strlen(msg),(unsigned char *)ret,len,rsa);
	fclose(fp);
	RSA_free(rsa);
	return ret;
}

int rsa_verify(char *msg, char *sig, char *keyfile,int len)
// returns 0 if failed, 1 if successful
{
	int slen;
	RSA *rsa;
	FILE *fp=fopen(keyfile,"rb");
	rsa=PEM_read_RSA_PUBKEY(fp,NULL,NULL,NULL);
	if(!RSA_verify(NID_sha1,(unsigned char *)msg,strlen(msg),(unsigned char *)sig,len,rsa)) 
		return 0;

	fclose(fp);
	RSA_free(rsa);
	return 1;

}
