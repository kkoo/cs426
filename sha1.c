#include <openssl/sha.h>
#include <string.h>
#include <malloc.h>

unsigned char *sha1_digest(char* msg)
{
	unsigned char *ret=(unsigned char *)malloc(SHA_DIGEST_LENGTH+1);
	memset(ret,0,SHA_DIGEST_LENGTH+1);
	
	SHA1(msg,sizeof(char),ret);
	return ret;
}
