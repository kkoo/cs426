#include <openssl/sha.h>
#include <string.h>
#include <malloc.h>

unsigned char *sha1_digest(char* msg)
{
	unsigned char *ret=(unsigned char *)malloc(65);
	memset(ret,0,65);
	SHA1(msg,sizeof(msg),ret);
	return ret;
}
