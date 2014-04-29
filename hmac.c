#include <openssl/hmac.h>

char *hmac(char *key, char *data) {
	char *result = (char *)malloc(20+1);
	memset(result, 0, 20+1);
	//char *digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), result, EVP_MAX_MD_SIZE);   
	char *tmp = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);
	strncpy(result, tmp, 20);
	return result;
} 