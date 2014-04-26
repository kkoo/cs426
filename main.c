// This is a test for encryption/decryption functions
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *hello="hello world hello hello hello hello!";
	char *cipher=des_encrypt("keykeykey",hello,strlen(hello));
	printf("Ciphertext: %s\n",cipher);
	char *plain=des_decrypt("keykeykey",cipher,strlen(cipher));
	printf("Plaintext: %s\n",plain);
	char *sha=sha1_digest(cipher);
	printf("Hash: %s\n",sha);
	char *rsa=rsa_encrypt(plain,"ku_pub.pem");
	printf("RSA cipher: %s\n",rsa);
	char *rsaplain=rsa_decrypt(rsa,"ku_priv.pem");
	printf("RSA decrypt result: %s\n",rsaplain);
	return 0;

}
