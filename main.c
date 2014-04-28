// This is a test for encryption/decryption functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "project.h"

int main(int argc, char **argv)
{
	/*
	char *hello="hello world hello hello hello hello!";
	char *cipher=des_encrypt("keykeykey",hello,strlen(hello));
	printf("Ciphertext: %s\n",cipher);
	char *plain=des_decrypt("keykeykey",cipher,strlen(cipher));
	printf("Plaintext: %s\n",plain);
	char *sha=sha1_digest(hello);
	printf("Hash: %s\n",sha);
	char *rsacipher=rsa_encrypt(plain,"ku_pub.pem");
	printf("RSA cipher: %s\n",rsacipher);
	char *rsaplain=rsa_decrypt(rsacipher,"ku_priv.pem");
	printf("RSA decryption result: %s\n",rsaplain);
	int len=0;
	char *sig=rsa_sign(plain,"ku_priv.pem",&len);
	printf("RSA signature: %s\n",sig);
	int v=rsa_verify(plain,sig,"ku_pub.pem",len);
	if(v) printf("Verified!\n"); else printf ("Verification failed!\n");
	*/
	////////STARTUP from U////////////////
	//create first message
	//struct Msg *msg = createMsg(0, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, createFistKey(), createX0());
	struct Msg *msg = createMsg(0, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, createFistKey(), "AAAAAAAAAAAAAAAA");
	//create first log entry
	struct LogEntry *firstLog = createLogEntry(LOG_INIT, 1, msg);
	
	///////T//////////////
	int result = verifyMsg(msg, PRIV_KEY_T, PUB_KEY_U);

	printf("result: %d\n", result);
	//shell();
	return 0;
}
