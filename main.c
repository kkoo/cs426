// This is a test for encryption/decryption functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "project.h"

int logID = 0;
int stepNum = 0;

int createLog() {
	////////STARTUP from U////////////////
	//create first message
	//struct Msg *msg = createMsg(0, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, createFistKey(), createX0());
	char *x = "AAAAAAAAAAAAAAAA";
	char *hashX = hash(x);
	struct Msg *msg = createMsg(stepNum, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, createFirstKey(), x);
	//create first log entry
	struct LogEntry *firstLog = createLogEntry(LOG_INIT, logID, msg);
	printLog(firstLog);

	///////T//////////////
	int result = verifyMsg(msg, PRIV_KEY_T, PUB_KEY_U);
	printf("Result from T:%d\n", result);
	//TODO: check valid certificate

	//get x, IDlog, p
	int p = msg->p;
	p+=1;
	char *x0 = getX(msg, PRIV_KEY_T, PUB_KEY_U);

	//create X1
	//char *x1 = createX(p, logID, x0); //what to do with logID?
	char *x1 = "AAAAAAAAAAAAAAAA";

	//create msg
	struct Msg *msg1 = createMsg(p, ID_TRUSTED, PUB_KEY_U, PRIV_KEY_T, createFirstKey(), x1);

	////////----U///////////////////
	result = verifyMsg(msg1, PRIV_KEY_U, PUB_KEY_T);
	printf("Result from U:%d\n", result);

	struct LogEntry *secondLog = createLogEntry(RESP_MSG, logID, msg);
	printLog(firstLog);
}

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

	createLog();

	//shell();
	return 0;
}
