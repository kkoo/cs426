#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"


char *certFile = CERT_FILE;

unsigned int getTimeStamp() {
    return (int)time(NULL);
}

unsigned int createRandomNum() {
	srand( (unsigned)time(NULL) );
	return rand();
}

unsigned char *intToStr(int num) {
	char str[16] = "";
	sprintf(str, "%d", num);

	char *returnStr = (char *)malloc(strlen(str) +1);
	memset(returnStr, 0, strlen(str) +1);
    strcpy(returnStr, str);

	return returnStr;
}

unsigned char *hash(char *str) {
	return sha1_digest(str);
}

unsigned char *createFirstKey() {
	//return sha1_digest( intToStr(getTimeStamp()+createRandomNum()) );
	return sha1_digest( intToStr(createRandomNum()) );
}

unsigned char *createKey(char *enc_key, msg_type logType, char *authKey) {
	int size = strlen(enc_key) + strlen(intToStr(logType)) +strlen(authKey) + 1;
	char *tmp = (char *)malloc(size);
	memset(tmp,0,size);
	//TODO: create key
	return sha1_digest(tmp);
}

unsigned char *createFirstAuthKey() {
	return sha1_digest( intToStr(createRandomNum()) );
}

unsigned char *createAuthKey(char *key) {
	return sha1_digest( *key );
}

unsigned char *createX0() {
	//x0 = p, d, Cu, A0
	char *p = intToStr( 1 );
	char *d = intToStr( getTimeStamp() );
	char *authKey = intToStr(createRandomNum());  //WHAT TO DO WITH RANDOM STARTING POINT?

	//read the certificate
	unsigned char *Cu;
	char *cert;

	FILE *fp=fopen(certFile, "rb");
	if (fp == NULL) {
  		fprintf(stderr, "Cannot open Certificate File\n");
  		exit(1);
	}
	fseek(fp,0,SEEK_END);
   	int length = ftell (fp);
   	rewind(fp);

	cert = (char *) malloc (length + 1);
	fread(cert,sizeof(char),length,fp);
	cert[length] = '\0';

	close(fp);
	//end read CERT

	char *retStr = (char *)malloc( strlen(p) + strlen(d) + strlen(cert) + strlen(authKey) + 1);
	strcpy(retStr, p); free(p);
	strcat(retStr, d); free(d);
	strcat(retStr, cert); free(cert);
	strcat(retStr, authKey); free(authKey);
	strcat(retStr, "\0");

	return retStr;
}

unsigned char *createX(int stepID, int logId, char *x) {
	//x = p, logID, hash(X_prev)
	char *p = intToStr( stepID );
	char *logID = intToStr( logId );
	char *hashVal = sha1_digest(x);

	//printf("createX p:%s log:%s hashval:%s\n", p, logID, hashVal);

	char *retStr = (char *)malloc( strlen(p) + strlen(logID) + strlen(hashVal) + 1);
	retStr = strcpy(retStr, p);	free(p);
	retStr = strcat(retStr, logID); free(logID);
	retStr = strcat(retStr, hashVal); free(hashVal);
	
	return retStr;
}

struct Msg *createMsg(int stepID, int senderID, 
						char *pubEncFile, char *sigFile,
						char *key, char *x) {

	//unsigned char *p = intToStr(stepID);
	//unsigned char *id = intToStr(senderID);
	unsigned char *pke;			//public encryption
	unsigned char *encrypt;		//sym encryption
	unsigned char *sign;

	//sign
	int xLen = strlen(x);
	int sigLen = 0;
	sign = rsa_sign(x, sigFile, &sigLen);

	//public encryption
	pke = rsa_encrypt(key, pubEncFile);

	char *tmp = (char *)malloc(xLen + sigLen + 1);
	strcpy(tmp, x); //free(x);
	strcat(tmp, sign); //free(sign);

	//sym enccryption
	encrypt = des_encrypt( key, tmp, strlen(tmp));

	struct Msg *msg = (struct Msg *)malloc( sizeof(struct Msg) );

	//prepare the msg
	msg->p = stepID;
	msg->id = senderID;
	msg->xLen = xLen;
	msg->sigLen = sigLen;
	msg->pke = pke;
	msg->enc = encrypt;
	msg->encLen = strlen(tmp);

	return msg;
}

struct LogEntry *createLogEntry(int logID, struct Msg *msg) {
	int d = getTimeStamp();
	struct LogEntry *entry = (struct LogEntry *)malloc( sizeof(struct LogEntry) );
	
	entry->timestamp = d;
	entry->timeout = TIMEOUT;
	entry->logID = logID;
	entry->message = msg;

	return entry;
}

void printLog(struct LogEntry *entry) {
	//char buf[1000];
	//sprintf(buf, "%d %d %d %s", entry->timestamp, entry->timeout, entry->logID, entry->message);

	//return buf;
	//printf("Log:%d %d %d %s\n", entry->timestamp, entry->timeout, entry->logID, entry->message);
	//printf("Log:%d %d %d\n", entry->timestamp, entry->timeout, entry->logID);
	return;
}

int verifyMsg(struct Msg *msg, char *privKeyFile, char *pubKeyFile) {
	//get key
	char *encKey = msg->pke;
	char *key = rsa_decrypt(encKey, privKeyFile);

	//decrypt the message
	char *enc = msg->enc;
	char *text = des_decrypt( key, enc, msg->encLen);

	//divide message into x and signiture
	int xLen = msg->xLen;
	int sigLen = msg->sigLen;
	char x[xLen+1];
	char sig[sigLen+1];
	memcpy( x, text, xLen );
	x[xLen] = '\0';
	text = text+xLen;
	memcpy( sig, text, sigLen );
	sig[sigLen] ='\0';

	//printf("verfy: encLen:%d xLen:%d sigLen:%d\n", msg->encLen, xLen, sigLen);

	//printf("x:%s\n", x);
	//printf("sig:%s\n", sig);

	//verify signiture
	int result = rsa_verify(x, sig, pubKeyFile, sigLen);
	return result;
}

char* getX(struct Msg *msg, char *privKeyFile, char *pubKeyFile) {
	//get key
	char *encKey = msg->pke;
	char *key = rsa_decrypt(encKey, privKeyFile);

	//decrypt the message
	char *enc = msg->enc;
	char *text = des_decrypt( key, enc, msg->encLen);

	//divide message into x and signiture
	int xLen = msg->xLen;
	char *x = (char *)malloc(xLen +1);
	memcpy( x, text, xLen );
	x[xLen] = '\0';
	
	return x;
}
