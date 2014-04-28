#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"


char *certFile = CERT_FILE;

int getTimeStamp() {
    return (int)time(NULL);
}

int createRandomNum() {
	srand( (unsigned)time(NULL) );
	return rand();
}

unsigned char *intToStr(int num) {
	char str[16];
	sprintf(str, "%d", num);

	char *returnStr = (char *)malloc(strlen(str) +1);
    	strcpy(returnStr,str);  

	return returnStr;
}

unsigned char *createFistKey() {
	return sha1_digest( intToStr(getTimeStamp()+createRandomNum()) );
}

unsigned char *createKey(char *enc_key, msg_type logType, char *authKey) {
	char *tmp = (char *)malloc(strlen(enc_key) + strlen(intToStr(logType)) +strlen(authKey) + 1);
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
	char *buf;

	FILE *fp=fopen(certFile, "rb");
	if (fp == NULL) {
  		fprintf(stderr, "Cannot open Certificate File\n");
  		exit(1);
	}
	fseek(fp,0,SEEK_END);
   	int length = ftell (fp);
   	rewind(fp);

	buf = (char *) malloc (length + 1);
	fread(buf,sizeof(char),length,fp);
	buf[length] = '\0';

	close(fp);
	//end read CERT

	char *retStr = (char *)malloc( strlen(p) + strlen(d) + strlen(buf) + strlen(authKey) + 1);
	strcpy(retStr, p);
	strcat(retStr, d);
	strcat(retStr, buf);
	strcat(retStr, authKey);
	strcat(retStr, "\0");

	return retStr;
}

unsigned char *createX(int stepID, msg_type logType, char *x) {
	//x = p, logID, hash(X_prev)
	char *p = intToStr( stepID );
	char *logID = intToStr( logType );
	char *hashVal = sha1_digest(x);

	char *retStr = (char *)malloc( strlen(p) + strlen(logID) + strlen(hashVal) + 1);
	retStr = strcpy(retStr, p);
	retStr = strcat(retStr, logID);
	retStr = strcat(retStr, hashVal);
	
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
	strcpy(tmp, x);
	strcat(tmp, sign);

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

	//verify signiture
	int result = rsa_verify(x, sig, pubKeyFile, sigLen);
	return result;
}
