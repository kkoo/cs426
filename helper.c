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
	return ( intToStr(createRandomNum()) );
}

unsigned char *createKey(msg_type logType, char *authKey) {
	int size = strlen(intToStr(logType)) + strlen(authKey) + 1;
	char *tmp = (char *)malloc(size);
	memset(tmp,0,size);
	strcpy(tmp, intToStr(logType));
	strcat(tmp, authKey);

	return sha1_digest(tmp);
}

unsigned char *createFirstAuthKey() {
	return ( intToStr(createRandomNum()) );
}

unsigned char *createAuthKey(char *key) {
	return ( *key );
}

unsigned char *createX0(char *authKey) {
	//x0 = p, d, Cu, A0
	char *p = intToStr( 1 );
	char *d = intToStr( getTimeStamp() );

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
	strcat(retStr, authKey); 
	strcat(retStr, "\0");

	return retStr;
}

unsigned char *createX(int stepID, int logId, char *x) {
	//x = p, logID, hash(X_prev)
	char *p = intToStr( stepID );
	char *logID = intToStr( logId );
	char *hashVal = (x);

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

char *encryptData(char *data, char *key, int len) {
	return des_encrypt(key, data, len);
}

struct LogEntry *createLogEntry(int type,int logID, struct Msg *msg) {
	int d = getTimeStamp();
	struct LogEntry *entry = (struct LogEntry *)malloc( sizeof(struct LogEntry) );
	
	entry->timestamp = d;
	entry->timeout = TIMEOUT;
	entry->logID = logID;
	entry->message = msg;

	return entry;
}

struct ALogEntry *createALogEntry(int logType, char *data, char *hash, char *msgAuth) {

	struct ALogEntry *entry = (struct ALogEntry *)malloc( sizeof(struct ALogEntry) );
	entry->logType = logType;
	entry->data = data;
	entry->hashChain = hash;
	entry->msgAuth = msgAuth;

	return entry;
}

char *msgToStr(struct Msg *msg) {
	char *retStr = (char *)malloc( strlen(intToStr(msg->p)) + strlen(intToStr(msg->id)) + strlen(msg->pke) + strlen(msg->enc) + 10);
	sprintf(retStr, "%d %d %s %s", msg->p, msg->id, msg->pke, msg->enc);
	return retStr;
}
char *logToStr(struct LogEntry *entry) {
	char *retStr = (char *)malloc( strlen(intToStr(entry->timestamp)) + strlen(intToStr(entry->timeout)) + strlen(intToStr(entry->logID)) + strlen(entry->message) + 10);
	sprintf(retStr, "%d %d %d %s", entry->timestamp, entry->timeout, entry->logID, entry->message);
	return retStr;
}

char *logToStr2(struct LogEntry *entry) {
	char *msg = msgToStr(entry->message);
	char *retStr = (char *)malloc( strlen(intToStr(entry->timestamp)) + strlen(intToStr(entry->timeout)) + strlen(intToStr(entry->logID)) + strlen(msg) + 10);
	sprintf(retStr, "%d %d %d %s", entry->timestamp, entry->timeout, entry->logID, msg);
	return retStr;
}


void printLog(struct LogEntry *entry) {
	printf("Log:%d %d %d %s\n", entry->timestamp, entry->timeout, entry->logID, entry->message);
	return;
}

void printALog(struct ALogEntry *entry) {
	printf("Log:%d %s %s %s\n", entry->logType, entry->data, entry->hashChain, entry->msgAuth);
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

char *getKey(struct Msg *msg, char *privKeyFile, char *pubKeyFile) {
	//get key
	char *encKey = msg->pke;
	char *key = rsa_decrypt(encKey, privKeyFile);

	return key;
}

char *createY(char *prevHash, char *encData, int logType) {
	char *logTypeStr = intToStr(logType);
	int prevHashLen = strlen(prevHash);
	int encDataLen = strlen(encData);
	int logTypeLen = strlen(logTypeStr);

	char *returnStr = (char *)malloc(prevHashLen+encDataLen+logTypeLen+1);
	strcpy(returnStr, prevHash); 
	strcpy(returnStr, encData);	
	strcpy(returnStr, logTypeStr); free(logTypeStr);

	return returnStr;
}

char *genMAC(char *key, char *data) {
	return hmac(key, data);
}


