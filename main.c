// This is a test for encryption/decryption functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "project.h"

int logID = 0;
int stepNum = 0;

char *A0;
char *_logAuthKey;
char *_hashChain;
char *_sessionKey;

int createLog(char *fn) {	
	////////////////STARTUP from U////////////////
	//create first message
	
	//INIT values
	char *x = "ZZZ";
	char *hashX = hash(x);
	
	_hashChain = (char *)malloc(20+1); // the initial hash chain
	memset(_hashChain, 'a', 20+1); 

	_logAuthKey = intToStr(createRandomNum());		//A
	A0 = _logAuthKey;

	char *msgAuthCode; 								//Z

	_sessionKey = createFirstKey();				//K

	//create msg for T
	struct Msg *msg = createMsg(stepNum, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, _sessionKey, x);
	
	//create first log entry
	char *data = logToStr(createLogEntry(LOG_INIT, logID, msg));
	char *encData = encryptData(data, _sessionKey, strlen(data)); 

	_hashChain = createY(_hashChain, encData, LOG_INIT);
	msgAuthCode = genMAC(_logAuthKey, _hashChain);

	struct ALogEntry *firstLog = createALogEntry(LOG_INIT, encData, _hashChain, msgAuthCode);
	writeAEntry(firstLog, fn);
	//////////////END STARTUP from U////////////////


	/////////////RECIEVE  T//////////////

	//verify the message
	int result = verifyMsg(msg, PRIV_KEY_T, PUB_KEY_U);
	printf("Result from T:%d\n", result);
	//TODO: check valid certificate

	//increment protocol step ID;
	int p = msg->p + 1;

	//create X1
	char *x0 = getX(msg, PRIV_KEY_T, PUB_KEY_U);
	char *x1 = "ZZZ";

	//create session key
	char *sessionKeyT = createFirstKey();
	
	//create msg
	struct Msg *msg1 = createMsg(p, ID_TRUSTED, PUB_KEY_U, PRIV_KEY_T, sessionKeyT, x1);
	/////////////END  RECIEVE  T//////////////



	/////////////FINALIZE INIT U///////////////////
	//verify the msg
	result = verifyMsg(msg1, PRIV_KEY_U, PUB_KEY_T);
	printf("Result from U:%d\n", result);

	//get the data
	//TODO: sessionKey = 
	data = logToStr(createLogEntry(RESP_MSG, logID, msg1));
	encData = encryptData(data, _sessionKey, strlen(data));

	//update hash chains and keys
	_logAuthKey = hash(_logAuthKey);						//A+1 = H(A)			//TODO: free prev
	_hashChain = createY(_hashChain, encData, RESP_MSG);	//Y+1 = H(y, encData, logtype)
	msgAuthCode = genMAC(_logAuthKey, _hashChain);		//Z = MAC(Y)
	struct ALogEntry *secondLog = createALogEntry(RESP_MSG, encData, _hashChain, msgAuthCode);

	writeAEntry(secondLog, fn);
}

int addEntry(char *fileName, char *msg) {
	int logType = NORMAL_MSG;
	char *encData;
	char *msgAuthCode;

	//TODO: _sessionKey = 
	encData = encryptData(msg, _sessionKey, strlen(msg));

	_logAuthKey = hash(_logAuthKey);						//A+1 = H(A)			//TODO: free prev
	_hashChain = createY(_hashChain, encData, logType);		//Y+1 = H(y, encData, logtype)
	msgAuthCode = genMAC(_logAuthKey, _hashChain);			//Z = MAC(Y)

	struct ALogEntry *newEntry = createALogEntry(logType, encData, _hashChain, msgAuthCode);

	writeAEntry(newEntry, fileName);
}

int closeLog(char *fn) {
	struct ALogEntry *finalLog = createALogEntry(NORMAL_CLOSE, intToStr(getTimeStamp()), "", "");
	writeAEntry(finalLog, fn);
}

void testLog(char *fn) {
	createLog(fn);
	addEntry(fn, "hello");
	addEntry(fn, "abcdef");
	closeLog(fn);

	int logType;
	char *data;
	char *prevHashChain;
	char *msgAuth;
	char *authKey = A0;

	prevHashChain = (char *)malloc(20+1); // the initial hash chain
	memset(prevHashChain, 'a', 20+1); 

	int i = 0;
	int fileOpen = 1;
	int logValid = 1;
	while(fileOpen) {
		struct ALogEntry *entry = readAEntry(fn, i);

		if(entry->logType == LOG_INIT && i != 0) {
			logValid = 0;
		} 
		if(entry->logType == NORMAL_CLOSE) {
			printf("Log normal close recieved:%d\n", i);
			break;
		}

		//authenticate the log
		char *msgAuthCmp = genMAC(authKey, entry->hashChain);
		int result = strcmp(entry->msgAuth,msgAuthCmp);

		if(result != 0) {
			printf("Invalid Log entry:%d\n", i);
			logValid = 0;
		}
		else {
			printf("Valid Log entry:%d\n", i);
			logValid = 1;
		}

		logType = entry->logType;
		data = entry->data;
		prevHashChain = entry->hashChain;
		msgAuth = entry->msgAuth;

		//next authKey
		authKey = hash(authKey);
		
		i++;
	}
	if(logValid == 1) {
		printf("Log is valid\n");
	}
	else {
		printf("Log is invalid\n");
	}
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
	/*
	createLog("1.log");
	struct LogEntry *l=readEntry("1.log");
	printf("%d %d %d %d %d %d %d %d\n",l->timestamp,l->timeout,l->logID,l->message->p,l->message->id,
			l->message->xLen,l->message->sigLen,l->message->encLen);
	printf("%s\n\n\n%s\n\n\n",l->message->pke,l->message->enc,l->message->encLen);
	printf("%d\n",verifyMsg(l->message, PRIV_KEY_T, PUB_KEY_U));
	*/
	//createLog("1.log");
	testLog("test.log");
	//struct ALogEntry *r=readAEntry("1.log",0);
	//printf("%d %s %s %s\n",r->logType,r->data,r->hashChain,r->msgAuth);
	//printf("%d %s %s %s\n",r->logType,r->data,r->hashChain,r->msgAuth);
	/*
	struct ALogEntry e;
	e.logType=0;
	e.data="Hello!";
	e.hashChain="asdjkasdhjaskdhkjasdhjaskdhkjsadhkjhsadjasd";
	e.msgAuth="DHASDASJDHJKASDHKJASDHJK";

	writeAEntry(&e,"1.log");
	struct ALogEntry *r=readAEntry("1.log",1);
	printf("%d %s %s %s\n",r->logType,r->data,r->hashChain,r->msgAuth);
	*/

	//shell();
	return 0;
}
