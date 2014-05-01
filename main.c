// This is a test for encryption/decryption functions
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "project.h"

const int ENTRYNO_OFFSET = 1;

int logID;
int stepNum;

char *currentFile;
char *A0;
char *_logAuthKey;
char *_hashChain;
char *_sessionKey;

int createLog(char *fn) {	
	logID = createRandomNum();
	stepNum = 0;
	////////////////STARTUP from U////////////////
	//create first message
	
	//INIT values
	char *x = "aaaaaaaaaaaaa";
	char *hashX = hash(x);
	
	_hashChain = (char *)malloc(20+1); // the initial hash chain
	memset(_hashChain, 'a', 20+1); 

	_logAuthKey = intToStr(createRandomNum());		//A
	A0 = _logAuthKey;

	char *msgAuthCode; 								//Z

	//_sessionKey = createFirstKey();				//K
	_sessionKey = createKey(LOG_INIT, _logAuthKey);

	//create msg for T
	struct Msg *msg = createMsg(stepNum, ID_UNTRUSTED, PUB_KEY_T, PRIV_KEY_U, _sessionKey, x);
	
	//create first log entry
	char *data = logToStr(createLogEntry(LOG_INIT, logID, msg));
	//char *data = logToStr2(createLogEntry(LOG_INIT, logID, msg));
	char *encData = encryptData(data, _sessionKey, strlen(data)); 

	_hashChain = createY(_hashChain, encData, LOG_INIT);
	msgAuthCode = genMAC(_logAuthKey, _hashChain);

	struct ALogEntry *firstLog = createALogEntry(LOG_INIT, encData, _hashChain, msgAuthCode);
	writeAEntry(firstLog, fn);
	//////////////END STARTUP from U////////////////


	/////////////RECIEVE  T//////////////

	//verify the message
	int result = verifyMsg(msg, PRIV_KEY_T, PUB_KEY_U);
	//printf("Result from T:%d\n", result);
	//TODO: check valid certificate

	//increment protocol step ID;
	int p = msg->p + 1;

	//create X1
	char *x0 = getX(msg, PRIV_KEY_T, PUB_KEY_U);
	char *x1 = "ZZZ";

	//create session key
	char *sessionKeyT = createKey(RESP_MSG, _logAuthKey);
	
	//create msg
	struct Msg *msg1 = createMsg(p, ID_TRUSTED, PUB_KEY_U, PRIV_KEY_T, sessionKeyT, x1);
	/////////////END  RECIEVE  T//////////////



	/////////////FINALIZE INIT U///////////////////
	//verify the msg
	result = verifyMsg(msg1, PRIV_KEY_U, PUB_KEY_T);
	//printf("Result from U:%d\n", result);

	//get the data
	data = logToStr(createLogEntry(RESP_MSG, logID, msg1));

	//update hash chains and keys
	_logAuthKey = hash(_logAuthKey);						//A+1 = H(A)			
	_sessionKey = createKey(NORMAL_MSG, _logAuthKey);		//K
	encData = encryptData(data, _sessionKey, strlen(data));

	//MSG Authentication
	_hashChain = createY(_hashChain, encData, RESP_MSG);	//Y+1 = H(y, encData, logtype)
	msgAuthCode = genMAC(_logAuthKey, _hashChain);		//Z = MAC(Y)
	struct ALogEntry *secondLog = createALogEntry(RESP_MSG, encData, _hashChain, msgAuthCode);

	writeAEntry(secondLog, fn);
}

int addEntry(char *fileName, char *msg) {
	int logType = NORMAL_MSG;
	char *encData;
	char *msgAuthCode;

	_logAuthKey = hash(_logAuthKey);						//A+1 = H(A)			
	_sessionKey = createKey(NORMAL_MSG, _logAuthKey);		//K
	encData = encryptData(msg, _sessionKey, strlen(msg));

	//MSG Authentication
	_hashChain = createY(_hashChain, encData, logType);		//Y+1 = H(y, encData, logtype)
	msgAuthCode = genMAC(_logAuthKey, _hashChain);			//Z = MAC(Y)

	struct ALogEntry *newEntry = createALogEntry(logType, encData, _hashChain, msgAuthCode);

	writeAEntry(newEntry, fileName);
}

int closeLog(char *fn) {
	char *encData;
	char *msgAuthCode;
	char *msg = intToStr(getTimeStamp());

	_logAuthKey = hash(_logAuthKey);						//A+1 = H(A)
	_sessionKey = createKey(NORMAL_CLOSE, _logAuthKey);		//K
	encData = encryptData(msg, _sessionKey, strlen(msg));

	//MSG Authentication
	_hashChain = createY(_hashChain, encData, NORMAL_CLOSE);		//Y+1 = H(y, encData, logtype)
	msgAuthCode = genMAC(_logAuthKey, _hashChain);					//Z = MAC(Y)

	struct ALogEntry *finalLog = createALogEntry(NORMAL_CLOSE, encData, _hashChain, msgAuthCode);
	writeAEntry(finalLog, fn);
	currentFile=NULL;
}

//verifies log entry
//verifies all log entry if entryNo = -1
void testLog(char *fn, int entryNo, FILE *fd) {
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
	int normalClose = 0;

	while(fileOpen) {
		//break if not "verifyall" entryNO has been reached
		if(entryNo != -1 && i-ENTRYNO_OFFSET > entryNo) {
			normalClose = 1;
			break;
		}

		struct ALogEntry *entry = readAEntry(fn, i);
		if(entry == NULL) {
			logValid = 0;
			break;
		}
		//check if log has been initialized
		if(i == 0 && entry->logType != LOG_INIT) {
			logValid = 0;
			break;
		}
		else if(i == 1 && entry->logType != RESP_MSG) {
			logValid = 0;
			break;
		}

		if(entry->logType == NORMAL_CLOSE) {
			//NORMAL close before the entryNo
			if(entryNo != -1) {
				//entryNo does not exist
				if(i-ENTRYNO_OFFSET <= entryNo) {
					logValid = 0;
					break;
				}
			}

			normalClose = 1;
			break;
		}

		//authenticate the log
		char *msgAuthCmp = genMAC(authKey, entry->hashChain);
		int result = strcmp(entry->msgAuth,msgAuthCmp);

		if(result != 0) {
			logValid = 0; //printf("Invalid Log entry:%d\n", i);
			break;
		}
		else {
			logValid = 1; //printf("Valid Log entry:%d\n", i);
		}

		logType = entry->logType;
		data = entry->data;
		prevHashChain = entry->hashChain;
		msgAuth = entry->msgAuth;

		//next authKey
		authKey = hash(authKey);
		
		i++;
	}
	if(logValid == 1 && normalClose == 1) {
		decryptLog(fn, entryNo, fd);
	}
	else {
		fprintf(fd, "Failed verification\n");
	}
}

void decryptLog(char *fn, int entryNo, FILE *fd) {
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
	int normalClose = 0;
	while(fileOpen) {
		if(entryNo != -1 && i-ENTRYNO_OFFSET > entryNo){
			break;
		}

		struct ALogEntry *entry = readAEntry(fn, i);
		if(entry == NULL) {
			break;
		}

		if(entry->logType == NORMAL_MSG || entry->logType == LOG_INIT || entry->logType == NORMAL_CLOSE) {
			if(entry->logType == LOG_INIT) {
				fprintf(fd, "%s", "LOG_INIT:");
			}
			else if(entry->logType == NORMAL_CLOSE) {
				fprintf(fd, "%s", "NORMAL_CLOSE:");
			}
			//char *decKey = _sessionKey;
			char *decKey = createKey(entry->logType, authKey);
			char *text = des_decrypt(decKey, entry->data, strlen(entry->data));
			if(text != NULL) {
				if(entryNo == -1) {
					fprintf(fd, "%s\n", text);
				}
				else if(i-ENTRYNO_OFFSET == entryNo) {
					fprintf(fd, "%s\n", text);
				}
			}
		}
		if(entry->logType == NORMAL_CLOSE) {
			break;
		}

		logType = entry->logType;
		data = entry->data;
		prevHashChain = entry->hashChain;
		msgAuth = entry->msgAuth;

		//next authKey
		authKey = hash(authKey);
		
		i++;
	}
}


int main(int argc, char **argv)
{

	currentFile=NULL;
	shell();
	
	return 0;
}
