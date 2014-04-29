#define TIMEOUT 1000
#define CERT_FILE "cert.pem"
#define PUB_KEY_T "kt_pub.pem"
#define PUB_KEY_U "ku_pub.pem"
#define PRIV_KEY_T "kt_priv.pem"
#define PRIV_KEY_U "ku_priv.pem"



typedef enum {LOG_INIT, RESP_MSG, ABNORMAL_CLOSE, NORMAL_CLOSE} msg_type;
typedef enum {ID_UNTRUSTED, ID_TRUSTED, ID_VERIFY} machine_id;


struct ALogEntry {
	int logType;		//type
	char *data;			//encrypted Data
	char *hashChain;	//hash chain
	char *msgAuth;		//MAC
};

struct LogEntry {
	int timestamp;
	int timeout;
	int logID;
	struct Msg *message;
};

struct Msg {
	int p;
	int id;
	int xLen;
	int sigLen;
	char *pke;
	char *enc;
	int encLen;
};
