#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"

void writeEntry(struct LogEntry *e, char* fn)
{
	FILE *pf=fopen(fn,"wb");

	fprintf(pf,"%d %d %d ",e->timestamp,e->timeout,e->logID);
	fprintf(pf,"%d %d %d %d %d\n",e->message->p,e->message->id,e->message->xLen,e->message->sigLen,e->message->encLen);

	fprintf(pf,"%s\n\n\n%s\n\n\n",e->message->pke,e->message->enc);

	fclose(pf);


}

struct LogEntry *readEntry(char *fn)
{
	FILE *pf=fopen(fn,"rb");
	int ts,to,logID,p,id,xLen,sigLen;
	int encLen;
	fscanf(pf,"%d %d %d %d %d %d %d %d\n",&ts,&to,&logID,&p,&id,&xLen,&sigLen,&encLen);
	char *enc=(char *)malloc(sizeof(char)*(encLen+1));
	char *pke=(char *)malloc(sizeof(char)*1024);
	memset(pke,0,1024);
	memset(enc,0,encLen+1);
	//fscanf(pf,"%s\n\n\n%s\n\n\n",pke,enc);
	int index=0;
	while(1) {
		fread(&pke[index],1,1,pf);
		if(index>=2) {
			if(pke[index]=='\n' && pke[index-1]=='\n' && pke[index-2]=='\n') {
				pke[index-2]=0;
				pke[index-1]=0;
				pke[index]=0;
				break;
			}
		}
		index++;
	} //while
	index=0;
	while(1) {
		fread(&enc[index],1,1,pf);
		if(index>=2) {
			if(enc[index]=='\n' && enc[index-1]=='\n' && enc[index-2]=='\n') {
				enc[index-2]=0;
				enc[index-1]=0;
				enc[index]=0;
				break;
			}
		}
		index++;
	} //while
	struct LogEntry *ret=(struct logEntry *)malloc(sizeof(struct LogEntry));
	ret->timestamp=ts;	
	fclose(pf);
	ret->timeout=to;
	ret->logID=logID;
	ret->message=(struct Msg *)malloc(sizeof(struct Msg));
	ret->message->p=p;
	ret->message->id=id;
	ret->message->xLen=xLen;
	ret->message->sigLen=sigLen;
	ret->message->encLen=encLen;
	ret->message->pke=pke;
	ret->message->enc=enc;
	
	return ret;
}
