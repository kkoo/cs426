#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"

void writeAEntry(struct ALogEntry *e, char* fn)
{
	FILE *pf=fopen(fn,"a");
	if (pf==NULL) pf=fopen(fn,"wb");
	fprintf(pf,"%d\n",e->logType);

	fprintf(pf,"%s\n\n\n%s\n\n\n%s\n\n\n",e->data,e->hashChain,e->msgAuth);
	fclose(pf);


}

struct ALogEntry *readAEntry(char* fn)
{
	FILE *pf=fopen(fn,"rb");
	if(pf==NULL) {
		perror("fopen");
		printf("%s\n",fn);
		exit(0);
	}
	struct ALogEntry *e=(struct ALogEntry *)malloc(sizeof(struct ALogEntry));
	int type;
	fscanf(pf,"%d\n",&type);
	e->logType=type;
	char *data=(char *)malloc(sizeof(char)*256);
	char *hc=(char *)malloc(sizeof(char)*256);
	char *ma=(char *)malloc(sizeof(char)*256);
	memset(data,0,sizeof(char)*256);
	memset(hc,0,sizeof(char)*256);
	memset(ma,0,sizeof(char)*256);

	int index=0;
	while(1) {
		fread(&data[index],1,1,pf);
		if(index>=2) {
			if(data[index]=='\n' && data[index-1]=='\n' && data[index-2]=='\n') {
				data[index-2]=0;
				data[index-1]=0;
				data[index]=0;
				break;
			}
		}
		index++;
	} //while
	index=0;
	while(1) {
		fread(&hc[index],1,1,pf);
		if(index>=2) {
			if(hc[index]=='\n' && hc[index-1]=='\n' && hc[index-2]=='\n') {
				hc[index-2]=0;
				hc[index-1]=0;
				hc[index]=0;
				break;
			}
		}
		index++;
	} //while
	index=0;
	while(1) {
		fread(&ma[index],1,1,pf);
		if(index>=2) {
			if(ma[index]=='\n' && ma[index-1]=='\n' && ma[index-2]=='\n') {
				ma[index-2]=0;
				ma[index-1]=0;
				ma[index]=0;
				break;
			}
		}
		index++;
	} //while
	e->data=data;
	e->hashChain=hc;
	e->msgAuth=ma;
	return e;
	fclose(pf);
}
