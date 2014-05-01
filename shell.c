#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"

void shell()
{
	FILE *pCert=fopen("cert.pem","rb");
	if(pCert==NULL) {
		printf("could not find certificate\n");
		exit(0);

	}
	while(1) {
		char cmd[128];
		printf("Shell> ");
		gets(cmd);
		if(strcmp(cmd,"exit")==0) break;
		if(strcmp(cmd,"closelog")==0) {
			if(currentFile==NULL) {
				printf("no file has been opened\n");
				continue;
			}
			// TODO: call closelog function here
			closeLog(currentFile);

			continue;
		}
		// divide command
		char str[128],operation[128];
		sscanf(cmd,"%s",operation);
		if(strcmp(operation,"verifyall")==0) {
			/*
			if(currentFile==NULL) {
				printf("no file has been opened\n");
				continue;
			}
			*/
			char outputFile[128];
			sscanf(cmd,"%s %s %s",operation,str,outputFile);
			// TODO: call verify all
			FILE *fd=fopen(outputFile,"wb");
			testLog(str, -1,fd);
			fclose(fd);

			continue;
		}
		sscanf(cmd,"%s %s",operation,str);
		if(strcmp(operation,"verify")==0) {
			if(currentFile==NULL) {
				printf("no file has been opened\n");
				continue;
			}
			int entryNo;
			sscanf(str,"%d",&entryNo);
			if(entryNo<1) {
				printf("invalid entry number\n");
				continue;
			}
			// TODO: call verify entry function
			if(entryNo >= 1) {
				testLog(currentFile, entryNo,stdout);
			}
			else {
				//error
			}

			continue;
		}
		if(strcmp(operation,"add")==0) {
			if(currentFile==NULL) {
				printf("no file has been opened\n");
				continue;
			}
			int index=0;
			for(;index<strlen(cmd)-4;index++) str[index]=cmd[index+4];
			str[index]=0;
			// TODO: add message
			addEntry(currentFile,str);
			continue;
		}
		if(strcmp(operation,"createlog")==0) {
			FILE *pp=fopen(str,"r");
			if(pp!=NULL) {
				printf("log already exists\n");
				fclose(pp);
				continue;
			}
			// TODO: add message
			createLog(str);
			currentFile=(char *)malloc(strlen(str)+1);
			strcpy(currentFile,str);

			
			continue;
		}
		printf("Bad command\n");	
	} // while

}
