#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void shell()
{
	while(1) {
		char cmd[128];
		printf("Shell> ");
		gets(cmd);
		if(strcmp(cmd,"exit")==0) break;
		if(strcmp(cmd,"closelog")==0) {
			printf("Closing opened log...\n");
			// TODO: call closelog function here

			continue;
		}
		// divide command
		char str[128],operation[128];
		sscanf(cmd,"%s",operation);
		if(strcmp(operation,"verifyall")==0) {
			char outputFile[128];
			sscanf(cmd,"%s %s %s",operation,str,outputFile);
			printf("Verifying all entries in %s, directing output to %s...\n",str,outputFile);
			// TODO: call verify all
			continue;
		}
		sscanf(cmd,"%s %s",operation,str);
		if(strcmp(operation,"verify")==0) {
			int entryNo;
			sscanf(str,"%d",&entryNo);
			printf("Verifying entry %d...\n",entryNo);
			// TODO: call verify entry function

			continue;
		}
		if(strcmp(operation,"add")==0) {
			int index=0;
			for(;index<strlen(cmd)-4;index++) str[index]=cmd[index+4];
			str[index]=0;
			printf("Adding message string \"%s\"...\n",str);
			// TODO: add message
			
			continue;
		}
		if(strcmp(operation,"createlog")==0) {
			printf("Creating log %s ..\n",str);
			// TODO: add message
			
			continue;
		}
		printf("Bad command\n");	
	} // while

}
