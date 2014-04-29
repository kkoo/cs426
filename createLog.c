#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int createLog(char* logName)
{
	printf("U is initializing...\n");
	char *k0;
	k0=createFistKey();
	printf("K0=\n%s \n\n",k0);

	char *ts=intToStr(getTimeStamp());
	printf("timestamp=\n%s \n\n",ts);

	char* idLog=intToStr(0);
	printf("IDlog=\n%s \n\n",idLog);

	int a0=sha1_digest( intToStr(createRandomNum()) );
	printf("A0=\n%s \n\n",a0);

	char *pke=rsa_encrypt(k0,"kt_pub.pem");
	printf("PKE-PKT(K0)=\n%s \n\n",pke);



	char x0[1024];
	memset(x0,0,1024);
	strcpy(x0,"0");
	strcat(x0,"0");
	strcat(x0,"Certificate");
	strcat(x0,a0);
	int len;
	char *sig=rsa_sign(x0,"ku_priv.pem",&len);
	printf("X0=\n%s\n\n",x0);
	printf("sign(x0)=\n%s\n\n",sig);

	


}
