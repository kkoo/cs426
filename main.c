#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *hello="hello world!";
	char *cipher=Encrypt("keykeykey",hello,strlen(hello));
	printf("%s\n",cipher);
	char *plain=Decrypt("keykeykey",cipher,strlen(cipher));
	printf("%s\n",plain);

	return 0;

}
