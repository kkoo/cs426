EXE=test
all:
	gcc -c -g -w main.c 
	gcc -c -g -w des.c
	gcc -c -g -w rsa.c
	gcc -c -g -w sha1.c
	gcc -c -g -w helper.c
	gcc -c -g -w shell.c
	gcc -c -g -w writeEntry.c
	gcc -c -g -w writeAEntry.c
	gcc -c -g -w hmac.c
	gcc -w -o $(EXE) main.o writeAEntry.o writeEntry.o des.o sha1.o rsa.o helper.o shell.o hmac.o -lcrypto -lm

clean:
	rm *.o
	rm $(EXE)
