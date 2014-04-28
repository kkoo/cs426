EXE=test
all:
	gcc -c -g main.c 
	gcc -c -g des.c
	gcc -c -g rsa.c
	gcc -c -g sha1.c
	gcc -c -g helper.c
	gcc -c -g shell.c
	gcc -o $(EXE) main.o des.o sha1.o rsa.o helper.o shell.o -lcrypto -lm

clean:
	rm *.o
	rm $(EXE)
