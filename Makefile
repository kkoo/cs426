EXE=test
all:
	gcc -c -g main.c 
	gcc -c -g des.c
	gcc -c -g rsa.c
	gcc -c -g sha1.c
	gcc -o $(EXE) main.o des.o sha1.o -lcrypto -lm

clean:
	rm *.o
	rm $(EXE)
