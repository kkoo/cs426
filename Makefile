EXE=test
all:
	gcc -c main.c 
	gcc -c des.c
	gcc -o $(EXE) main.o des.o -lcrypto -lm

clean:
	rm *.o
	rm $(EXE)
