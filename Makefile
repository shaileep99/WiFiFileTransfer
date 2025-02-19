CC = gcc
CFLAGS = -Wall -g -lcrypto -lpthread

TARGET = file_transfer
OBJS = file_transfer.o encryption.o decryption.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(CFLAGS)

file_transfer.o: file_transfer.c encryption.h decryption.h
	$(CC) -c file_transfer.c $(CFLAGS)

encryption.o: encryption.c encryption.h
	$(CC) -c encryption.c $(CFLAGS)

decryption.o: decryption.c decryption.h
	$(CC) -c decryption.c $(CFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
