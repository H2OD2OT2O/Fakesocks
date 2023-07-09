CC = gcc

main: main.c utils.c
	$(CC) main.c utils.c -lmbedtls -lmbedx509 -lmbedcrypto -o bin/main

server: server.c utils.c
	$(CC) server.c utils.c -lmbedtls -lmbedx509 -lmbedcrypto -o bin/server

client: client.c utils.c
	$(CC) client.c utils.c -lmbedtls -lmbedx509 -lmbedcrypto -o bin/client

clean:
	rm main main.o utils.o 