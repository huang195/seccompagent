all: client server

client: client.c
	gcc -o client client.c -lssl -lcrypto

server: server.c
	gcc -o server server.c -lssl -lcrypto

clean:
	rm -f client server
