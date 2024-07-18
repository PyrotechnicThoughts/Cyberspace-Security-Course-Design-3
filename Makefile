all: server client middle test

server: ./codes/server.c
	gcc ./codes/server.c ./codes/utils.c ./codes/aes.c ./codes/diffie.c -o ./cmd/server -Wall -g -O2 -lpthread -lgmp -lcrypto

client: ./codes/client.c
	gcc ./codes/client.c ./codes/utils.c ./codes/aes.c ./codes/diffie.c -o ./cmd/client -Wall -g -O2 -lgmp -lcrypto

middle: ./codes/middle.c
	gcc ./codes/middle.c ./codes/utils.c ./codes/aes.c ./codes/diffie.c -o ./cmd/middle -Wall -g -O2 -lpthread -lgmp -lcrypto

test: ./test/test.c
	gcc ./test/test.c -o ./cmd/test -Wall -g -lgmp

clean: 
	rm ./cmd/server ./cmd/client ./cmd/middle ./cmd/test