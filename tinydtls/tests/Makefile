
SERVER := dtls-server
CLIENT := dtls-client

CFLAGS := -I.. -Wall -g -O2 -DNDEBUG
LIBS := ../libtinydtls.a

all:
	gcc $(CFLAGS) $(SERVER).c $(LIBS) -o $(SERVER)
	gcc $(CFLAGS) $(CLIENT).c $(LIBS) -o $(CLIENT)

clean:
	@rm -f $(SERVER) $(CLIENT) *.o *.exe

