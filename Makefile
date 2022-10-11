CC=gcc
CFLAGS=-Wall
LDFLAGS=
SOURCES=lib/aes.c lib/sha1.c lib/des.c lib/aes_omac.c lib/keys.c lib/kgen.c lib/aes_xts.c lib/util.c lib/indiv.c lib/eid.c lib/main.c
EXECUTABLE=decrypt_tools
all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)
clean:
	rm -rf $(EXECUTABLE)
