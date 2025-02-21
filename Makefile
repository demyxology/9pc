CC=gcc
CFLAGS=-Wall -O2

TARGET=9pc
SRCS=9pc.c util.c
OBJS=$(SRCS:.c=.o)

# Detect OS
ifeq ($(OS),Windows_NT)
    RM=del /F /Q
    TARGET_EXT=.exe
		LDFLAGS=-lws2_32
else
    RM=rm -f
    TARGET_EXT=
		LDFLAGS=
endif

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(TARGET)$(TARGET_EXT) $(OBJS)

.PHONY: clean
