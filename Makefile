# Detect OS
ifeq ($(OS),Windows_NT)
    # Windows-specific settings (MSVC)
    CC=cl.exe
    CFLAGS=
    RM=del /F /Q
    TARGET_EXT=.exe
    WINFSP_INCLUDE="C:\Program Files (x86)\WinFSP\inc"
    WINFSP_LIB="C:\Program Files (x86)\WinFSP\lib"
    CFLAGS+=/I$(WINFSP_INCLUDE)
    LDFLAGS=/link /LIBPATH:$(WINFSP_LIB) winfsp-x64.lib ws2_32.lib
    OBJEXT=.obj
else
    # Unix-specific settings (GCC)
    CC=gcc
    CFLAGS=-Wall -O2
    RM=rm -f
    TARGET_EXT=
    LDFLAGS=
    OBJEXT=.o
endif

TARGET=9pc
SRCS=9pc.c util.c passthrough.c
OBJS=$(SRCS:.c=$(OBJEXT))

all: $(TARGET)$(TARGET_EXT)

ifeq ($(OS),Windows_NT)
# Windows/MSVC specific build rules
$(TARGET)$(TARGET_EXT): $(OBJS)
	$(CC) $(OBJS) /Fe$(TARGET)$(TARGET_EXT) $(LDFLAGS)

%.obj: %.c
	$(CC) $(CFLAGS) /c $< /Fo$@
else
# Unix/GCC specific build rules
$(TARGET)$(TARGET_EXT): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
endif

clean:
	$(RM) $(TARGET)$(TARGET_EXT) $(OBJS)

.PHONY: clean all