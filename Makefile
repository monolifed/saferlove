COMMON_FLAGS := -Wall -Wextra -Wvla -pedantic -std=c99
JIT_INC := "/usr/include/luajit-2.1"
JIT_DLL := "path.to.luajit.dll"

COMPILE_FLAGS := $(COMMON_FLAGS) -c -O2 -I$(JIT_INC)
LINK_FLAGS := -O2 -shared
ENCRYPT := luajit encrypt.lua

ifeq ($(OS),Windows_NT)
	UTILS_C := wutils.c
	RM := del /Q
	EXT := .dll
	CC := gcc
	LIBS := -l:$(JIT_DLL)
else
	UTILS_C := putils.c
	EXT := .so
	COMPILE_FLAGS := $(COMPILE_FLAGS) -fpic
	LINK_FLAGS := $(LINK_FLAGS) -fpic
endif

MONOCYPHER_SO := monocypher$(EXT)
SAFER_SO := safer$(EXT)

$(MONOCYPHER_SO) : utils.o monocypher.o
	$(CC) $(LINK_FLAGS) -o $@ $^

$(SAFER_SO) : safer.o monocypher.o
	$(CC) $(LINK_FLAGS) -o $@ $^ $(LIBS)

utils.o : src/$(UTILS_C) src/utils.h
	$(CC) $(COMPILE_FLAGS) -o $@ $<

monocypher.o : src/monocypher.c src/monocypher.h
	$(CC) $(COMPILE_FLAGS) -o $@ $<

safer.o : src/safer.c src/loader.lua src/publickey.h
	$(CC) $(COMPILE_FLAGS) -o $@ $<

src/publickey.h : encrypt.lua $(MONOCYPHER_SO) privatekey.lua
	$(ENCRYPT) generate header

privatekey.lua : encrypt.lua $(MONOCYPHER_SO)
	$(ENCRYPT) generate secret

encryptfiles : encrypt.lua filelist.lua $(MONOCYPHER_SO)
	$(ENCRYPT) encrypt filelist.lua

clean :
	$(RM) *.o
	$(RM) monocypher$(EXT_SO)
	$(RM) safer$(EXT_SO)
	$(RM) src/publickey.h