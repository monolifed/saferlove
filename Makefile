COMMON_FLAGS := -Wall -Wextra -pedantic -std=c99
JIT_INC := "/usr/include/luajit-2.1"
JIT_DLL := "path.to.luajit.dll"

COMPILE := $(CC) $(COMMON_FLAGS) -c -O2 -I$(JIT_INC)
LINK := $(CC) -O -shared
ENCRYPT := luajit encrypt.lua

ifeq ($(OS),Windows_NT)
	PREFIX := w
	RM := del /Q
	EXT := .exe
	EXT_SO := .dll
	CC := gcc
	LIBS := -l:$(JIT_DLL)
else
	PREFIX := p
	EXT_SO := .so
	COMPILE := $(COMPILE) -fpic
	LINK := $(LINK) -fpic
endif

MONOCYPHER_SO := monocypher$(EXT_SO)
SAFER_SO := safer$(EXT_SO)
UTILS_C := $(PREFIX)utils.c

$(MONOCYPHER_SO) : utils.o monocypher.o
	$(LINK) -o $@ $^

$(SAFER_SO) : safer.o monocypher.o
	$(LINK) -o $@ $^ $(LIBS)

utils.o : src/$(UTILS_C) src/utils.h
	$(COMPILE) -o $@ $<

monocypher.o : src/monocypher.c src/monocypher.h
	$(COMPILE) -o $@ $<

safer.o : src/safer.c src/loader.lua src/publickey.h
	$(COMPILE) -o $@ $<

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