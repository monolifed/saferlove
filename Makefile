COMMON_FLAGS := -Wall -Wextra -pedantic -std=c99
APPNAME := monocypher
JIT_INC="/usr/include/luajit-2.1"
JIT_DLL="path.to.luajit.dll"

ifeq ($(OS),Windows_NT)
	PLATFORM := w
	RM := del /Q
	EXT := .exe
	EXT_SO := .dll
	CC := gcc
	COMPILE := $(CC) $(COMMON_FLAGS) -c -O2 -I$(JIT_INC)
	LINK := $(CC) -O -shared
else
	PLATFORM := p
	EXT_SO := .so
	COMPILE := $(CC) $(COMMON_FLAGS) -c -fpic -O2 -I$(JIT_INC)
	LINK := $(CC) -O -shared -fpic
endif

monocypher$(EXT_SO) : utils.o monocypher.o
	$(LINK) -o $@ $^

safer$(EXT_SO) : safer.o monocypher.o
	$(LINK) -o $@ $^

utils.o : src/$(PLATFORM)utils.c src/utils.h
	$(COMPILE) -o $@ $<

monocypher.o : src/monocypher.c src/monocypher.h
	$(COMPILE) -o $@ $<

safer.o : src/safer.c src/loader.h publickey.h
	$(COMPILE) -o $@ $<


clean :
	$(RM) *.o
	$(RM) monocypher$(EXT_SO)
	$(RM) safer$(EXT_SO)
