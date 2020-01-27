#include <lua.h>
#include <lauxlib.h>
#include <string.h>

#include "monocypher.h"

#include "loader.h"
#include "../publickey.h"

static void rawsetfield(lua_State *L, int t, const char *k)
{
#if LUA_VERSION_NUM >= 502
	t = lua_absindex(L, t);
#else
	t = (t > 0 || t <= LUA_REGISTRYINDEX) ? t : (lua_gettop(L) + t + 1);
#endif
	lua_pushstring(L, k);
	lua_insert(L, -2);
	lua_rawset(L, t);
}

#define SZNONCE 24
#define SZMAC 16
#define SZSIGN 64
#define SZHEADER (SZNONCE + SZMAC + SZSIGN)

static int unlock(const char key[32], char *buffer, size_t buffer_size)
{
	size_t text_size = buffer_size - SZHEADER;
	uint8_t *nonce = (uint8_t *)buffer;
	uint8_t *mac   = nonce + SZNONCE;
	uint8_t *sign  = mac   + SZMAC;
	uint8_t *text  = sign  + SZSIGN;

	if (buffer_size < SZHEADER)
	{
		printf("Unlock: file is too small\n");
		return -3;
	}
	
	if (crypto_check(sign, (uint8_t *)key, text, text_size) != 0)
	{
		printf("Unlock: file is unsigned\n");
		return -2;
	}
	 
	if (crypto_unlock(text, (uint8_t *)key, nonce, mac, text, text_size) != 0)
	{
		printf("Unlock: file is corrupt\n");
		return -1;
	}
	
	return 0;
}

static int load(lua_State *L)
{
	const char *filename = luaL_checkstring(L, 1);
	lua_getfield(L, LUA_GLOBALSINDEX, "love");
	lua_getfield(L, -1, "filesystem"); lua_remove(L, -2);
	lua_getfield(L, -1, "read");       lua_remove(L, -2);
	lua_pushvalue(L, 1);
	lua_call(L, 1, 2);
	if (lua_isnil(L, -2))
		return 0;
	
	int buffer_size = luaL_checkint(L, -1);
	char buffer[buffer_size];
	const char *s = luaL_checkstring(L, -2);
	memcpy(buffer, s, buffer_size);
	
	if (unlock(publickey, buffer, buffer_size) != 0)
		return 0;
	luaL_loadbuffer(L, buffer + SZHEADER, buffer_size - SZHEADER, filename);
	return 1;
}

LUALIB_API int luaopen_safer_core(lua_State *L)
{
	lua_pushcfunction(L, load);
	return 1;
}

LUALIB_API int luaopen_safer(lua_State *L)
{
	if (luaL_dostring(L, loader)) printf("luaL_dostring error\n");
	return 0;
}

