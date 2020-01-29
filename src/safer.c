#include <lua.h>
#include <lauxlib.h>

#include "monocypher.h"

#include "loader.lua"  // const char LOADER_LUA[]
#include "publickey.h" // #define PUBLICKEY

#define SZNONCE 24
#define SZMAC 16
#define SZSIGN 64
#define SZHEADER (SZNONCE + SZMAC + SZSIGN)

static int load(lua_State *L)
{
	const char *filename = luaL_checkstring(L, 1);
	lua_getfield(L, LUA_GLOBALSINDEX, "love");
	lua_getfield(L, -1, "filesystem");
	lua_getfield(L, -1, "read");
	lua_pushvalue(L, 1);
	lua_call(L, 1, 2);
	if (lua_isnil(L, -2)) { return 0; }
	
	int buffer_size = luaL_checkint(L, -1);
	int cypher_size = buffer_size - SZHEADER;
	if (cypher_size < 0)
	{
		printf("Unlock: file '%s' has invalid size\n", filename);
		return 0;
	}
	
	const uint8_t *buffer = (uint8_t *) luaL_checkstring(L, -2);
	const uint8_t *nonce  = buffer;
	const uint8_t *mac    = nonce + SZNONCE;
	const uint8_t *sign   = mac   + SZMAC;
	const uint8_t *cypher = sign  + SZSIGN;
	
	if (crypto_check(sign, (uint8_t *)PUBLICKEY, cypher, cypher_size) != 0)
	{
		printf("Unlock: file '%s' is not signed\n", filename);
		return 0;
	}
	
	uint8_t text[cypher_size];
	if (crypto_unlock(text, (uint8_t *)PUBLICKEY, nonce, mac, cypher, cypher_size) != 0)
	{
		printf("Unlock: file '%s' is not signed\n", filename);
		return 0;
	}
	
	luaL_loadbuffer(L, (char *) text, sizeof text, filename);
	return 1;
}

LUALIB_API int luaopen_safer_core(lua_State *L)
{
	lua_pushcfunction(L, load);
	return 1;
}

LUALIB_API int luaopen_safer(lua_State *L)
{
	if (luaL_dostring(L, LOADER_LUA))
	{
		printf("Safer: luaL_dostring error\n");
	}
	return 0;
}

