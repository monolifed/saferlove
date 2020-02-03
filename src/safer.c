#include <lua.h>
#include <lauxlib.h>

#include "monocypher.h"

#include "loader.lua"
// char LOADER_LUA[]
#include "publickey.h"
// uint8_t publickey[32], encryptkey[32], xor0, ..., xor7
// #define LE_XOR_N or BE_XOR_N

#define SZNONCE 24
#define SZMAC 16
#define SZSIGN 64
#define SZEXTRA (SZNONCE + SZMAC + SZSIGN)

uint8_t enckey[32]; // the reconstructed key

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
	int text_size = buffer_size - SZEXTRA;
	if (text_size < 0)
	{
		printf("Unlock: file '%s' has invalid size\n", filename);
		return 0;
	}
	
	const uint8_t *buffer = (uint8_t *) luaL_checkstring(L, -2);
	const uint8_t *nonce  = buffer;
	const uint8_t *mac    = nonce  + SZNONCE;
	const uint8_t *cypher = mac    + SZMAC;
	
	uint8_t text[text_size + SZSIGN]; // text+sign is encrypted
	if (crypto_unlock(text, enckey, nonce, mac, cypher, sizeof text) != 0)
	{
		printf("Unlock: file '%s' is not signed\n", filename);
		return 0;
	}
	
	const uint8_t *sign = text + text_size;
	if (crypto_check(sign, publickey, text, text_size) != 0)
	{
		printf("Unlock: file '%s' is not signed\n", filename);
		return 0;
	}
	
	luaL_loadbuffer(L, (char *) text, text_size, filename);
	crypto_wipe(text, sizeof text);
	return 1;
}


LUALIB_API int luaopen_safer_core(lua_State *L)
{
	// FIXME: do it right before decryption and wipe the key?
	#define XR(N) xor##N
	
	#ifdef LE_XOR_N // little endian
	  #define XE(N) \
	    enckey[4 * N    ] = (XR(N)      ) & 0xFF; enckey[4 * N + 1] = (XR(N) >>  8) & 0xFF; \
	    enckey[4 * N + 2] = (XR(N) >> 16) & 0xFF; enckey[4 * N + 3] = (XR(N) >> 24) & 0xFF;
	#endif
	
	#ifdef BE_XOR_N // big endian
	  #define XE(N) \
	    enckey[4 * N    ] = (XR(N) >> 24) & 0xFF; enckey[4 * N + 1] = (XR(N) >> 16) & 0xFF; \
	    enckey[4 * N + 2] = (XR(N) >>  8) & 0xFF; enckey[4 * N + 3] = (XR(N)      ) & 0xFF;
	#endif
	
	XE(0) XE(1) XE(2) XE(3) XE(4) XE(5) XE(6) XE(7)
	
	#undef XE
	#undef XR
	
	for (int i = 0; i < 32; i++)
	{
		enckey[i] = enckey[i] ^ encryptkey[i];
	}
	
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

