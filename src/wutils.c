#include <windows.h>
#include <conio.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

#include "utils.h"

// Todo: calculate the encoded length as characters entered
int readpassword(const char *prompt, char *out, size_t outl)
{
	printf("%s", prompt);
	wchar_t input[MAX_INPUTWCS];
	wint_t c;
	int i;
	for (i = 0; i < MAX_INPUTWCS - 1; i++)
	{
		c = _getwch();
		if (c == L'\r')
		{
			//input[i++] = 0;
			break;
		}
		input[i] = c;
	}
	input[i] = 0;
	printf("\n");
	int err = 0;
	int len = WideCharToMultiByte(CP_UTF8, 0, input, i, out, outl - 1, NULL, NULL);
	SecureZeroMemory(input, sizeof input);
	
	if (len == 0 || len == 0xFFFD)
	{
		err = GetLastError();
	}
	out[len] = 0;
	if (err != 0)
	{
		fprintf(stderr, "WideCharToMultiByte got error code %i\n", err);
		return 0;
	}
	return len;
}

void *zeromemory(void *dst, size_t dstlen)
{
	return SecureZeroMemory(dst, dstlen);
}

#include <bcrypt.h>
int randmemory(void *dst, size_t dstlen)
{
	if (BCryptGenRandom(NULL, dst, dstlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS)
		return dstlen;
	return 0;
}