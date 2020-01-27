#include <stdio.h>
#include <string.h>
#include "utils.h"

// Fixme: there should be a more standard secure zero function?
void *zeromemory(void *dst, size_t dstlen)
{
	void *ret;
#if defined(__GNUC__) || defined(__clang__)
	ret = memset(dst, '\0', dstlen);
	__asm__ volatile("" : : "g"(dst) : "memory");
#else
	volatile char *volatile p;
	p = (volatile char *volatile) dst;
	size_t i = 0;
	while (i < dstlen)
	{
		p[i++] = 0;
	}
	ret = dst;
#endif
	return ret;
}


#include <termios.h>
#include <wchar.h>

#if __WCHAR_MAX__ < 0x10FFFF
// Fixme: Because then fgetws will use some non-standard wchar encoding.
//        However if the terminal encoding is already utf-8,
//        there is no (need for any) conversion anyway.
#pragma message "Unsupported wchar_t type"
#define NOCONVERSION
#endif

#ifndef NOCONVERSION

#include <locale.h>
#include <langinfo.h>

#define UTF8_1 0x007FUL
#define UTF8_2 0x07FFUL
#define UTF8_3 0xFFFFUL
#define UTF8_4 0x10FFFFUL
static int uc_toutf8(unsigned long uc, unsigned char *utf8)
{
	if (uc <= UTF8_1)
	{
		utf8[0] = uc;
		return 1;
	}
	if (uc <= UTF8_2)
	{
		utf8[0] = 0xC0 | ((uc >> 6) & 0x1F);
		utf8[1] = 0x80 | ((uc >> 0) & 0x3F);
		return 2;
	}
	if (uc <= UTF8_3)
	{
		utf8[0] = 0xE0 | ((uc >> 12) & 0x0F);
		utf8[1] = 0x80 | ((uc >>  6) & 0x3F);
		utf8[2] = 0x80 | ((uc >>  0) & 0x3F);
		return 3;
	}
	if (uc <= UTF8_4)
	{
		utf8[0] = 0xF0 | ((uc >> 18) & 0x07);
		utf8[1] = 0x80 | ((uc >> 12) & 0x3F);
		utf8[2] = 0x80 | ((uc >>  6) & 0x3F);
		utf8[3] = 0x80 | ((uc >>  0) & 0x3F);
		return 4;
	}
	return 0;
}

static int uc_utf8len(unsigned long uc)
{
	if (uc <= UTF8_1) { return 1; }
	if (uc <= UTF8_2) { return 2; }
	if (uc <= UTF8_3) { return 3; }
	if (uc <= UTF8_4) { return 4; }
	return 0;
}

static size_t wcs_utf8len(const wchar_t *wcs, size_t wcslen)
{
	int len;
	size_t tlen = 0;
	for (unsigned i = 0; i < wcslen; i++)
	{
		len = uc_utf8len(wcs[i]);
		if (len == 0)
			return 0;
		tlen += len;
	}
	return tlen;
}

static int wcs_toutf8(const wchar_t *wcs, size_t wlen, unsigned char *out, size_t outlen)
{
	if (wlen == 0)
		return 0;
		
	size_t tlen = wcs_utf8len(wcs, wlen);
	if (tlen == 0 || outlen < tlen)
		return -1;
		
	unsigned char *p = out;
	for (unsigned i = 0; i < wlen; i++)
	{
		p += uc_toutf8(wcs[i], p);
	}
	return tlen;
}

// read as wchar convert to utf8
static int readpassword_utf8(char *out, size_t outlen)
{
	wchar_t input[MAX_INPUTWCS];
	wchar_t *wp = fgetws(input, MAX_INPUTWCS, stdin);
	if (wp == NULL)
		return 0;
		
	int len = wcscspn(input, L"\r\n");
	if (len == 0)
		return 0;
		
	len = wcs_toutf8(input, len, (unsigned char *) out, outlen - 1);
	zeromemory(input, sizeof input);
	if (len <= 0)
		return 0;
		
	out[len] = 0;
	return len;
}
#endif // NOCONVERSION

// read directly, no conversion
static int readpassword_nc(char *out, size_t outlen)
{
	out = fgets(out, outlen, stdin);
	if (out == NULL)
		return 0;
		
	int len = strcspn(out, "\r\n");
	if (len == 0)
		return 0;
		
	out[len] = 0;
	return len;
}

int readpassword(const char *prompt, char *out, size_t outlen)
{
	printf("%s", prompt);
	static struct termios told, tnew;
	tcgetattr(0, &told);
	tnew = told;
	tnew.c_lflag &= ~ICANON;
	tnew.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &tnew);
	
	int ret;
#ifndef NOCONVERSION
	if (strcmp(nl_langinfo(CODESET), "UTF-8") != 0) // convert to utf8 if needed
	{
		ret = readpassword_utf8(out, outlen);
	}
	else
#endif // NOCONVERSION
	{
		ret = readpassword_nc(out, outlen);
	}
	
	tcsetattr(0, TCSANOW, &told);
	printf("\n");
	return ret;
}

#include <sys/random.h>
int randmemory(void *dst, size_t dstlen)
{
	return getrandom(dst, dstlen, 0);
}
