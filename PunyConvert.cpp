#include <stdlib.h>
#include <string.h>
#include "PunyConvert.h"

punycode_uint ConvertToPunycode(const wchar_t *src, punycode_uint len, char *dst, punycode_uint cap)
{
	punycode_uint ret = 0;
	const UTF16 *source = reinterpret_cast<const UTF16 *>(src);
	punycode_uint codepoints[512];
	UTF32 *target = reinterpret_cast<UTF32 *>(codepoints);
	if (ConvertUTF16toUTF32(
		&source, source + len,
		&target, target + len,
		strictConversion) == conversionOK)
	{
		punycode_uint cap32 = cap - 5;
		if (punycode_encode(
			target - reinterpret_cast<UTF32 *>(codepoints),
			codepoints,
			NULL, &cap32, dst + 4) == punycode_success)
		{
			*dst++ = 'x';
			*dst++ = 'n';
			*dst++ = '-';
			*dst++ = '-';
			ret = cap32 + 4;
		}
	}
	dst[ret] = '\0';
	return ret;
}

void ConvertToPunycode(const wchar_t *src, char *dst, punycode_uint cap)
{
	while (punycode_uint eat = *src == L'.' ? 1 : wcscspn(src, L"."))
	{
		punycode_uint len = eat;
		do
		{
			--len;
			if (src[len] > 0x7F)
			{
				len = ConvertToPunycode(src, eat, dst, cap);
				break;
			}
		} while (len != 0);
		if (len == 0)
		{
			do
			{
				*dst++ = static_cast<char>(*src++);
			} while (--eat);
		}
		dst += len;
		cap -= len;
		src += eat;
	}
	*dst = '\0';
}

punycode_uint ConvertFromPunycode(const char *src, punycode_uint len, char *dst, punycode_uint cap)
{
	punycode_uint ret = 0;
	punycode_uint codepoints[512];
	punycode_uint cap32 = _countof(codepoints);
	if (src[0] == 'x' && src[1] == 'n' && src[2] == '-' && src[3] == '-' &&
		punycode_decode(len - 4, src + 4, &cap32, codepoints, NULL) == punycode_success)
	{
		UTF8 *target = reinterpret_cast<UTF8 *>(dst);
		const UTF32 *source = reinterpret_cast<const UTF32 *>(codepoints);
		if (ConvertUTF32toUTF8(
			&source, source + cap32,
			&target, target + cap,
			strictConversion) == conversionOK)
		{
			ret = target - reinterpret_cast<const UTF8 *>(dst);
		}
	}
	dst[ret] = '\0';
	return ret;
}

void ConvertFromPunycode(const char *src, char *dst, punycode_uint cap)
{
	while (punycode_uint eat = *src == '.' ? 1 : strcspn(src, "."))
	{
		punycode_uint len = ConvertFromPunycode(src, eat, dst, cap);
		if (len == 0)
		{
			len = eat;
			memcpy(dst, src, len);
		}
		dst += len;
		cap -= len;
		src += eat;
	}
	*dst = '\0';
}
