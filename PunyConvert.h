#include "punycode/punycode.h"
#include "convert_utf/ConvertUTF.h"

punycode_uint ConvertToPunycode(const wchar_t *src, punycode_uint len, char *dst, punycode_uint cap);
void ConvertToPunycode(const wchar_t *src, char *dst, punycode_uint cap);
punycode_uint ConvertFromPunycode(const char *src, punycode_uint len, char *dst, punycode_uint cap);
void ConvertFromPunycode(const char *src, char *dst, punycode_uint cap);
