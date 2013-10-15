#include <crtdbg.h>
#include <stdio.h>

// Support EASTL as per <EASTL/allocator.h> line 194.
void* operator new[](size_t size, const char* pName, int flags,
    unsigned debugFlags, const char* file, int line)
{
#ifdef _DEBUG
    return ::operator new[](size, _NORMAL_BLOCK, file, line);
#else
    return ::operator new[](size);
#endif
}

// Support EASTL as per <EASTL/allocator.h> line 195.
void* operator new[](size_t size, size_t alignment, size_t alignmentOffset,
    const char* pName, int flags, unsigned debugFlags, const char* file, int line)
{
    // this allocator doesn't support alignment
#ifdef _DEBUG
    return ::operator new[](size, _NORMAL_BLOCK, file, line);
#else
    return ::operator new[](size);
#endif
}

// Support EASTL as per <EASTL/string.h> line 197.
int Vsnprintf8(char* pDestination, size_t n, const char* pFormat, va_list arguments)
{
	// The _vscprintf() avoids reallocations by pretending C99 conformance.
	return n ? _vsnprintf(pDestination, n, pFormat, arguments) : _vscprintf(pFormat, arguments);
}

// Support EASTL as per <EASTL/string.h> line 198.
int Vsnprintf16(wchar_t* pDestination, size_t n, const wchar_t* pFormat, va_list arguments)
{
	// The _vscwprintf() avoids reallocations by pretending C99 conformance.
	return n ? _vsnwprintf(pDestination, n, pFormat, arguments) : _vscwprintf(pFormat, arguments);
}

