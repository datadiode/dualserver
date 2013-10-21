/*
[The MIT license]

Copyright (C) 2013 Jochen Neubeck

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Last change: 2013-10-20 by Jochen Neubeck
*/
#include "EASTL/list.h"

using namespace eastl;

class HttpResponse
{
	class Chunk
	{
		char data[sizeof(double)];
	public:
		operator char *() { return data; }
	};
	class Allocator: public allocator
	{
	public:
		void *allocate(size_t n, size_t alignment, size_t offset, int flags = 0)
		{
			return allocator::allocate(n + extra, alignment, offset, flags);
		}
		void *allocate(size_t n, int flags = 0)
		{
			return allocator::allocate(n + extra, flags);
		}
		void deallocate(void* p, size_t n)
		{
			allocator::deallocate(p, n);
		}
		Allocator(const char *name)
			: allocator(name), extra(0)
		{
		}
		eastl_size_t extra;
	};

public:
	typedef list<Chunk, Allocator>::size_type size_type;
	typedef list<Chunk, Allocator>::iterator iterator;
	const size_type chunk;
	class ISend
	{
	public:
		virtual bool send(const char *, size_type) = 0;
	};
	HttpResponse(const size_type chunk = 1024)
		: chunk(chunk), avail(0), first(NULL), final(NULL)
	{
		chunklist.get_allocator().extra = chunk - sizeof(Chunk);
	}
	~HttpResponse()
	{
		cancel(NULL);
	}
	size_type total()
	{
		return chunklist.size() * chunk - avail;
	}
	void operator += (size_type);
	char *open(size_type size)
	{
		return first = new char[size];
	}
	void close(const char *fp)
	{
		final = fp;
	}
	void cancel(const char *);
	void send(ISend *);
	operator char *()
	{
		return first;
	}
private:
	list<Chunk, Allocator> chunklist;
	size_type avail;
	char *first;
	const char *final;
	void operator=(const HttpResponse &);
};
