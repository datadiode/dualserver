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
#include "HttpResponse.h"

void HttpResponse::operator += (size_type ahead)
{
	size_type length = ahead;
	while (ahead != 0)
	{
		if (avail == 0)
		{
			chunklist.push_back();
			avail = chunk;
		}
		size_type bytes = ahead < avail ? ahead : avail;
		memcpy(chunklist.back() + chunk - avail, first + length - ahead, bytes);
		ahead -= bytes;
		avail -= bytes;
	}
}

void HttpResponse::cancel(const char *fp)
{
	chunklist.clear();
	delete []first;
	first = NULL;
	final = fp;
}

void HttpResponse::send(ISend *pif)
{
	const char *dp = first ? first : final;
	size_type bytes = final - dp + strlen(final);
	iterator p = chunklist.begin();
	while (pif->send(dp, bytes) && p != chunklist.end())
	{
		bytes = chunk;
		dp = *p;
		if (++p == chunklist.end())
			bytes -= avail;
	}
}
