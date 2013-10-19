/**************************************************************************
*   Copyright (C) 2005 by Achal Dhir                                      *
*   achaldhir@gmail.com                                                   *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/

class HttpChunkList
	: public list<char *>
	, public string::CtorSprintf
{
public:
	const string::size_type chunk;
	string::size_type avail;
	HttpChunkList(const string::size_type chunk = 1024): chunk(chunk), avail(0)
	{
	}
	~HttpChunkList()
	{
		for (iterator p = begin(); p != end(); ++p)
			delete []*p;
	}
	string::size_type total()
	{
		return size() * chunk - avail;
	}
	void operator += (const string &s)
	{
		string::size_type ahead = s.length();
		while (ahead != 0)
		{
			if (avail == 0)
				push_back(new char[avail = chunk]);
			string::size_type bytes = ahead < avail ? ahead : avail;
			memcpy(back() + chunk - avail, s.c_str() + s.size() - ahead, bytes);
			ahead -= bytes;
			avail -= bytes;
		}
	}
private:
	void operator=(const HttpChunkList &);
};

class HttpHandler
{
public:
	HttpHandler(SOCKET selected);

	void *operator new(size_t size)
	{
		return calloc(1, size);
	}
	void operator delete(void *p)
	{
		free(p);
	}

	static string htmlTitle;

private:
	void sendStatus();
	void sendScopeStatus();
	static void __cdecl sendThread(void *);
	void operator=(const HttpHandler &);

	SOCKET sock;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	linger ling;
	HttpChunkList fp;
	int code;
};
