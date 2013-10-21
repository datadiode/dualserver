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

#include "HttpResponse.h"

class HttpHandler: public HttpResponse::ISend
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

	static char htmlTitle[512];

private:
	static const HttpResponse::size_type buffer_size = 2048;

	void sendStatus();
	void sendScopeStatus();
	virtual bool send(const char *, HttpResponse::size_type);
	static void __cdecl sendThread(void *);
	void operator=(const HttpHandler &);

	SOCKET sock;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	linger ling;
	HttpResponse fp;
};
