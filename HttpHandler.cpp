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
// HttpHandler.cpp
// Last change: 2013-10-12 by Jochen Neubeck
#include <stdio.h>
#include <winsock2.h>
#include <time.h>
#include <tchar.h>
#include <ws2tcpip.h>
#include <limits.h>
#include <iphlpapi.h>
#include <process.h>
#include <assert.h>
#include "PunyConvert.h"
#include "DualServer.h"
#include "HttpHandler.h"

static const char td200[] = "<td>%s</td>";
static const char htmlStart[] =
	"<!DOCTYPE HTML 4.0 Transitional>\n"
	"<html>\n"
	"<head>\n"
	"<title>%s</title>\n"
	"<meta http-equiv='refresh' content='60'>\n"
	"<meta http-equiv='cache-control' content='no-cache'>\n"
	"<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>\n"
	"<style>\n"
	"body { background-color: #cccccc; }\n"
	"table { table-layout: fixed; width: 480pt; margin-top: 2ex; background-color: #b8b8b8; }\n"
	"caption { font: bold 14pt sans-serif; background-color: #cccccc; }\n"
	"tBody th { font: 10pt sans-serif; background-color: #cccccc; }\n"
	"tHead th { font: bold italic 14pt sans-serif; }\n"
	"tHead td { font: bold 10pt sans-serif; }\n"
	"tBody td { font: 10pt monospace; word-wrap: break-word; }\n" // white-space: nowrap;
	"</style>\n"
	"</head>\n";
static const char bodyStart[] =
	"<body>\n"
	"<table cellspacing='0'>\n"
	"<caption>%s</caption>\n"
	"<tr>\n"
	"<th width='40%%' align='left'><a target='_new' href='http://dhcp-dns-server.sourceforge.net'>http://dhcp-dns-server.sourceforge.net</a></th>\n"
	"<th width='60%%' align='right'>punycode-enabled fork: <a target='_new' href='https://bitbucket.org/jtuc/dualserver'>https://bitbucket.org/jtuc/dualserver</a></th>\n"
	"</tr>\n"
	"</table>\n";

string HttpHandler::htmlTitle;

HttpHandler::HttpHandler(SOCKET selected)
{
	char logBuff[1024];
	sockLen = sizeof remote;
	sock = accept(selected, (sockaddr*)&remote, &sockLen);
	if (sock == INVALID_SOCKET)
	{
		int error = WSAGetLastError();
		sprintf(logBuff, "Accept Failed, WSAError %u", error);
		logDHCPMess(logBuff, 1);
		delete this;
		return;
	}
	//debug("procHTTP");

	ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	ling.l_linger = 30; //0 = discard data, nonzero = wait for data sent
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof ling);

	timeval tv1;
	tv1.tv_sec = 1;
	tv1.tv_usec = 0;

	fd_set readfds1;
	FD_ZERO(&readfds1);
	FD_SET(sock, &readfds1);

	char buffer[1024];

	int bytes = -1;
	if (select(sock + 1, &readfds1, NULL, NULL, &tv1))
		bytes = recv(sock, buffer, sizeof buffer - 1, 0);

	if (bytes <= 0)
	{
		int error = WSAGetLastError();
		sprintf(logBuff, "Client %s, HTTP Message Receive failed, WSAError %d", IP2String(remote.sin_addr.s_addr), error);
		logDHCPMess(logBuff, 1);
		closesocket(sock);
		delete this;
		return;
	}

	sprintf(logBuff, "Client %s, HTTP Request Received", IP2String(remote.sin_addr.s_addr));
	logDHCPMess(logBuff, 2);

	if (cfig.httpClients[0] && !findServer(cfig.httpClients, 8, remote.sin_addr.s_addr))
	{
		code = 403;
		sprintf(logBuff, "Client %s, HTTP Access Denied", IP2String(remote.sin_addr.s_addr));
		logDHCPMess(logBuff, 2);
	}
	else try
	{
		char *fp = buffer + bytes;
		*fp = '\0';
		if (char *end = strchr(buffer, '\n'))
		{
			*end = '\0';
			if (char *slash = strchr(buffer, '/'))
				fp = slash;
			fp[strcspn(fp, "\t ")] = '\0';
		}
		if (!strcasecmp(fp, "/"))
			sendStatus();
		else if (!strcasecmp(fp, "/scopestatus"))
			sendScopeStatus();
		else
		{
			code = 404;
			if (*fp != '\0')
			{
				sprintf(logBuff, "Client %s, %.100s not found", IP2String(remote.sin_addr.s_addr), fp);
				logDHCPMess(logBuff, 2);
			}
			else
			{
				sprintf(logBuff, "Client %s, Invalid http request", IP2String(remote.sin_addr.s_addr));
				logDHCPMess(logBuff, 2);
			}
		}
	}
	catch (std::bad_alloc)
	{
		code = 507;
		sprintf(logBuff, "Memory Error");
		logDHCPMess(logBuff, 1);
	}
	BeginThread(sendThread, 0, this);
}

void HttpHandler::sendStatus()
{
	char tempbuff[512];
	//debug("sendStatus");

	dhcpMap::iterator p;

	typedef string sprintf;

	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp, "<table border='1' cellpadding='1'>\n");

	if (cfig.dhcpRepl > t)
	{
		fp += sprintf(fp,
			"<tHead>"
			"<tr><th colspan='5'>Active Leases</th></tr>\n"
			"<tr>"
			"<td>Mac Address</td>"
			"<td>IP</td>"
			"<td>Lease Expiry</td>"
			"<td>Hostname</td>"
			"<td>Server</td>"
			"</tr>\n"
			"</tHead>\n");
	}
	else
	{
		fp += sprintf(fp,
			"<tHead>\n"
			"<tr><th colspan='4'>Active Leases</th></tr>\n"
			"<tr>"
			"<td>Mac Address</td>"
			"<td>IP</td>"
			"<td>Lease Expiry</td>"
			"<td>Hostname</td>"
			"</tr>\n"
			"</tHead>\n");
	}

	for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end(); ++p)
	{
		data7 *dhcpEntry = p->second;
		if (dhcpEntry->display && dhcpEntry->expiry >= t)
		{
			fp += sprintf(fp, "<tr>");
			fp += sprintf(fp, td200, dhcpEntry->mapname);
			fp += sprintf(fp, td200, IP2String(dhcpEntry->ip));

			if (dhcpEntry->expiry >= INT_MAX)
				fp += sprintf(fp, td200, "Infinity");
			else
			{
				tm *ttm = localtime(&dhcpEntry->expiry);
				strftime(tempbuff, sizeof tempbuff, "%d-%b-%y %X", ttm);
				fp += sprintf(fp, td200, tempbuff);
			}

			if (dhcpEntry->hostname)
			{
				ConvertFromPunycode(dhcpEntry->hostname, tempbuff, _countof(tempbuff) - 1);
				fp += sprintf(fp, td200, tempbuff);
			}
			else
				fp += sprintf(fp, td200, "&nbsp;");

			if (cfig.dhcpRepl > t)
			{
				if (dhcpEntry->local && cfig.replication == 1)
					fp += sprintf(fp, td200, "Primary");
				else if (dhcpEntry->local && cfig.replication == 2)
					fp += sprintf(fp, td200, "Secondary");
				else if (cfig.replication == 1)
					fp += sprintf(fp, td200, "Secondary");
				else
					fp += sprintf(fp, td200, "Primary");
			}

			fp += sprintf(fp, "</tr>\n");
		}
	}

	fp += sprintf(fp,
		"</table>\n"
		"<table border='1' cellpadding='1'>\n"
		"<tHead>\n"
		"<tr><th colspan='4'>Free Dynamic Leases</th></tr>\n"
		"<tr>"
		"<td align='left' colspan='2'>DHCP Range</td>"
		"<td align='right'>Available Leases</td>"
		"<td align='right'>Free Leases</td>"
		"</tr>\n"
		"</tHead>\n");

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount; ++rangeInd)
	{
		int ipused = 0;
		int ipfree = 0;
		int ind = 0;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] < t)
				++ipfree;
			else if (cfig.dhcpRanges[rangeInd].dhcpEntry[ind] && !(cfig.dhcpRanges[rangeInd].dhcpEntry[ind]->fixed))
				++ipused;
		}
		fp += sprintf(fp, "<tr><td colspan='2'>%s - %s</td><td align='right'>%d</td><td align='right'>%d</td></tr>\n",
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeStart)),
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeEnd)),
			ipused + ipfree,
			ipfree);
	}

	fp += sprintf(fp,
		"</table>\n"
		"<table border='1' cellpadding='1'>\n"
		"<tHead>\n"
		"<tr><th colspan='4'>Free Static Leases</th></tr>\n"
		"<tr>"
		"<td>Mac Address</td>"
		"<td>IP</td>"
		"<td>Mac Address</td>"
		"<td>IP</td>"
		"</tr>\n"
		"</tHead>\n");

	MYBYTE colNum = 0;

	for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end(); ++p)
	{
		data7 *dhcpEntry = p->second;
		if (dhcpEntry->fixed && dhcpEntry->expiry < t)
		{
			if (!colNum)
			{
				fp += sprintf(fp, "<tr>");
				colNum = 1;
			}
			else if (colNum == 1)
			{
				colNum = 2;
			}
			else if (colNum == 2)
			{
				fp += sprintf(fp, "</tr>\n<tr>");
				colNum = 1;
			}

			fp += sprintf(fp, td200, dhcpEntry->mapname);
			fp += sprintf(fp, td200, IP2String(dhcpEntry->ip));
		}
	}

	if (colNum)
		fp += sprintf(fp, "</tr>\n");

	fp += sprintf(fp, "</table>\n</body>\n</html>");

	code = 200;
}

void HttpHandler::sendScopeStatus()
{
	//debug("sendScopeStatus");

	typedef string sprintf;

	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp,
		"<table border='1' cellpadding='1'>\n"
		"<tHead>\n"
		"<tr><th colspan='5'>Scope Status</th></tr>\n"
		"<tr>"
		"<td colspan='2'>DHCP Range</td>"
		"<td align='right'>IPs Used</td>"
		"<td align='right'>IPs Free</td>"
		"<td align='right'>%% Free</td>"
		"</tr>\n"
		"</tHead>\n");

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount; ++rangeInd)
	{
		int ipused = 0;
		int ipfree = 0;
		int ind = 0;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] > t)
				++ipused;
			else
				++ipfree;
		}

		fp += sprintf(fp,
			"<tr>"
			"<td colspan='2'>%s - %s</td>"
			"<td align='right'>%d</td>"
			"<td align='right'>%d</td>"
			"<td align='right'>%.2f</td>"
			"</tr>\n",
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeStart)),
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeEnd)),
			ipused, ipfree, ((100.0 * ipfree)/(ipused + ipfree)));
	}

	fp += sprintf(fp, "</table>\n</body>\n</html>");

	code = 200;
}

void HttpHandler::sendThread(void *param)
{
	HttpHandler *req = static_cast<HttpHandler *>(param);

	static const char send200[] =
		"HTTP/1.1 200 OK\r\n"
		"Date: %a, %d %b %Y %H:%M:%S GMT\r\n"
		"Last-Modified: %a, %d %b %Y %H:%M:%S GMT\r\n"
		"Content-Type: text/html\r\n"
		"Connection: Close\r\n";

	static const char send403[] =
		"HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";

	static const char send404[] =
		"HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";

	static const char send507[] =
		"HTTP/1.1 507 Not Found\r\n\r\n<h1>507 Insufficient Storage</h1>";

	char header[512];
	char *dp = header;

	switch (req->code)
	{
	case 200:
		dp += strftime(dp, _countof(header), send200, gmtime(&t));
		dp += sprintf(dp, "Content-Length: %d\r\n\r\n", req->fp.total());
		break;
	case 403:
		dp += sprintf(dp, send403);
		break;
	case 404:
		dp += sprintf(dp, send404);
		break;
	case 507:
		dp += sprintf(dp, send507);
		break;
	}

	int bytes = dp - header;
	dp = header;

	HttpChunkList::iterator p = req->fp.begin();
	for (;;)
	{
		timeval tv1;
		tv1.tv_sec = 1;
		tv1.tv_usec = 0;

		fd_set writefds1;
		FD_ZERO(&writefds1);
		FD_SET(req->sock, &writefds1);

		if (!select((req->sock + 1), NULL, &writefds1, NULL, &tv1))
			break;

		bytes = send(req->sock, dp, bytes, 0);
		if (bytes < 0)
			break;

		if (p == req->fp.end())
			break;

		bytes = req->fp.chunk;
		dp = *p;
		if (++p == req->fp.end())
			bytes -= req->fp.avail;
	}

	closesocket(req->sock);
	delete req;
	EndThread();
}
