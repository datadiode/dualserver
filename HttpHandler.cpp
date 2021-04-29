// HttpHandler.cpp
// Copyright (C) 2005 by Achal Dhir
// SPDX-License-Identifier: GPL-2.0-or-later
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

static const char send200[] =
	"HTTP/1.1 200 OK\r\n"
	"Date: %a, %d %b %Y %H:%M:%S GMT\r\n"
	"Last-Modified: %a, %d %b %Y %H:%M:%S GMT\r\n"
	"Content-Type: text/html\r\n"
	"Connection: Close\r\n";

static const char httpContentLength[] =
	"Content-Length: %d\r\n\r\n";

static const char send403[] =
	"HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";

static const char send404[] =
	"HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";

static const char send507[] =
	"HTTP/1.1 507 Insufficient Storage\r\n\r\n<h1>507 Insufficient Storage</h1>";

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
	"<th width='60%%' align='right'>punycode-enabled fork: <a target='_new' href='https://github.com/datadiode/dualserver'>https://github.com/datadiode/dualserver</a></th>\n"
	"</tr>\n"
	"</table>\n";

char HttpHandler::htmlTitle[512];

HttpHandler::HttpHandler(SOCKET selected)
{
	sockLen = sizeof remote;
	sock = accept(selected, (sockaddr*)&remote, &sockLen);
	if (sock == INVALID_SOCKET)
	{
		int error = WSAGetLastError();
		sprintf(logDHCP<1>(), "Accept Failed, WSAError %u", error);
		delete this;
		return;
	}

	ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	ling.l_linger = 30; //0 = discard data, nonzero = wait for data sent
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof ling);

	timeval tv1;
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;

	fd_set readfds1;
	FD_ZERO(&readfds1);
	FD_SET(sock, &readfds1);

	char buffer[1024];

	int bytes = -1;
	if (select(0, &readfds1, NULL, NULL, &tv1))
		bytes = recv(sock, buffer, sizeof buffer - 1, 0);

	if (bytes <= 0)
	{
		int error = WSAGetLastError();
		sprintf(logDHCP<1>(), "Client %s, HTTP Message Receive failed, WSAError %d", IP2String(remote.sin_addr.s_addr), error);
		closesocket(sock);
		delete this;
		return;
	}

	sprintf(logDHCP<2>(), "Client %s, HTTP Request Received", IP2String(remote.sin_addr.s_addr));

	if (cfig.httpClients[0] && !findServer(cfig.httpClients, 8, remote.sin_addr.s_addr))
	{
		fp.cancel(send403);
		sprintf(logDHCP<2>(), "Client %s, HTTP Access Denied", IP2String(remote.sin_addr.s_addr));
	}
	else try
	{
		char *url = buffer + bytes;
		*url = '\0';
		if (char *end = strchr(buffer, '\n'))
		{
			*end = '\0';
			if (char *slash = strchr(buffer, '/'))
				url = slash;
			url[strcspn(url, "\t ")] = '\0';
		}
		if (!strcasecmp(url, "/"))
			sendStatus();
		else if (!strcasecmp(url, "/scopestatus"))
			sendScopeStatus();
		else
		{
			fp.cancel(send404);
			if (*url != '\0')
			{
				sprintf(logDHCP<2>(), "Client %s, %.100s not found", IP2String(remote.sin_addr.s_addr), url);
			}
			else
			{
				sprintf(logDHCP<2>(), "Client %s, Invalid http request", IP2String(remote.sin_addr.s_addr));
			}
		}
	}
	catch (std::bad_alloc)
	{
		fp.cancel(send507);
		sprintf(logDHCP<1>(), "Memory Error");
	}

	if (!BeginThread(sendThread, 0, this))
	{
		sprintf(logDHCP<1>(), "Thread Creation Failed");
		closesocket(sock);
		delete this;
	}
}

void HttpHandler::sendStatus()
{
	char tempbuff[512];
	dhcpMap::iterator p;

	char *dp = fp.open(buffer_size);

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

	dp += strftime(dp, buffer_size, send200, gmtime(&t));
	dp += sprintf(dp, httpContentLength, fp.total());

	fp.close(dp);
}

void HttpHandler::sendScopeStatus()
{
	char *dp = fp.open(buffer_size);

	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp,
		"<table border='1' cellpadding='1'>\n"
		"<tHead>\n"
		"<tr><th colspan='6'>Scope Status</th></tr>\n"
		"<tr>"
		"<td colspan='3'>DHCP Range</td>"
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
			"<td colspan='3'>%s - %s</td>"
			"<td align='right'>%d</td>"
			"<td align='right'>%d</td>"
			"<td align='right'>%.2f</td>"
			"</tr>\n",
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeStart)),
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeEnd)),
			ipused, ipfree, ((100.0 * ipfree)/(ipused + ipfree)));
	}

	fp += sprintf(fp, "</table>\n</body>\n</html>");

	dp += strftime(dp, buffer_size, send200, gmtime(&t));
	dp += sprintf(dp, httpContentLength, fp.total());

	fp.close(dp);
}

bool HttpHandler::send(const char *dp, HttpResponse::size_type bytes)
{
	timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	fd_set writefds;
	FD_ZERO(&writefds);
	FD_SET(sock, &writefds);

	if (::select(0, NULL, &writefds, NULL, &tv) <= 0)
		return false;
	if (::send(sock, dp, bytes, 0) <= 0)
		return false;

	return true;
}

void HttpHandler::sendThread(void *param)
{
	HttpHandler *req = static_cast<HttpHandler *>(param);
	req->fp.send(req);
	closesocket(req->sock);
	delete req;
	EndThread();
}
