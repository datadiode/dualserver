// TelnetHandler.cpp
// Copyright (c) datadiode
// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <limits.h>
#include <assert.h>
#include "DualServer.h"
#include "TelnetHandler.h"

static void __cdecl telnetThread(void *pv)
{
	SOCKET const client = reinterpret_cast<SOCKET>(pv);

	u_long iMode = 1;
	ioctlsocket(client, FIONBIO, &iMode);

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof sa;
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	enum { read, write };
	HANDLE input[2] = { NULL, NULL };
	HANDLE output[2] = { NULL, NULL };
	CreatePipe(&input[read], &input[write], &sa, 0);
	CreatePipe(&output[read], &output[write], &sa, 0);

	STARTUPINFO si;
	ZeroMemory(&si, sizeof si);
	si.cb = sizeof si;
	si.hStdError = output[write];
	si.hStdOutput = output[write];
	si.hStdInput = input[read];
	si.dwFlags = STARTF_USESTDHANDLES;

	TCHAR path[MAX_PATH];
	PROCESS_INFORMATION pi;
	if ((input[read] != input[write]) && (output[read] != output[write]) &&
		GetEnvironmentVariable(TEXT("COMSPEC"), path, _countof(path)) &&
		CreateProcess(NULL, path, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		logDHCPMess("Started command shell", 1);
		DWORD wait;
		do
		{
			wait = WaitForSingleObject(pi.hProcess, 100);
			int result;
			DWORD cb;
			char buffer[4096];
			while (PeekNamedPipe(output[read], buffer, sizeof buffer, &cb, NULL, NULL) && cb != 0)
			{
				ReadFile(output[read], buffer, cb, &cb, NULL);
				char *p = buffer;
				while (cb != 0)
				{
					if ((result = send(client, p, cb, 0)) > 0)
					{
						p += result;
						cb -= result;
					}
					else if (result == 0 || (result = WSAGetLastError()) != WSAEWOULDBLOCK)
					{
						wsprintf(buffer, "Send error due to %d", result);
						logDHCPMess(buffer, 1);
						break;
					}
				}
			}
			if ((result = recv(client, buffer, sizeof buffer, 0)) > 0)
			{
				WriteFile(input[write], buffer, result, &cb, NULL);
			}
			else if (result == 0 || (result = WSAGetLastError()) != WSAEWOULDBLOCK)
			{
				wsprintf(buffer, "Premature exit due to %d", result);
				logDHCPMess(buffer, 1);
				break;
			}
		} while (wait == WAIT_TIMEOUT);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	if (input[read] != input[write])
	{
		CloseHandle(input[read]);
		CloseHandle(input[write]);
	}
	if (output[read] != output[write])
	{
		CloseHandle(output[read]);
		CloseHandle(output[write]);
	}

	closesocket(client);
	logDHCPMess("Disconnected", 1);
	EndThread();
}

bool AcceptTelnetConnection(SOCKET selected)
{
	char logBuff[1024];
	SOCKADDR_IN remote;
	socklen_t sockLen = sizeof remote;;
	SOCKET client = accept(selected, (sockaddr*)&remote, &sockLen);
	if (client != INVALID_SOCKET)
	{
		sprintf(logBuff, "Client %s, Telnet Request Received", IP2String(remote.sin_addr.s_addr));
		logDHCPMess(logBuff, 2);
		if (!cfig.telnetClients[0] || findServer(cfig.telnetClients, 8, remote.sin_addr.s_addr))
			if (BeginThread(telnetThread, 0, reinterpret_cast<void *>(client)))
				return true;
		sprintf(logBuff, "Client %s, Telnet Access Denied", IP2String(remote.sin_addr.s_addr));
		logDHCPMess(logBuff, 2);
		closesocket(client);
	}
	else
	{
		sprintf(logBuff, "Accept Failed, WSAError %u", WSAGetLastError());
		logDHCPMess(logBuff, 1);
	}
	return false;
}
