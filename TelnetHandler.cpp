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
		sprintf(logTelnet<1>(), "Started command shell");
		DWORD wait;
		do
		{
			wait = WaitForSingleObject(pi.hProcess, 100);
			int result;
			DWORD cb;
			char buffer[4096];
			while (PeekNamedPipe(output[read], buffer, sizeof buffer, &cb, NULL, NULL) && cb != 0)
			{
				if ((result = send(client, buffer, cb, 0)) > 0)
				{
					ReadFile(output[read], buffer, result, &cb, NULL);
				}
				else if (result < 0 && (result = WSAGetLastError()) != WSAEWOULDBLOCK)
				{
					sprintf(logTelnet<1>(), "Send error due to %d", result);
					break;
				}
			}
			if ((result = recv(client, buffer, sizeof buffer, 0)) > 0)
			{
				WriteFile(input[write], buffer, result, &cb, NULL);
			}
			else if (result < 0 && (result = WSAGetLastError()) != WSAEWOULDBLOCK)
			{
				sprintf(logTelnet<1>(), "Receive error due to %d", result);
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
	sprintf(logTelnet<1>(), "Disconnected");
	EndThread();
}

bool AcceptTelnetConnection(SOCKET selected)
{
	SOCKADDR_IN remote;
	socklen_t sockLen = sizeof remote;;
	SOCKET client = accept(selected, reinterpret_cast<sockaddr*>(&remote), &sockLen);
	if (client != INVALID_SOCKET)
	{
		sprintf(logTelnet<2>(), "Client %s, Telnet Request Received", IP2String(remote.sin_addr.s_addr));
		if (cfig.telnetClients[0] && !findServer(cfig.telnetClients, 8, remote.sin_addr.s_addr))
		{
			sprintf(logTelnet<2>(), "Client %s, Telnet Access Denied", IP2String(remote.sin_addr.s_addr));
		}
		else if (!BeginThread(telnetThread, 0, reinterpret_cast<void *>(client)))
		{
			sprintf(logTelnet<1>(), "Thread Creation Failed");
		}
		else
		{
			return true;
		}
		closesocket(client);
	}
	else
	{
		int error = WSAGetLastError();
		sprintf(logTelnet<1>(), "Accept Failed, WSAError %u", error);
	}
	return false;
}
