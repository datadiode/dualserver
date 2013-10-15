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
// DualServer.cpp
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
#include "LeakDetector.h"
#include "DualServer.h"

//Global Variables
volatile bool kRunning = true;
volatile LONG threadCount = 0;
bool verbatim = false;
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = CreateEvent(NULL, TRUE, FALSE, 0);
data1 network;
data2 cfig;
data9 token;
data9 dhcpr;
data5 dnsr;
MYBYTE currentInd = 0;
MYBYTE newInd = 0;
hostMap dnsCache[2];
dhcpMap dhcpCache;
expiryMap dnsAge[2];
//expiryMap dhcpAge;
char serviceName[] = "DUALServer";
const char displayName[] = "Dual DHCP DNS Service";
char htmlTitle[256] = "";
char filePATH[_MAX_PATH];
char iniFile[_MAX_PATH];
char leaFile[_MAX_PATH];
char logFile[_MAX_PATH];
char htmFile[_MAX_PATH];
char lnkFile[_MAX_PATH];
char cliFile[_MAX_PATH];
const char arpa[] = ".in-addr.arpa";
const char ip6arpa[] = ".ip6.arpa";
bool dhcpService = true;
bool dnsService = true;
time_t t = time(NULL);
HANDLE lEvent;

//constants
const char NBSP = 32;
const char RANGESET[] = "RANGE_SET";
const char GLOBALOPTIONS[] = "GLOBAL_OPTIONS";
const char td200[] = "<td>%s</td>";
const char sVersion[] = "Dual DHCP DNS Server Version 7.11p Windows Build 0001";
const char htmlStart[] =
	"<html>\n"
	"<head>\n"
	"<title>%s</title>"
	"<meta http-equiv='refresh' content='60'>\n"
	"<meta http-equiv='cache-control' content='no-cache'>\n"
	"<meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>\n"
	"<style>\n"
	"table { table-layout: fixed; width: 640px; overflow: hidden; white-space: nowrap }\n"
	"</style>\n"
	"</head>\n";
const char bodyStart[] =
	"<body bgcolor='#cccccc'>\n"
	"<table><col width='40%%'><col width='60%%'>\n"
	"<tr>"
	"<td colspan='2' align='center'><font size='5'><b>%s</b></font></td>"
	"</tr>\n"
	"<tr>"
	"<td align='left'><a target='_new' href='http://dhcp-dns-server.sourceforge.net'>http://dhcp-dns-server.sourceforge.net</a></td>"
	"<td align='right'>punycode-enabled fork: <a target='_new' href='https://bitbucket.org/jtuc/dualserver'>https://bitbucket.org/jtuc/dualserver</a></td>"
	"</tr>\n"
	"</table>\n";

const data4 opData[] =
{
	{ "SubnetMask",							DHCP_OPTION_NETMASK,				3,	true	},
	{ "TimeOffset",							DHCP_OPTION_TIMEOFFSET,				4,	true	},
	{ "Router",								DHCP_OPTION_ROUTER,					3,	true	},
	{ "TimeServer",							DHCP_OPTION_TIMESERVER,				3,	true	},
	{ "NameServer",							DHCP_OPTION_NAMESERVER,				3,	true	},
	{ "DomainServer",						DHCP_OPTION_DNS,					3,	true	},
	{ "LogServer",							DHCP_OPTION_LOGSERVER,				3,	true	},
	{ "QuotesServer",						DHCP_OPTION_COOKIESERVER,			3,	true	},
	{ "LPRServer",							DHCP_OPTION_LPRSERVER,				3,	true	},
	{ "ImpressServer",						DHCP_OPTION_IMPRESSSERVER,			3,	true	},
	{ "RLPServer",							DHCP_OPTION_RESLOCSERVER,			3,	true	},
	{ "Hostname",							DHCP_OPTION_HOSTNAME,				1,	true	},
	{ "BootFileSize",						DHCP_OPTION_BOOTFILESIZE,			5,	true	},
	{ "MeritDumpFile",						DHCP_OPTION_MERITDUMP,				1,	true	},
	{ "DomainName",							DHCP_OPTION_DOMAINNAME,				1,	true	},
	{ "SwapServer",							DHCP_OPTION_SWAPSERVER,				3,	true	},
	{ "RootPath",							DHCP_OPTION_ROOTPATH,				1,	true	},
	{ "ExtensionFile",						DHCP_OPTION_EXTSPATH,				1,	true	},
	{ "ForwardOn/Off",						DHCP_OPTION_IPFORWARD,				7,	true	},
	{ "SrcRteOn/Off",						DHCP_OPTION_NONLOCALSR,				7,	true	},
	{ "PolicyFilter",						DHCP_OPTION_POLICYFILTER,			8,	true	},
	{ "MaxDGAssembly",						DHCP_OPTION_MAXREASSEMBLE,			5,	true	},
	{ "DefaultIPTTL",						DHCP_OPTION_IPTTL,					6,	true	},
	{ "MTUTimeout",							DHCP_OPTION_PATHMTUAGING,			4,	true	},
	{ "MTUPlateau",							DHCP_OPTION_PATHMTUPLATEAU, 		2,	true	},
	{ "MTUInterface",						DHCP_OPTION_INTERFACEMTU,			5,	true	},
	{ "MTUSubnet",							DHCP_OPTION_SUBNETSLOCAL,			7,	true	},
	{ "BroadcastAddress",					DHCP_OPTION_BCASTADDRESS,			3,	true	},
	{ "MaskDiscovery",						DHCP_OPTION_MASKDISCOVERY,			7,	true	},
	{ "MaskSupplier",						DHCP_OPTION_MASKSUPPLIER,			7,	true	},
	{ "RouterDiscovery",					DHCP_OPTION_ROUTERDISCOVERY,		7,	true	},
	{ "RouterRequest",						DHCP_OPTION_ROUTERSOLIC,			3,	true	},
	{ "StaticRoute",						DHCP_OPTION_STATICROUTE,			8,	true	},
	{ "Trailers",							DHCP_OPTION_TRAILERENCAPS,			7,	true	},
	{ "ARPTimeout",							DHCP_OPTION_ARPTIMEOUT,				4,	true	},
	{ "Ethernet",							DHCP_OPTION_ETHERNETENCAPS,			7,	true	},
	{ "DefaultTCPTTL",						DHCP_OPTION_TCPTTL,					6,	true	},
	{ "KeepaliveTime",						DHCP_OPTION_TCPKEEPALIVEINT,		4,	true	},
	{ "KeepaliveData",						DHCP_OPTION_TCPKEEPALIVEGRBG,		7,	true	},
	{ "NISDomain",							DHCP_OPTION_NISDOMAIN,				1,	true	},
	{ "NISServers",							DHCP_OPTION_NISSERVERS,				3,	true	},
	{ "NTPServers",							DHCP_OPTION_NTPSERVERS,				3,	true	},
	{ "VendorSpecificInf",					DHCP_OPTION_VENDORSPECIFIC,			2,	false	},
	{ "NETBIOSNameSrv",						DHCP_OPTION_NETBIOSNAMESERV,		3,	true	},
	{ "NETBIOSDistSrv",						DHCP_OPTION_NETBIOSDGDIST,			3,	true	},
	{ "NETBIOSNodeType",					DHCP_OPTION_NETBIOSNODETYPE,		6,	true	},
	{ "NETBIOSScope",						DHCP_OPTION_NETBIOSSCOPE,			1,	true	},
	{ "XWindowFont",						DHCP_OPTION_X11FONTS,				1,	true	},
	{ "XWindowManager",						DHCP_OPTION_X11DISPLAYMNGR,			3,	true	},
	{ "AddressRequest",						DHCP_OPTION_REQUESTEDIPADDR,		3,	false	},
	{ "AddressTime",						DHCP_OPTION_IPADDRLEASE,			4,	true	},
	{ "OverLoad",							DHCP_OPTION_OVERLOAD,				7,	false	},
	{ "DHCPMsgType",						DHCP_OPTION_MESSAGETYPE,			6,	false	},
	{ "DHCPServerId",						DHCP_OPTION_SERVERID,				3,	false	},
	{ "ParameterList",						DHCP_OPTION_PARAMREQLIST,			2,	false	},
	{ "DHCPMessage",						DHCP_OPTION_MESSAGE,				1,	false	},
	{ "DHCPMaxMsgSize",						DHCP_OPTION_MAXDHCPMSGSIZE,			5,	false	},
	{ "RenewalTime",						DHCP_OPTION_RENEWALTIME,			4,	true	},
	{ "RebindingTime",						DHCP_OPTION_REBINDINGTIME,			4,	true	},
	{ "ClassId",							DHCP_OPTION_VENDORCLASSID,			1,	false	},
	{ "ClientId",							DHCP_OPTION_CLIENTID,				2,	false	},
	{ "NetWareIPDomain",					DHCP_OPTION_NETWARE_IPDOMAIN,		1,	true	},
	{ "NetWareIPOption",					DHCP_OPTION_NETWARE_IPOPTION,		2,	true	},
	{ "NISDomainName",						DHCP_OPTION_NISPLUSDOMAIN,			1,	true	},
	{ "NISServerAddr",						DHCP_OPTION_NISPLUSSERVERS,			3,	true	},
	{ "TFTPServerName",						DHCP_OPTION_TFTPSERVER,				1,	true	},
	{ "BootFileOption",						DHCP_OPTION_BOOTFILE,				1,	true	},
	{ "HomeAgentAddrs",						DHCP_OPTION_MOBILEIPHOME,			3,	true	},
	{ "SMTPServer",							DHCP_OPTION_SMTPSERVER,				3,	true	},
	{ "POP3Server",							DHCP_OPTION_POP3SERVER,				3,	true	},
	{ "NNTPServer",							DHCP_OPTION_NNTPSERVER,				3,	true	},
	{ "WWWServer",							DHCP_OPTION_WWWSERVER,				3,	true	},
	{ "FingerServer",						DHCP_OPTION_FINGERSERVER,			3,	true	},
	{ "IRCServer",							DHCP_OPTION_IRCSERVER,				3,	true	},
	{ "StreetTalkServer",					DHCP_OPTION_STSERVER,				3,	true	},
	{ "STDAServer",							DHCP_OPTION_STDASERVER,				3,	true	},
	{ "UserClass",							DHCP_OPTION_USERCLASS,				1,	false	},
	{ "DirectoryAgent",						DHCP_OPTION_SLPDIRAGENT,			1,	true	},
	{ "ServiceScope",						DHCP_OPTION_SLPDIRSCOPE,			1,	true	},
	{ "RapidCommit",						80,									2,	false	},
	{ "ClientFQDN",							DHCP_OPTION_CLIENTFQDN,				2,	false	},
	{ "RelayAgentInformation",				DHCP_OPTION_RELAYAGENTINFO,			2,	false	},
	{ "iSNS",								DHCP_OPTION_I_SNS,					1,	true	},
	{ "NDSServers",							DHCP_OPTION_NDSSERVERS,				3,	true	},
	{ "NDSTreeName",						DHCP_OPTION_NDSTREENAME,			1,	true	},
	{ "NDSContext",							DHCP_OPTION_NDSCONTEXT,				1,	true	},
	{ "LDAP",								DHCP_OPTION_LDAP,					1,	true	},
	{ "PCode",								DHCP_OPTION_P_CODE,					1,	true	},
	{ "TCode",								DHCP_OPTION_T_CODE,					1,	true	},
	{ "NetInfoAddress",						DHCP_OPTION_NETINFOADDRESS,			3,	true	},
	{ "NetInfoTag",							DHCP_OPTION_NETINFOTAG,				1,	true	},
	{ "URL",								DHCP_OPTION_URL,					1,	true	},
	{ "AutoConfig",							DHCP_OPTION_AUTO_CONFIG,			7,	true	},
	{ "NameServiceSearch",					DHCP_OPTION_NAMESERVICESEARCH,		2,	true	},
	{ "SubnetSelectionOption",				DHCP_OPTION_SUBNETSELECTION,		3,	true	},
	{ "DomainSearch",						DHCP_OPTION_DOMAINSEARCH,			1,	true	},
	{ "SIPServersDHCPOption",				DHCP_OPTION_SIPSERVERSDHCP,			1,	true	},
	{ "121",								DHCP_OPTION_CLASSLESSSTATICROUTE,	1,	true	},
	{ "CCC",								DHCP_OPTION_CCC,					1,	true	},
	{ "TFTPServerIPaddress",				DHCP_OPTION_TFPTSERVERIPADDRESS,	3,	true	},
	{ "CallServerIPaddress",				DHCP_OPTION_CALLSERVERIPADDRESS,	3,	true	},
	{ "DiscriminationString",				DHCP_OPTION_DISCRIMINATIONSTRING,	1,	true	},
	{ "RemoteStatisticsServerIPAddress",	DHCP_OPTION_REMOTESTATISTICSSERVER,	3,	true	},
	{ "HTTPProxyPhone",						DHCP_OPTION_HTTPPROXYFORPHONE_SPEC,	3,	true	},
	{ "OPTION_CAPWAP_AC_V4",				138,								1,	true	},
	{ "OPTIONIPv4_AddressMoS",				139,								1,	true	},
	{ "OPTIONIPv4_FQDNMoS",					140,								1,	true	},
	{ "SIPUAServiceDomains",				141,								1,	true	},
	{ "OPTIONIPv4_AddressANDSF",			142,								1,	true	},
	{ "IPTelephone",						176,								1,	true	},
	{ "ConfigurationFile",					209,								1,	true	},
	{ "PathPrefix",							210,								1,	true	},
	{ "RebootTime",							211,								4,	true	},
	{ "OPTION_6RD",							212,								1,	true	},
	{ "OPTION_V4_ACCESS_DOMAIN",			213,								1,	true	},
	{ "BootFileName",						DHCP_OPTION_BP_FILE,				1,	true	},
	{ "NextServer",							DHCP_OPTION_NEXTSERVER,				3,	true	},
};

void WINAPI ServiceControlHandler(DWORD controlCode)
{
	switch (controlCode)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		serviceStatus.dwControlsAccepted = 0;
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		kRunning = false;
		SetEvent(stopServiceEvent);
		break;
	}
}

BOOL WINAPI ConsoleControlHandler(DWORD)
{
	kRunning = false;
	SetEvent(stopServiceEvent);
	Sleep(INFINITE);
	return TRUE;
}

DWORD ServiceSleep(DWORD dwMilliseconds)
{
	return WaitForSingleObject(stopServiceEvent, dwMilliseconds);
}

uintptr_t BeginThread(void (__cdecl *entrypoint)(void *), unsigned stacksize, void *param)
{
	InterlockedIncrement(&threadCount);
	uintptr_t result = _beginthread(entrypoint, stacksize, param);
	if (result == 0)
		InterlockedDecrement(&threadCount);
	return result;
}

void EndThread()
{
	InterlockedDecrement(&threadCount);
}

void WINAPI ServiceMain(DWORD /*argc*/, TCHAR* /*argv*/[])
{
	serviceStatusHandle = RegisterServiceCtrlHandler(serviceName, ServiceControlHandler);
	if (serviceStatusHandle)
	{
		serviceStatus.dwServiceType = SERVICE_WIN32;
		serviceStatus.dwWin32ExitCode = NO_ERROR;
		serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
		serviceStatus.dwCheckPoint = 0;
		serviceStatus.dwWaitHint = 0;
		serviceStatus.dwControlsAccepted = 0;
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		runProg();
	}
}

void closeConn()
{
	if (network.httpConn.ready)
		closesocket(network.httpConn.sock);

    if (dhcpService)
    {
        for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].loaded; i++)
        	if (network.dhcpConn[i].ready)
            	closesocket(network.dhcpConn[i].sock);
    }

    if (dnsService)
    {
        for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].loaded; i++)
        	if (network.dnsUdpConn[i].ready)
           		closesocket(network.dnsUdpConn[i].sock);

        for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].loaded; i++)
        	if (network.dnsTcpConn[i].ready)
            	closesocket(network.dnsTcpConn[i].sock);

        if (network.forwConn.ready)
        	closesocket(network.forwConn.sock);
    }
}

void runService()
{
	SERVICE_TABLE_ENTRY serviceTable[] =
	{
		{ serviceName, ServiceMain },
		{ NULL, NULL }
	};
	StartServiceCtrlDispatcher(serviceTable);
}

void showError(MYDWORD enumber)
{
	LPTSTR lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		enumber,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);
	printf("%s\n", lpMsgBuf);
	LocalFree(lpMsgBuf);
}

bool stopService(SC_HANDLE service)
{
	if (service)
	{
		SERVICE_STATUS serviceStatus;
		QueryServiceStatus(service, &serviceStatus);
		if (serviceStatus.dwCurrentState != SERVICE_STOPPED)
		{
			ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
			printf("Stopping Service.");
			for (int i = 0; i < 100; i++)
			{
				QueryServiceStatus(service, &serviceStatus);
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
				{
					printf("Stopped\n");
					return true;
				}
				else
				{
					Sleep(500);
					printf(".");
				}
			}
			printf("Failed\n");
			return false;
		}
	}
	return true;
}

void installService()
{
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE | SERVICE_START);

	if (serviceControlManager)
	{
		TCHAR path[_MAX_PATH];
		if (GetModuleFileName(0, path, _countof(path)) > 0)
		{
			SC_HANDLE service = CreateService(serviceControlManager,
											  serviceName, displayName,
											  SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
											  SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
											  0, 0, 0, 0, 0);
			if (service)
			{
				printf("Successfully installed.. !\n");
				StartService(service, 0, NULL);
				CloseServiceHandle(service);
			}
			else
			{
				showError(GetLastError());
			}
		}
		CloseServiceHandle(serviceControlManager);
	}
}

void uninstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager,
		                                serviceName, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
		if (service)
		{
			if (stopService(service))
			{
				if (DeleteService(service))
					printf("Successfully Removed !\n");
				else
					showError(GetLastError());
			}
			else
				printf("Failed to Stop Service..\n");

			CloseServiceHandle(service);
		}
		else
			printf("Service Not Found..\n");

		CloseServiceHandle(serviceControlManager);
	}
}

int main(int argc, TCHAR* argv[])
{
	int ret = 0;
	OSVERSIONINFO osvi;
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	if (GetVersionEx(&osvi) && osvi.dwPlatformId >= VER_PLATFORM_WIN32_NT)
	{
		if (argc > 1 && lstrcmpi(argv[1], TEXT("-i")) == 0)
		{
			installService();
		}
		else if (argc > 1 && lstrcmpi(argv[1], TEXT("-u")) == 0)
		{
			uninstallService();
		}
		else if (argc > 1 && lstrcmpi(argv[1], TEXT("-v")) == 0)
		{
			SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
			bool serviceStopped = true;

			if (serviceControlManager)
			{
				SC_HANDLE service = OpenService(serviceControlManager, serviceName, SERVICE_QUERY_STATUS | SERVICE_STOP);

				if (service)
				{
					serviceStopped = stopService(service);
					CloseServiceHandle(service);
				}
				CloseServiceHandle(serviceControlManager);
			}

			if (serviceStopped)
			{
				verbatim = true;
				SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);
				ret = runProg();
			}
			else
				printf("Failed to Stop Service\n");
		}
		else
			runService();
	}
	else if (argc == 1 || lstrcmpi(argv[1], TEXT("-v")) == 0)
	{
		verbatim = true;
		ret = runProg();
	}
	else
		printf("This option is not available on Windows95/98/ME\n");

	return ret;
}

void __cdecl serverloop(void *)
{
	char logBuff[256];

	timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	do
	{
		network.busy = false;

		if (!network.dhcpConn[0].ready && !network.dnsUdpConn[0].ready)
		{
			ServiceSleep(1000);
			continue;
		}

		if (!network.ready)
		{
			ServiceSleep(1000);
			continue;
		}

		fd_set readfds;
		FD_ZERO(&readfds);

		if (dhcpService)
		{
			if (network.httpConn.ready)
				FD_SET(network.httpConn.sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				FD_SET(network.dhcpConn[i].sock, &readfds);

			if (cfig.dhcpReplConn.ready)
				FD_SET(cfig.dhcpReplConn.sock, &readfds);
		}

		if (dnsService)
		{
			for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
				FD_SET(network.dnsUdpConn[i].sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
				FD_SET(network.dnsTcpConn[i].sock, &readfds);

			if (network.forwConn.ready)
				FD_SET(network.forwConn.sock, &readfds);
		}

		if (select(network.maxFD, &readfds, NULL, NULL, &tv))
		{
			t = time(NULL);
			network.busy = true;

			if (dhcpService)
			{
				if (network.httpConn.ready && FD_ISSET(network.httpConn.sock, &readfds))
				{
					if (data19 *req = new data19)
					{
						req->sockLen = sizeof req->remote;
						req->sock = accept(network.httpConn.sock, (sockaddr*)&req->remote, &req->sockLen);
						if (req->sock == INVALID_SOCKET)
						{
							int error = WSAGetLastError();
							sprintf(logBuff, "Accept Failed, WSAError %u", error);
							logDHCPMess(logBuff, 1);
							delete req;
						}
						else
							procHTTP(req);
					}
					else
					{
						sprintf(logBuff, "Memory Error");
						logDHCPMess(logBuff, 1);
					}
				}

				if (cfig.dhcpReplConn.ready && FD_ISSET(cfig.dhcpReplConn.sock, &readfds))
				{
					dhcpr.sockLen = sizeof(dhcpr.remote);

					dhcpr.bytes = recvfrom(cfig.dhcpReplConn.sock,
										   dhcpr.raw,
										   sizeof(dhcpr.raw),
										   0,
										   (sockaddr*)&dhcpr.remote,
										   &dhcpr.sockLen);

					if (dhcpr.bytes <= 0)
						cfig.dhcpRepl = 0;
				}

				for (MYBYTE i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dhcpConn[i].sock, &readfds) && gdmess(&dhcpr, i) && sdmess(&dhcpr))
						alad(&dhcpr);
				}
			}

			if (dnsService)
			{
				for (MYBYTE i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dnsUdpConn[i].sock, &readfds))
					{
						if (gdnmess(&dnsr, i))
						{
							if (scanloc(&dnsr))
							{
								if (htons(dnsr.dnsp->header.ancount))
								{
									if (verbatim || cfig.dnsLogLevel >= 2)
									{
										if (dnsr.qtype == DNS_TYPE_SOA)
											sprintf(logBuff, "SOA Sent for zone %s", dnsr.query);
										else if (dnsr.qtype == DNS_TYPE_NS)
											sprintf(logBuff, "NS Sent for zone %s", dnsr.query);
										else if (dnsr.respType == CACHED)
											sprintf(logBuff, "%s resolved from Cache to %s", strquery(&dnsr), getResult(&dnsr));
										else
											sprintf(logBuff, "%s resolved Locally to %s", strquery(&dnsr), getResult(&dnsr));

										logDNSMess(&dnsr, logBuff, 2);
									}
								}
								else if (dnsr.dnsp->header.rcode == RCODE_NAMEERROR || dnsr.dnsp->header.rcode == RCODE_NOERROR)
								{
									if (dnsr.qtype != DNS_TYPE_SOA)
										dnsr.dnsp->header.rcode = RCODE_NAMEERROR;

									if (verbatim || cfig.dnsLogLevel >= 2)
									{
										if (dnsr.qtype == DNS_TYPE_SOA)
											sprintf(logBuff, "%s updated", strquery(&dnsr));
										else
											sprintf(logBuff, "%s not found", strquery(&dnsr));
										logDNSMess(&dnsr, logBuff, 2);
									}
								}
								sdnmess(&dnsr);
							}
							else if (!fdnmess(&dnsr))
								sdnmess(&dnsr);
						}
						else if (dnsr.dnsp)
							sdnmess(&dnsr);
					}
				}

				for (MYBYTE i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dnsTcpConn[i].sock, &readfds))
					{
						dnsr.sockInd = i;
						dnsr.sockLen = sizeof(dnsr.remote);
						dnsr.sock = accept(network.dnsTcpConn[i].sock, (sockaddr*)&dnsr.remote, &dnsr.sockLen);
						if (dnsr.sock == INVALID_SOCKET)
						{
							int error = WSAGetLastError();
							sprintf(logBuff, "Accept Failed, WSAError=%u", error);
							logDNSMess(logBuff, 1);
						}
						else
							procTCP(&dnsr);
					}
				}

				if (network.forwConn.ready && FD_ISSET(network.forwConn.sock, &readfds))
				{
					if (frdnmess(&dnsr))
					{
						sdnmess(&dnsr);

						if (verbatim || cfig.dnsLogLevel >= 2)
						{
							if (dnsr.dnsIndex < MAX_SERVERS)
							{
								if (dnsr.dnsp->header.ancount)
								{
									char tempbuff[512];
									if (getResult(&dnsr, tempbuff))
										sprintf(logBuff, "%s resolved from Forwarding server as %s", dnsr.cname, tempbuff);
									else
										sprintf(logBuff, "%s resolved from Forwarding server", dnsr.cname);
								}
								else
									sprintf(logBuff, "%s not found by Forwarding Server", dnsr.cname);
							}
							else
							{
								if (dnsr.dnsp->header.ancount)
								{
									char tempbuff[512];
									if (getResult(&dnsr, tempbuff))
										sprintf(logBuff, "%s resolved from Conditional Forwarder as %s", dnsr.cname, tempbuff);
									else
										sprintf(logBuff, "%s resolved from Conditional Forwarder", dnsr.cname);
								}
								else
									sprintf(logBuff, "%s not found by Conditional Forwarder", dnsr.cname);
							}

							logDNSMess(&dnsr, logBuff, 2);
						}
					}
				}
			}
		}
		else
			t = time(NULL);

		currentInd = newInd;
		checkSize(currentInd);

	} while (kRunning);
	EndThread();
}

char *AnsiToPunycode(const char *hostname, unsigned codepage)
{
	if (codepage != 0)
	{
		WCHAR utf16[512];
		char punycode[512];
		int cch = MultiByteToWideChar(codepage, 0, hostname, -1, utf16, _countof(utf16));
		if (cch >= 0)
		{
			ConvertToPunycode(utf16, punycode, sizeof punycode - 1);
			hostname = punycode;
		}
	}
	return const_cast<char *>(strdup(hostname));
}

bool chkQu(const char *query)
{
	if (strlen(query) >= UCHAR_MAX)
		return false;

	while (const char *dp = strchr(query, '.'))
	{
		size_t size = dp - query;
		if (size >= 64)
			return false;
		query += (size + 1);
	}
	return strlen(query) < 64;
}

MYWORD fQu(char *query, dnsPacket *mess, char *raw)
{
	MYBYTE *xname = (MYBYTE*)query;
	MYBYTE *xraw = (MYBYTE*)raw;
	MYWORD retvalue = 0;
	bool goneout = false;

	while (MYWORD size = *xraw++)
	{
		if (size <= 63)
		{
			if (!goneout)
				retvalue += (size + 1);

			memcpy(xname, xraw, size);
			xname += size;
			xraw += size;

			if (!*xraw)
				break;

			*xname++ = '.';
		}
		else
		{
			if (!goneout)
				retvalue += 2;

			goneout = true;
			size %= 128;
			size %= 64;
			size *= 256;
			size += *xraw;
			xraw = (MYBYTE*)mess + size;
		}
	}
	*xname = 0;

	if (!goneout)
		++retvalue;

	return retvalue;
}

MYWORD qLen(const char *query)
{
	size_t fullsize = 1;
	while (const char *dp = strchr(query, '.'))
	{
		size_t size = dp - query;
		query += (size + 1);
		fullsize += (size + 1);
	}
	if (size_t size = strlen(query))
	{
		fullsize += (size + 1);
	}
	//printf("%i\n",fullsize);
	return static_cast<MYWORD>(fullsize);
}

MYWORD pQu(char *raw, const char *query)
{
	size_t fullsize = 1;
	while (const char *dp = strchr(query, '.'))
	{
		size_t size = dp - query;
		*raw++ = static_cast<char>(size);
		memcpy(raw, query, size);
		raw += size;
		query += (size + 1);
		fullsize += (size + 1);
	}
	if (size_t size = strlen(query))
	{
		*raw++ = static_cast<char>(size);
		strcpy(raw, query);
		fullsize += (size + 1);
	}
	//printf("%i\n",fullsize);
	return static_cast<MYWORD>(fullsize);
}

MYWORD fUShort(void *raw)
{
	return ntohs(*((MYWORD*)raw));
}

MYDWORD fULong(void *raw)
{
	return ntohl(*((MYDWORD*)raw));
}

MYDWORD fIP(void *raw)
{
	return (*((MYDWORD*)raw));
}

MYBYTE pUShort(void *raw, MYWORD data)
{
	*((MYWORD*)raw) = htons(data);
	return sizeof(MYWORD);
}

MYBYTE pULong(void *raw, MYDWORD data)
{
	*((MYDWORD*)raw) = htonl(data);
	return sizeof(MYDWORD);
}

MYBYTE pIP(void *raw, MYDWORD data)
{
	*((MYDWORD*)raw) = data;
	return sizeof(MYDWORD);
}

void addRRBlank(data5 *req)
{
	req->dnsp->header.ra = 0;
	req->dnsp->header.at = 0;
	req->dnsp->header.aa = 0;
	req->dnsp->header.qr = 1;
	req->dp = &req->dnsp->data;
	req->dnsp->header.qdcount = 0;
	req->dnsp->header.ancount = 0;
	req->dnsp->header.nscount = 0;
	req->dnsp->header.adcount = 0;
}

void addRRNone(data5 *req)
{
	if (network.dns[0])
		req->dnsp->header.ra = 1;
	else
		req->dnsp->header.ra = 0;

	req->dnsp->header.at = 0;
	req->dnsp->header.aa = 0;

	req->dnsp->header.qr = 1;
	req->dnsp->header.ancount = 0;
	req->dnsp->header.nscount = 0;
	req->dnsp->header.adcount = 0;
}

void addRRExt(data5 *req)
{
	char tempbuff[512];
	//printf("%s=%s\n", req->cname, req->query);

	if (strcasecmp(req->cname, req->query))
	{
		memcpy(req->temp, req->raw, req->bytes);
		dnsPacket *input = (dnsPacket*)req->temp;
		req->dnsp = (dnsPacket*)req->raw;

		req->dnsp->header.aa = 0;
		req->dnsp->header.at = 0;
		req->dnsp->header.qdcount = htons(1);
		req->dnsp->header.ancount = htons(1);

		//manuplate the response
		req->dp = &req->dnsp->data;
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);

		char *indp = &input->data;

		for (int i = 1; i <= ntohs(input->header.qdcount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			indp += 4;
		}

		for (int i = 1; i <= ntohs(input->header.ancount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			MYWORD type = fUShort(indp);
			req->dp += pQu(req->dp, tempbuff);
			memcpy(req->dp, indp, 8);
			req->dp += 8;
			indp += 8;
			//indp += 2; //type
			//indp += 2; //class
			//indp += 4; //ttl
			MYWORD zLen = fUShort(indp);
			indp += 2; //datalength

			switch (type)
			{
			case DNS_TYPE_A:
				req->dp += pUShort(req->dp, zLen);
				req->dp += pIP(req->dp, fIP(indp));
				break;
			case DNS_TYPE_CNAME:
				fQu(tempbuff, input, indp);
				MYWORD dl = pQu(req->dp + 2, tempbuff);
				req->dp += pUShort(req->dp, dl);
				req->dp += dl;
				break;
			}

			indp += zLen;
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		}
	}
	else
	{
		req->dnsp = (dnsPacket*)req->raw;
		req->dp = req->raw + req->bytes;
	}
}

void addRRCache(data5 *req, data7 *cache)
{
	char tempbuff[512];
	//manuplate the response
	//printf("%s=%s\n", req->cname, req->query);
	dnsPacket *input = (dnsPacket*)cache->response;
	char *indp = &input->data;
	req->dnsp = (dnsPacket*)req->raw;
	req->dp = &req->dnsp->data;

	req->dnsp->header.aa = 0;
	req->dnsp->header.at = 0;
	req->dnsp->header.ancount = 0;
	req->dnsp->header.qdcount = htons(1);

	req->dp = &req->dnsp->data;
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);

	if (strcasecmp(req->cname, req->query))
	{
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
		req->dnsp->header.ancount = htons(1);
	}

	for (int i = 1; i <= ntohs(input->header.qdcount); i++)
	{
		indp += fQu(tempbuff, input, indp);
		indp += 4;
	}

	for (int i = 1; i <= ntohs(input->header.ancount); i++)
	{
		indp += fQu(tempbuff, input, indp);
		MYWORD type = fUShort(indp);

		if (!strcasecmp(tempbuff, req->query))
			strcpy(tempbuff, req->query);

		req->dp += pQu(req->dp, tempbuff);
		memcpy(req->dp, indp, 8);
		req->dp += 8;
		indp += 8;
		//indp += 2; //type
		//indp += 2; //class
		//indp += 4; //ttl
		MYWORD zLen = fUShort(indp);
		indp += 2; //datalength

		switch (type)
		{
		case DNS_TYPE_A:
			req->dp += pUShort(req->dp, zLen);
			req->dp += pIP(req->dp, fIP(indp));
			break;
		case DNS_TYPE_CNAME:
			fQu(tempbuff, input, indp);
			MYWORD dl = pQu(req->dp + 2, tempbuff);
			req->dp += pUShort(req->dp, dl);
			req->dp += dl;
			break;
		}

		indp += zLen;
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	}
}

void addRRA(data5 *req)
{
	if (strcasecmp(req->query, req->cname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		data7 *cache = req->iterBegin->second;

		if (strcasecmp(cache->mapname, req->mapname))
			break;

		if (cache->ip)
		{
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			req->dp += pQu(req->dp, req->cname);
			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.lease);
			req->dp += pUShort(req->dp, 4);
			req->dp += pIP(req->dp, cache->ip);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRPtr(data5 *req)
{
	for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		if (data7 *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->mapname, req->mapname))
				break;

			req->dp += pQu(req->dp, req->query);
			req->dp += pUShort(req->dp, DNS_TYPE_PTR);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			req->dp += pULong(req->dp, cfig.lease);

			if (!cache->hostname[0])
				strcpy(req->cname, cfig.zone);
			else if (!strchr(cache->hostname, '.'))
				sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
			else
				strcpy(req->cname, cache->hostname);

			req->dp += pUShort(req->dp, qLen(req->cname));
			req->dp += pQu(req->dp, req->cname);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRServerA(data5 *req)
{
	if (strcasecmp(req->query, req->cname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->cname);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, network.dnsUdpConn[req->sockInd].server);

	for (;req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		if (data7 *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->mapname, req->mapname))
				break;

			if (cache->ip && cache->ip != network.dnsUdpConn[req->sockInd].server)
			{
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				req->dp += pUShort(req->dp, 4);
				req->dp += pIP(req->dp, cache->ip);
			}
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAny(data5 *req, bool adFlag)
{
	while (req->iterBegin != dnsCache[currentInd].end())
	{
		if (data7 *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->mapname, req->mapname))
				break;

			if (adFlag)
				req->dnsp->header.adcount = htons(htons(req->dnsp->header.adcount) + 1);
			else
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

			switch (cache->dataType)
			{
			case LOCAL_A:
			case SERVER_A_AUTH:
			case STATIC_A_AUTH:
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				req->dp += pUShort(req->dp, 4);
				req->dp += pIP(req->dp, cache->ip);
				break;

			case LOCAL_PTR_AUTH:
			case LOCAL_PTR_NAUTH:
			case STATIC_PTR_AUTH:
			case STATIC_PTR_NAUTH:
			case SERVER_PTR_AUTH:
			case SERVER_PTR_NAUTH:
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_PTR);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);

				if (!cache->hostname[0])
					strcpy(req->temp, cfig.zone);
				else if (!strchr(cache->hostname, '.'))
					strcpy(req->temp, cache->hostname);
				else
					sprintf(req->temp, "%s.%s", cache->hostname, cfig.zone);

				req->dp += pUShort(req->dp, qLen(req->temp));
				req->dp += pQu(req->dp, req->temp);
				break;

			case EXT_CNAME:
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				req->dp += pUShort(req->dp, qLen(cache->hostname));
				req->dp += pQu(req->dp, cache->hostname);
				return;

			case LOCAL_CNAME:
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
				req->dp += pUShort(req->dp, qLen(req->cname));
				req->dp += pQu(req->dp, req->cname);
				strcpy(req->mapname, cache->hostname);
				myLower(req->mapname);
				req->iterBegin = dnsCache[currentInd].find(req->mapname);
				adFlag = true;
				continue;
			}
			++req->iterBegin;
		}
	}
}

void addRRWildA(data5 *req, MYDWORD ip)
{
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostA(data5 *req, data7 *cache)
{
	if (strcasecmp(req->query, req->mapname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->mapname));
		req->dp += pQu(req->dp, req->mapname);
	}

	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->mapname);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, cache->ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostPtr(data5 *req, data7 *cache)
{
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_PTR);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, qLen(cache->hostname));
	req->dp += pQu(req->dp, cache->hostname);
	//req->bytes = req->dp - req->raw;
}

void addRRMX(data5 *req)
{
	if (cfig.mxCount[currentInd])
	{
		for (MYBYTE m = 0; m < cfig.mxCount[currentInd]; m++)
		{
			addRRMXOne(req, m);
		}
	}

	//req->bytes = req->dp - req->raw;
}

void addRRNS(data5 *req)
{
	//printf("%s=%u\n", cfig.ns, cfig.expireTime);
	if (cfig.authorized && cfig.expireTime > t)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.authority);
		else
			req->dp += pQu(req->dp, cfig.zone);

		req->dp += pUShort(req->dp, DNS_TYPE_NS);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);

		req->dp += pULong(req->dp, cfig.expire);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
		{
			req->dp += pUShort(req->dp, qLen(cfig.nsP));
			req->dp += pQu(req->dp, cfig.nsP);
		}
		else
		{
			req->dp += pUShort(req->dp, qLen(cfig.nsA));
			req->dp += pQu(req->dp, cfig.nsA);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRSOA(data5 *req)
{
	if (cfig.authorized)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.authority);
		else
			req->dp += pQu(req->dp, cfig.zone);

		req->dp += pUShort(req->dp, DNS_TYPE_SOA);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		char *data = req->dp;
		req->dp += 2;

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.nsP);
		else
			req->dp += pQu(req->dp, cfig.nsA);

		sprintf(req->temp, "hostmaster.%s", cfig.zone);
		req->dp += pQu(req->dp, req->temp);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pULong(req->dp, cfig.serial2);
		else
			req->dp += pULong(req->dp, cfig.serial1);

		req->dp += pULong(req->dp, cfig.refresh);
		req->dp += pULong(req->dp, cfig.retry);
		req->dp += pULong(req->dp, cfig.expire);
		req->dp += pULong(req->dp, cfig.minimum);
		pUShort(data, static_cast<MYWORD>(req->dp - data) - 2);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRSOAuth(data5 *req)
{
	if (cfig.authorized)
	{
		req->dnsp->header.nscount = htons(htons(req->dnsp->header.nscount) + 1);
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.authority);
		else
			req->dp += pQu(req->dp, cfig.zone);

		req->dp += pUShort(req->dp, DNS_TYPE_SOA);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		char *data = req->dp;
		req->dp += 2;

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.nsP);
		else
			req->dp += pQu(req->dp, cfig.nsA);

		sprintf(req->temp, "hostmaster.%s", cfig.zone);
		req->dp += pQu(req->dp, req->temp);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pULong(req->dp, cfig.serial2);
		else
			req->dp += pULong(req->dp, cfig.serial1);

		req->dp += pULong(req->dp, cfig.refresh);
		req->dp += pULong(req->dp, cfig.retry);
		req->dp += pULong(req->dp, cfig.expire);
		req->dp += pULong(req->dp, cfig.minimum);
		pUShort(data, static_cast<MYWORD>(req->dp - data) - 2);
	}
	//req->bytes = req->dp - req->raw;
}

void addNS(data5 *req)
{
	if (cfig.authorized && cfig.expireTime > t)
	{
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		req->dnsp->header.nscount = htons(1);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.authority);
		else
			req->dp += pQu(req->dp, cfig.zone);

		req->dp += pUShort(req->dp, DNS_TYPE_NS);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);

		if (cfig.expire >= INT_MAX)
			req->dp += pULong(req->dp, UINT_MAX);
		else
			req->dp += pULong(req->dp, cfig.expire);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
		{
			req->dp += pUShort(req->dp, qLen(cfig.nsP));
			req->dp += pQu(req->dp, cfig.nsP);
		}
		else
		{
			req->dp += pUShort(req->dp, qLen(cfig.nsA));
			req->dp += pQu(req->dp, cfig.nsA);
		}

		addRRAd(req);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAd(data5 *req)
{
	if (cfig.authorized && cfig.expireTime > t)
	{
		req->dnsp->header.adcount = htons(htons(req->dnsp->header.adcount) + 1);

		if (req->dnType == DNTYPE_P_LOCAL || req->dnType == DNTYPE_P_EXT || req->dnType == DNTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.nsP);
		else
			req->dp += pQu(req->dp, cfig.nsA);

		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, 4);

		if (cfig.replication)
			req->dp += pIP(req->dp, cfig.zoneServers[0]);
		else
			req->dp += pIP(req->dp, network.listenServers[req->sockInd]);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAOne(data5 *req)
{
	if (data7 *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->mapname[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->mapname, '.'))
			sprintf(req->cname, "%s.%s", cache->mapname, cfig.zone);
		else
			strcpy(req->cname, cache->mapname);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
		//req->bytes = req->dp - req->raw;
	}
}

void addRRPtrOne(data5 *req)
{
	if (data7 *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		sprintf(req->cname, "%s%s", cache->mapname, arpa);
		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_PTR);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->hostname, '.'))
			sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
		else
			strcpy(req->cname, cache->hostname);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	//req->bytes = req->dp - req->raw;
}

void addRRSTAOne(data5 *req)
{
	if (data7 *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->mapname[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->mapname, '.'))
			sprintf(req->cname, "%s.%s", cache->mapname, cfig.zone);
		else
			strcpy(req->cname, cache->mapname);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRCNOne(data5 *req)
{
	if (data7 *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->mapname[0])
			strcpy(req->cname, cfig.zone);
		else if (strchr(cache->mapname, '.'))
			strcpy(req->cname, cache->mapname);
		else
			sprintf(req->cname, "%s.%s", cache->mapname, cfig.zone);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, cfig.zone);
		else if (strchr(cache->hostname, '.'))
			strcpy(req->cname, cache->hostname);
		else
			sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRMXOne(data5 *req, MYBYTE m)
{
	//req->dp += pQu(req->dp, req->query);
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, cfig.zone);
	req->dp += pUShort(req->dp, DNS_TYPE_MX);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, static_cast<MYWORD>(strlen(cfig.mxServers[currentInd][m].hostname) + 4));
	req->dp += pUShort(req->dp, cfig.mxServers[currentInd][m].pref);
	req->dp += pQu(req->dp, cfig.mxServers[currentInd][m].hostname);
	//req->bytes = req->dp - req->raw;
}

void procHTTP(data19 *req)
{
	char logBuff[256];
	//debug("procHTTP");

	req->ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	req->ling.l_linger = 30; //0 = discard data, nonzero = wait for data sent
	setsockopt(req->sock, SOL_SOCKET, SO_LINGER, (const char*)&req->ling, sizeof(req->ling));

	timeval tv1;
	tv1.tv_sec = 1;
	tv1.tv_usec = 0;

	fd_set readfds1;
	FD_ZERO(&readfds1);
	FD_SET(req->sock, &readfds1);

	char buffer[1024];

	int bytes = -1;
	if (select((req->sock + 1), &readfds1, NULL, NULL, &tv1))
		bytes = recv(req->sock, buffer, sizeof buffer - 1, 0);

	if (bytes <= 0)
	{
		int error = WSAGetLastError();
		sprintf(logBuff, "Client %s, HTTP Message Receive failed, WSAError %d", IP2String(req->remote.sin_addr.s_addr), error);
		logDHCPMess(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}

	sprintf(logBuff, "Client %s, HTTP Request Received", IP2String(req->remote.sin_addr.s_addr));
	logDHCPMess(logBuff, 2);

	if (cfig.httpClients[0] && !findServer(cfig.httpClients, 8, req->remote.sin_addr.s_addr))
	{
		req->code = 403;
		sprintf(logBuff, "Client %s, HTTP Access Denied", IP2String(req->remote.sin_addr.s_addr));
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
			sendStatus(req);
		/*else if (!strcasecmp(fp, "/scopestatus"))
			sendScopeStatus(req);*/
		else
		{
			req->code = 404;
			if (*fp != '\0')
			{
				sprintf(logBuff, "Client %s, %.100s not found", IP2String(req->remote.sin_addr.s_addr), fp);
				logDHCPMess(logBuff, 2);
			}
			else
			{
				sprintf(logBuff, "Client %s, Invalid http request", IP2String(req->remote.sin_addr.s_addr));
				logDHCPMess(logBuff, 2);
			}
		}
	}
	catch (std::bad_alloc)
	{
		req->code = 507;
		sprintf(logBuff, "Memory Error");
		logDHCPMess(logBuff, 1);
	}
	BeginThread(sendHTTP, 0, req);
}

void sendStatus(data19 *req)
{
	char tempbuff[512];
	//debug("sendStatus");

	dhcpMap::iterator p;

	class : public string, public string::CtorSprintf { } fp;
	typedef string sprintf;

	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp, "<table bgcolor='#b8b8b8' border='1' cellpadding='1'>\n");

	if (cfig.dhcpRepl > t)
	{
		fp += sprintf(fp, "<tr><th colspan='5'><font size='5'><i>Active Leases</i></font></th></tr>\n");
		fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname</th><th>Server</th></tr>\n");
	}
	else
	{
		fp += sprintf(fp, "<tr><th colspan='4'><font size='5'><i>Active Leases</i></font></th></tr>\n");
		fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname</th></tr>\n");
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

/*
	fp += sprintf(fp, "</table>\n<br>\n<table bgcolor='#b8b8b8' border='1' cellpadding='1'>\n");
	fp += sprintf(fp, "<tr><th colspan=\"5\"><font size=\"5\"><i>Free Dynamic Leases</i></font></th></tr>\n");
	MYBYTE colNum = 0;

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount; rangeInd++)
	{
		for (MYDWORD ind = 0, iip = cfig.dhcpRanges[rangeInd].rangeStart; kRunning && iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] < t)
			{
				if (!colNum)
				{
					fp += sprintf(fp, "<tr>");
					colNum = 1;
				}
				else if (colNum < 5)
					++colNum;
				else
				{
					fp += sprintf(fp, "</tr>\n<tr>");
					colNum = 1;
				}

				fp += sprintf(fp, td200, IP2String(htonl(iip)));
			}
		}
	}

	if (colNum)
		fp += sprintf(fp, "</tr>\n");
*/
	fp += sprintf(fp, "</table>\n<br>\n<table bgcolor='#b8b8b8' border='1' cellpadding='1'>\n");
	fp += sprintf(fp, "<tr><th colspan='4'><font size='5'><i>Free Dynamic Leases</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><td colspan='2'><b>DHCP Range</b></td><td align='right'><b>Available Leases</b></td><td align='right'><b>Free Leases</b></td></tr>\n");

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

	fp += sprintf(fp, "</table>\n<br>\n<table bgcolor='#b8b8b8' border='1' cellpadding='1'>\n");
	fp += sprintf(fp, "<tr><th colspan='4'><font size='5'><i>Free Static Leases</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Mac Address</th><th>IP</th></tr>\n");

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

	fp.swap(req->data);
	req->code = 200;
}

/*
void sendScopeStatus(data19 *req)
{
	//debug("sendScopeStatus");

	class : public string, public string::CtorSprintf { } fp;
	typedef string sprintf;

	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp, "<table bgcolor='#b8b8b8' border='1' cellpadding='1'>\n");
	fp += sprintf(fp, "<tr><th colspan='4'><font size='5'><i>Scope Status</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><td><b>DHCP Range</b></td><td align=\"right\"><b>IPs Used</b></td><td align=\"right\"><b>IPs Free</b></td><td align=\"right\"><b>%% Free</b></td></tr>\n");

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount; ++rangeInd)
	{
		float ipused = 0;
		float ipfree = 0;
		int ind = 0;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] > t)
				++ipused;
			else
				++ipfree;
		}

		;
		;
		fp += sprintf(fp, "<tr><td>%s - %s</td><td align=\"right\">%5.0f</td><td align=\"right\">%5.0f</td><td align=\"right\">%2.2f</td></tr>\n",
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeStart)),
			IP2String(ntohl(cfig.dhcpRanges[rangeInd].rangeEnd)),
			ipused, ipfree, ((ipfree * 100)/(ipused + ipfree)));
	}

	fp += sprintf(fp, "</table>\n</body>\n</html>");

	fp.swap(req->data);
	req->code = 200;
}
*/

void __cdecl sendHTTP(void *param)
{
	data19 *req = static_cast<data19 *>(param);

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
		dp += sprintf(dp, "Content-Length: %d\r\n\r\n", req->data.length());
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

	struct
	{
		int bytes;
		const char *dp;
	} chunks[] =
	{
		{ dp - header, header },
		{ req->data.length(), req->data.c_str() }
	}, *pchunk = chunks;

	do
	{
		timeval tv1;
		tv1.tv_sec = 1;
		tv1.tv_usec = 0;

		fd_set writefds1;
		FD_ZERO(&writefds1);
		FD_SET(req->sock, &writefds1);

		if (!select((req->sock + 1), NULL, &writefds1, NULL, &tv1))
			break;

		int bytes = pchunk->bytes;
		if (bytes > 1024)
			bytes = 1024;

		bytes = send(req->sock, pchunk->dp, bytes, 0);
		if (bytes < 0)
			break;

		pchunk->dp += bytes;
		pchunk->bytes -= bytes;

	} while (kRunning &&
		(pchunk->bytes > 0 || ++pchunk < chunks + _countof(chunks)));

	closesocket(req->sock);
	delete req;
	EndThread();
}

void procTCP(data5 *req)
{
	char logBuff[256];
	//debug("procTCP");
	req->ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	req->ling.l_linger = 10; //0 = discard data, nonzero = wait for data sent
	setsockopt(req->sock, SOL_SOCKET, SO_LINGER, (const char*)&req->ling, sizeof(req->ling));

	req->bytes = recvTcpDnsMess(req->raw, req->sock, sizeof(req->raw));
	//printf("%u\n",req->bytes);

	if (req->bytes < 2)
	{
		sprintf(logBuff, "Error Getting TCP DNS Message");
		logDNSMess(logBuff, 1);
		closesocket(req->sock);
		return;
	}

	//MYWORD pktSize = fUShort(req->raw);
	req->dp = req->raw + 2;
	req->dnsp = (dnsPacket*)(req->dp);
	req->dp = &req->dnsp->data;

	if (req->dnsp->header.qr != 0 || ntohs(req->dnsp->header.qdcount) != 1 || ntohs(req->dnsp->header.ancount))
	{
		sprintf(logBuff, "DNS Query Format Error");
		logTCPMess(req, logBuff, 1);
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_FORMATERROR;
		req->dnsp->header.qdcount = 0;
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		req->dp += fQu(req->query, req->dnsp, req->dp);
		req->qtype = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	MYDWORD clientIP = req->remote.sin_addr.s_addr;

	if (!findServer(network.allServers, MAX_SERVERS, clientIP) && !findServer(cfig.zoneServers, MAX_TCP_CLIENTS, clientIP) && !findServer(&cfig.zoneServers[2], MAX_TCP_CLIENTS - 2, clientIP))
	{
		sprintf(logBuff, "DNS TCP Query, Access Denied");
		logTCPMess(req, logBuff, 1);
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_REFUSED;
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (req->dnsp->header.opcode != OPCODE_STANDARD_QUERY)
	{
		switch (req->dnsp->header.opcode)
		{
		case OPCODE_INVERSE_QUERY:
			sprintf(logBuff, "Inverse query not supported");
			break;

		case OPCODE_SRVR_STAT_REQ:
			sprintf(logBuff, "Server Status Request not supported");
			break;

		case OPCODE_NOTIFY:
			sprintf(logBuff, "Notify not supported");
			break;

		case OPCODE_DYNAMIC_UPDATE:
			sprintf(logBuff, "Dynamic Update not needed/supported by Dual Server");
			break;

		default:
			sprintf(logBuff, "OpCode %u not supported", req->dnsp->header.opcode);
			break;
		}

		logTCPMess(req, logBuff, 1);

		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTIMPL;
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (req->qclass != DNS_CLASS_IN)
	{
		sprintf(logBuff, "DNS Class %u not supported", req->qclass);
		logTCPMess(req, logBuff, 1);
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTIMPL;
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (!req->qtype)
	{
		sprintf(logBuff, "missing query type");
		logTCPMess(req, logBuff, 1);
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_FORMATERROR;
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->qLen = static_cast<MYWORD>(strlen(req->cname));
	req->dnType = makeLocal(req->mapname);
	bool AXFRError = false;

	if (req->dnType == DNTYPE_A_EXT && req->qLen > cfig.zLen)
	{
		char *dp = req->cname + (req->qLen - cfig.zLen);

		if (!strcasecmp(dp, cfig.zone))
			req->dnType = DNTYPE_A_SUBZONE;
	}

	if (req->qtype != DNS_TYPE_NS && req->qtype != DNS_TYPE_SOA && req->qtype != DNS_TYPE_AXFR && req->qtype != DNS_TYPE_IXFR)
	{
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTIMPL;
		sendTCPmess(req);
		sprintf(logBuff, "DNS TCP query % Query Type not supported", strquery(req));
		logTCPMess(req, logBuff, 1);
	}
	else if (!cfig.authorized || (req->dnType != DNTYPE_A_ZONE && req->dnType != DNTYPE_A_SUBZONE && req->dnType != DNTYPE_P_ZONE && req->dnType != DNTYPE_P_LOCAL))
	{
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTAUTH;
		sendTCPmess(req);
		sprintf(logBuff, "Server is not authority for zone %s", req->query);
		logTCPMess(req, logBuff, 1);
	}
	else if (cfig.expireTime < t)
	{
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTZONE;
		sendTCPmess(req);
		sprintf(logBuff, "Zone %s expired", req->query);
		logTCPMess(req, logBuff, 1);
	}
	else
	{
		switch (req->qtype)
		{
		case DNS_TYPE_SOA:
			if (req->dnType == DNTYPE_A_ZONE || req->dnType == DNTYPE_P_ZONE)
			{
				addRRNone(req);
				addRRSOA(req);
				req->dnsp->header.aa = 0;
				req->dnsp->header.at = 0;
				req->dnsp->header.rcode = RCODE_NOERROR;
				sendTCPmess(req);
				sprintf(logBuff, "SOA Sent for zone %s", req->query);
				logTCPMess(req, logBuff, 2);
			}
			else
			{
				addRRNone(req);
				addRRSOAuth(req);
				req->dnsp->header.aa = 0;
				req->dnsp->header.at = 0;
				req->dnsp->header.rcode = RCODE_NOERROR;
				sendTCPmess(req);
				sprintf(logBuff, "%s not found", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			break;

		case DNS_TYPE_NS:
			if (req->dnType == DNTYPE_A_ZONE || req->dnType == DNTYPE_P_ZONE)
			{
				addRRNone(req);
				addRRNS(req);
				addRRAd(req);
				req->dnsp->header.aa = 0;
				req->dnsp->header.at = 0;
				req->dnsp->header.rcode = RCODE_NOERROR;
				sendTCPmess(req);
				sprintf(logBuff, "NS Sent for Zone %s", req->query);
				logTCPMess(req, logBuff, 2);
			}
			else
			{
				addRRNone(req);
				addNS(req);
				req->dnsp->header.aa = 0;
				req->dnsp->header.at = 0;
				req->dnsp->header.rcode = RCODE_NOERROR;
				sendTCPmess(req);
				sprintf(logBuff, "%s not found", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			break;

		case DNS_TYPE_AXFR:
		case DNS_TYPE_IXFR:

			if (req->dnType == DNTYPE_A_ZONE)
			{
				MYDWORD tempserial = cfig.serial1;
				MYWORD records = 0;

				addRRBlank(req);
				addRRSOA(req);

				if (!sendTCPmess(req))
				{
					AXFRError = true;
					break;
				}
				++records;

				addRRBlank(req);
				addRRNS(req);

				if (!sendTCPmess(req))
				{
					AXFRError = true;
					break;
				}
				++records;

				req->iterBegin = dnsCache[currentInd].begin();

				while (!AXFRError && req->iterBegin != dnsCache[currentInd].end())
				{
					addRRBlank(req);

					if (req->iterBegin->second->expiry > t)
					{
						//printf("%s=%d=%d\n",req->iterBegin->second->mapname, req->iterBegin->second->dataType, req->iterBegin->second->expiry);

						switch (req->iterBegin->second->dataType)
						{
						case LOCAL_A:
							addRRAOne(req);
							break;

						case SERVER_A_AUTH:
						case STATIC_A_AUTH:
							addRRSTAOne(req);
							break;

						case LOCAL_CNAME:
						case EXT_CNAME:
							addRRCNOne(req);
							break;

						default:
							++req->iterBegin;
							continue;
						}

						if (tempserial != cfig.serial1)
						{
							AXFRError = true;
							break;
						}

						if (!sendTCPmess(req))
						{
							AXFRError = true;
							break;
						}
						++records;
					}
					++req->iterBegin;
				}

				for (MYBYTE m = 0; m < cfig.mxCount[currentInd]; m++)
				{
					addRRBlank(req);
					addRRMXOne(req, m);

					if (tempserial != cfig.serial1)
					{
						AXFRError = true;
						break;
					}

					if (!sendTCPmess(req))
					{
						AXFRError = true;
						break;
					}
					++records;
				}

				addRRBlank(req);
				addRRSOA(req);

				if (!AXFRError && tempserial == cfig.serial1)
				{
					if (sendTCPmess(req))
					{
						++records;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMess(req, logBuff, 2);

//							if (cfig.replication && clientIP == cfig.zoneServers[1] && cfig.qc == 2)
//								cfig.qc = 3;
					}
				}
			}
			else if (req->dnType == DNTYPE_P_ZONE)
			{
/*
				if (clientIP == cfig.zoneServers[0])
				{
					addRRNone(req);
					req->dnsp->header.rcode = RCODE_REFUSED;
					sendTCPmess(req);
					closesocket(req->sock);
					return;
				}
*/
				MYDWORD tempserial = cfig.serial2;
				MYWORD records = 0;

				addRRBlank(req);
				addRRSOA(req);

				if (!sendTCPmess(req))
				{
					AXFRError = true;
					break;
				}
				++records;

				addRRBlank(req);
				addRRNS(req);

				if (!sendTCPmess(req))
				{
					AXFRError = true;
					break;
				}
				++records;

				req->iterBegin = dnsCache[currentInd].begin();

				while (!AXFRError && req->iterBegin != dnsCache[currentInd].end())
				{
					addRRBlank(req);

					if (req->iterBegin->second->expiry > t)
					{
						switch (req->iterBegin->second->dataType)
						{
						case LOCAL_PTR_AUTH:
						case STATIC_PTR_AUTH:
						case SERVER_PTR_AUTH:
							addRRPtrOne(req);
							break;

						default:
							++req->iterBegin;
							continue;
						}

						if (tempserial != cfig.serial2)
						{
							AXFRError = true;
							break;
						}

						if (!sendTCPmess(req))
						{
							AXFRError = true;
							break;
						}
						++records;

					}
					++req->iterBegin;
				}

				addRRBlank(req);
				addRRSOA(req);

				if (!AXFRError && tempserial == cfig.serial2)
				{
					if (sendTCPmess(req))
					{
						++records;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMess(req, logBuff, 2);

//							if (cfig.replication && clientIP == cfig.zoneServers[1] && cfig.qc == 3)
//								cfig.dnsRepl = t + cfig.refresh;
					}
				}
			}
			else
			{
				addRRNone(req);
				req->dnsp->header.rcode = RCODE_NOTAUTH;
				sendTCPmess(req);
				sprintf(logBuff, "Server is not authority for zone %s", req->query);
				logTCPMess(req, logBuff, 1);
			}
			break;
		}
	}
}

int sendTCPmess(data5 *req)
{
	req->dnsp->header.ra = 0;
	req->bytes = req->dp - req->raw;
	pUShort(req->raw, static_cast<MYWORD>(req->bytes - 2));

	if (req->bytes != send(req->sock, req->raw, req->bytes, 0))
		return 0;

	return req->bytes;
}

int gdnmess(data5 *req, MYBYTE sockInd)
{
	char logBuff[256];
	//debug("gdnmess");

	memset(req, 0, sizeof(data5));
	req->sockLen = sizeof(req->remote);

	req->bytes = recvfrom(network.dnsUdpConn[sockInd].sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	if (req->bytes <= 0)
		return 0;

	req->sockInd = sockInd;
	req->dnsp = (dnsPacket*)req->raw;

	if (req->dnsp->header.qr != 0)
		return 0;

	if (req->dnsp->header.opcode != OPCODE_STANDARD_QUERY)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			switch (req->dnsp->header.opcode)
			{
			case OPCODE_INVERSE_QUERY:
				sprintf(logBuff, "Inverse query not supported");
				break;

			case OPCODE_SRVR_STAT_REQ:
				sprintf(logBuff, "Server Status Request not supported");
				break;

			case OPCODE_NOTIFY:
				sprintf(logBuff, "Notify not supported");
				break;

			case OPCODE_DYNAMIC_UPDATE:
				sprintf(logBuff, "Dynamic Update not needed/supported by Dual Server");
				break;

			default:
				sprintf(logBuff, "OpCode %d not supported", req->dnsp->header.opcode);
				break;
			}
			logDNSMess(req, logBuff, 1);
		}

		addRRBlank(req);
		req->dnsp->header.rcode = RCODE_NOTIMPL;
		return 0;
	}

	if (ntohs(req->dnsp->header.qdcount) != 1 || ntohs(req->dnsp->header.ancount))
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Query Format Error");
			logDNSMess(req, logBuff, 1);
		}

		addRRBlank(req);
		req->dnsp->header.rcode = RCODE_FORMATERROR;
		return 0;
	}

	req->dp = &req->dnsp->data;

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		req->dp += fQu(req->query, req->dnsp, req->dp);
		req->qtype = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	if (req->qclass != DNS_CLASS_IN)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Class %d not supported", req->qclass);
			logDNSMess(req, logBuff, 1);
		}
		addRRNone(req);
		req->dnsp->header.rcode = RCODE_NOTIMPL;
		return 0;
	}

	if (!req->qtype)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "missing query type");
			logDNSMess(req, logBuff, 1);
		}

		addRRNone(req);
		req->dnsp->header.rcode = RCODE_FORMATERROR;
		return 0;
	}

	MYDWORD ip = req->remote.sin_addr.s_addr;
	MYDWORD iip = ntohl(ip);

	for (int i = 0; i < MAX_DNS_RANGES && cfig.dnsRanges[i].rangeStart; i++)
	{
		if (iip >= cfig.dnsRanges[i].rangeStart && iip <= cfig.dnsRanges[i].rangeEnd)
			return req->bytes;
	}

	if (isLocal(ip))
		return req->bytes;

	if (findEntry(currentInd, IP2String(iip, req->cname)))
		return req->bytes;

	if (findServer(network.allServers, MAX_SERVERS, ip))
		return req->bytes;

	addRRNone(req);
	req->dnsp->header.rcode = RCODE_REFUSED;

	if (verbatim || cfig.dnsLogLevel >= 1)
	{
		sprintf(logBuff, "DNS UDP Query, Access Denied");
		logDNSMess(req, logBuff, 1);
	}
	return 0;
}

int sdnmess(data5 *req)
{
	//debug("sdnmess");

	req->bytes = req->dp - req->raw;

	req->bytes = sendto(network.dnsUdpConn[req->sockInd].sock,
	                    req->raw,
	                    req->bytes,
	                    0,
	                    (sockaddr*)&req->remote,
	                    sizeof(req->remote));

	if (req->bytes <= 0)
		return 0;

	return req->bytes;
}

MYWORD scanloc(data5 *req)
{
	char logBuff[256];
	//debug("scanloc");

	if (!req->query[0])
		return 0;

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->dnType = makeLocal(req->mapname);
	//printf("LocalCode=%u query=%s mapname=%s\n", req->dnType, req->query, req->mapname);

	switch (req->qtype)
	{
	case DNS_TYPE_PTR:
		break;

	case DNS_TYPE_A:
		if (req->dnType == DNTYPE_A_BARE)
			sprintf(req->cname, "%s.%s", req->query, cfig.zone);
		break;

	case DNS_TYPE_MX:
		if (!strcasecmp(req->query, cfig.zone) && (cfig.authorized || cfig.mxServers[currentInd][0].hostname[0]))
		{
			addRRNone(req);
			addRRMX(req);
			addNS(req);
			return 1;
		}
		return 0;

	case DNS_TYPE_NS:
		if (cfig.authorized)
		{
			if (req->dnType == DNTYPE_P_ZONE)
			{
				addRRNone(req);
				addRRNS(req);
				addRRAd(req);
				return 1;
			}
			else if (req->dnType == DNTYPE_A_ZONE)
			{
				addRRNone(req);
				addRRNS(req);
				addRRAd(req);
				return 1;
			}
		}
		return 0;

	case DNS_TYPE_SOA:
		if (req->dnType == DNTYPE_A_LOCAL)
		{
			myLower(req->cname);
			DWORD ip = req->remote.sin_addr.s_addr;
			// The ~~ avoids warning C4244 but is otherwise meaningless
			MYBYTE pType = isLocal(ip) ?~~ LOCAL_PTR_AUTH : LOCAL_PTR_NAUTH;
			add2Cache(currentInd, req->cname, ip, INT_MAX, LOCAL_A, pType);
			return 1;
		}
		if (cfig.authorized)
		{
			if (req->dnType == DNTYPE_P_ZONE)
			{
				addRRNone(req);
				addRRSOA(req);

				if (cfig.replication == 1 && req->remote.sin_addr.s_addr == cfig.zoneServers[1] && cfig.qc == 1)
				{
					cfig.dnsRepl = t + cfig.refresh;
					cfig.qc = 0;
				}

				return 1;
			}
			else if (req->dnType == DNTYPE_A_ZONE)
			{
				addRRNone(req);
				addRRSOA(req);

				if (cfig.replication == 1 && req->remote.sin_addr.s_addr == cfig.zoneServers[1])
					cfig.qc = 1;

				return 1;
			}
		}
		return 0;

	case DNS_TYPE_ANY:
		req->iterBegin = dnsCache[currentInd].find(req->mapname);

		if (req->iterBegin != dnsCache[currentInd].end() && req->iterBegin->second->dataType != CACHED)
		{
			switch (req->dnType)
			{
			case DNTYPE_A_BARE:
				addRRNone(req);
				sprintf(req->cname, "%s.%s", req->mapname, cfig.zone);
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
				req->dp += pQu(req->dp, req->mapname);
				req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				req->dp += pUShort(req->dp, qLen(req->cname));
				req->dp += pQu(req->dp, req->cname);
				req->dnsp->header.ancount = htons(1);
				addRRAny(req, true);
				return 1;

			case DNTYPE_A_ZONE:
				addRRNone(req);
				if (cfig.authorized)
				{
					addRRSOA(req);
					addRRNS(req);
					req->dnsp->header.ancount = htons(2);
				}

				for (MYBYTE m = 0; m < cfig.mxCount[currentInd]; m++)
					addRRMXOne(req, m);

				addRRAny(req, false);

				//if (cfig.authorized)
				//	addRRAd(req);

				return 1;

			case DNTYPE_P_ZONE:
				addRRNone(req);
				if (cfig.authorized)
				{
					addRRSOA(req);
					addRRNS(req);
					req->dnsp->header.ancount = htons(2);
				}

				//if (cfig.authorized)
				//	addRRAd(req);

				return 1;

			default:
				addRRNone(req);
				addRRAny(req, false);
				return 1;
			}
		}
		else
		{
			switch (req->dnType)
			{
			case DNTYPE_A_ZONE:
				addRRNone(req);
				if (cfig.authorized)
				{
					addRRSOA(req);
					addRRNS(req);
					req->dnsp->header.ancount = htons(2);
				}

				for (MYBYTE m = 0; m < cfig.mxCount[currentInd]; m++)
					addRRMXOne(req, m);

				//if (cfig.authorized)
				//	addRRAd(req);

				return 1;

			case DNTYPE_P_ZONE:
				addRRNone(req);
				if (cfig.authorized)
				{
					addRRSOA(req);
					addRRNS(req);
					req->dnsp->header.ancount = htons(2);
				}

				//if (cfig.authorized)
				//	addRRAd(req);

				return 1;

			case DNTYPE_A_LOCAL:
			case DNTYPE_P_LOCAL:
			case DNTYPE_A_EXT:
			case DNTYPE_P_EXT:
				return 0;

			default:
				addRRNone(req);
				return 1;
			}
		}

		break;

	default:
		if (cfig.authorized && req->dnType != DNTYPE_A_EXT && req->dnType != DNTYPE_P_EXT)
		{
			if (verbatim || cfig.dnsLogLevel)
			{
				sprintf(logBuff, "%s, DNS Query Type not supported", strquery(req));
				logDNSMess(req, logBuff, 1);
			}
			addRRNone(req);
			req->dnsp->header.rcode = RCODE_NOTIMPL;
			addNS(req);
			return 1;
		}
		return 0;
	}

	for (int m = 0; m < 3; ++m)
	{
		//printf("%s has %u Entries\n", req->mapname, dnsCache[currentInd].count(req->mapname));
		req->iterBegin = dnsCache[currentInd].find(req->mapname);
		//if (req->iterBegin != dnsCache[currentInd].end() && req->iterBegin->second->expiry >= t)
		if (req->iterBegin != dnsCache[currentInd].end())
		{
			data7 *cache = req->iterBegin->second;
			req->respType = cache->dataType;
			//printf("mapname=%s, datatype=%i exp=%u\n",cache->mapname, req->respType, cache->expiry);
			//printf("%s cache=%u mapname=%u hostname=%u\n", cache->mapname, cache, cache->mapname, cache->hostname);

			switch (req->respType)
			{
			case LOCAL_A:
			case STATIC_A_AUTH:
				addRRNone(req);
				addRRA(req);
				addNS(req);
				return 1;

			case LOCAL_PTR_AUTH:
			case STATIC_PTR_AUTH:
			case SERVER_PTR_AUTH:
				addRRNone(req);
				addRRPtr(req);
				addNS(req);
				return 1;

			case LOCALHOST_A:
				addRRNone(req);
				addRRLocalhostA(req, cache);
				addNS(req);
				return 1;

			case LOCALHOST_PTR:
				addRRNone(req);
				addRRLocalhostPtr(req, cache);
				addNS(req);
				return 1;

			case STATIC_A_NAUTH:
				addRRNone(req);
				addRRA(req);
				return 1;

			case LOCAL_PTR_NAUTH:
			case SERVER_PTR_NAUTH:
			case STATIC_PTR_NAUTH:
				addRRNone(req);
				addRRPtr(req);
				return 1;

			case SERVER_A_AUTH:
				addRRNone(req);
				addRRServerA(req);
				addNS(req);
				return 1;

			case CACHED:
				addRRNone(req);
				addRRCache(req, cache);
				return 1;

			case LOCAL_CNAME:
			case EXT_CNAME:

				//printf("mapname=%s, hostname=%s datatype=%i exp=%u\n",cache->mapname, cache->hostname, req->respType,cache->expiry);

				if (!cache->hostname[0])
					strcpy(req->cname, cfig.zone);
				else if (strchr(cache->hostname, '.'))
					strcpy(req->cname, cache->hostname);
				else
					sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);

				strcpy(req->mapname, cache->hostname);
				myLower(req->mapname);
				continue;

			default:
				break;
			}
		}

		break;
	}

	if (req->qtype == DNS_TYPE_A && cfig.wildHosts[0].wildcard[0])
	{
		for (MYBYTE i = 0; i < MAX_WILD_HOSTS && cfig.wildHosts[i].wildcard[0]; i++)
		{
			if (wildcmp(req->mapname, cfig.wildHosts[i].wildcard))
			{
				addRRNone(req);

				if (cfig.wildHosts[i].ip)
					addRRWildA(req, cfig.wildHosts[i].ip);

				return 1;
			}
		}
	}

	if (req->respType == LOCAL_CNAME)
	{
		addRRNone(req);
		addRRA(req);
		addNS(req);
		return 1;
	}
	else if (req->respType == NONE && (req->dnType == DNTYPE_A_BARE || req->dnType == DNTYPE_A_ZONE || req->dnType == DNTYPE_P_ZONE))
	{
		addRRNone(req);
		addNS(req);
		return 1;
	}
	else if (req->respType == EXT_CNAME)
	{
		//printf("mapname=%s, hostname=%s datatype=%i exp=%u\n",cache->mapname, cache->hostname, req->respType,cache->expiry);
		req->dnType = makeLocal(req->mapname);
		req->dp = &req->dnsp->data;
		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->bytes = req->dp - req->raw;
	}

	return 0;
}

int fdnmess(data5 *req)
{
	char logBuff[256];
	//debug("fdnmess");
	//printf("before dnType=%d %d\n", req->dnType, DNTYPE_A_SUBZONE);
	req->qLen = static_cast<MYWORD>(strlen(req->cname));
	MYBYTE zoneDNS;
	int nRet = -1;

	char mapname[8];
	sprintf(mapname, "%u", req->dnsp->header.xid);
	data7 *queue = findEntry(currentInd, mapname, QUEUE);

	for (zoneDNS = 0; zoneDNS < MAX_COND_FORW && cfig.dnsRoutes[zoneDNS].zLen; zoneDNS++)
	{
		if (req->qLen == cfig.dnsRoutes[zoneDNS].zLen && !strcasecmp(req->cname, cfig.dnsRoutes[zoneDNS].zone))
			req->dnType = DNTYPE_CHILDZONE;
		else if (req->qLen > cfig.dnsRoutes[zoneDNS].zLen)
		{
			char *dp = req->cname + (req->qLen - cfig.dnsRoutes[zoneDNS].zLen - 1);

			if (*dp == '.' && !strcasecmp(dp + 1, cfig.dnsRoutes[zoneDNS].zone))
				req->dnType = DNTYPE_CHILDZONE;
		}

		if (req->dnType == DNTYPE_CHILDZONE)
		{
			if (queue && cfig.dnsRoutes[zoneDNS].dns[1])
				cfig.dnsRoutes[zoneDNS].currentDNS = 1 - cfig.dnsRoutes[zoneDNS].currentDNS;

			if (req->remote.sin_addr.s_addr != cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS])
			{
				req->addr.sin_family = AF_INET;
				req->addr.sin_addr.s_addr = cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS];
				req->addr.sin_port = htons(IPPORT_DNS);

				nRet = sendto(network.forwConn.sock,
							  req->raw,
							  req->bytes,
							  0,
							  (sockaddr*)&req->addr,
							  sizeof(req->addr));

				if (nRet <= 0)
				{
					if (verbatim || cfig.dnsLogLevel)
					{
						sprintf(logBuff, "Error Forwarding UDP DNS Message to Conditional Forwarder %s", IP2String(req->addr.sin_addr.s_addr));
						logDNSMess(req, logBuff, 1);
						addRRNone(req);
						req->dnsp->header.rcode = RCODE_SERVERFAIL;
					}

					if (cfig.dnsRoutes[zoneDNS].dns[1])
						cfig.dnsRoutes[zoneDNS].currentDNS = 1 - cfig.dnsRoutes[zoneDNS].currentDNS;

					return 0;
				}
				else
				{
					if (verbatim || cfig.dnsLogLevel >= 2)
					{
						sprintf(logBuff, "%s forwarded to Conditional Forwarder %s", strquery(req),
							IP2String(cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS]));
						logDNSMess(req, logBuff, 2);
					}
				}
			}

			break;
		}
	}

	if (req->dnType != DNTYPE_CHILDZONE)
	{
		char *dp = 0;

		if (req->dnType == DNTYPE_A_EXT && req->qLen > cfig.zLen)
		{
			dp = req->cname + (req->qLen - cfig.zLen);

			if (!strcasecmp(dp, cfig.zone))
				req->dnType = DNTYPE_A_SUBZONE;
		}

		//printf("after dnType=%d %d\n", req->dnType, DNTYPE_A_SUBZONE);

		if (cfig.authorized && (req->dnType == DNTYPE_A_LOCAL || req->dnType == DNTYPE_A_SUBZONE || req->dnType == DNTYPE_P_LOCAL))
		{
			if (verbatim || cfig.dnsLogLevel >= 2)
			{
				sprintf(logBuff, "%s not found", strquery(req));
				logDNSMess(req, logBuff, 2);
			}

			switch (req->qtype)
			{
			case DNS_TYPE_NS:
				addRRNone(req);
				addNS(req);
				req->dnsp->header.rcode = RCODE_NOERROR;
				return 0;

			case DNS_TYPE_SOA:
				addRRNone(req);
				addRRSOAuth(req);
				req->dnsp->header.rcode = RCODE_NOERROR;
				return 0;

			default:
				addRRNone(req);
				addNS(req);
				req->dnsp->header.rcode = RCODE_NAMEERROR;
				return 0;
			}
		}

		if (!req->dnsp->header.rd)
		{
			addRRNone(req);
			req->dnsp->header.rcode = RCODE_NAMEERROR;
			if (verbatim || cfig.dnsLogLevel)
			{
				sprintf(logBuff, "%s is not found (recursion not desired)", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			return 0;
		}

		if (!network.dns[0])
		{
			addRRNone(req);
			req->dnsp->header.rcode = RCODE_NAMEERROR;
			req->dnsp->header.ra = 0;
			if (verbatim || cfig.dnsLogLevel)
			{
				sprintf(logBuff, "%s not found (recursion not available)", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			return 0;
		}

		if (queue && network.dns[1] && queue->dnsIndex < MAX_SERVERS && network.currentDNS == queue->dnsIndex)
		{
			++network.currentDNS;

			if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
				network.currentDNS = 0;
		}

		if (req->remote.sin_addr.s_addr != network.dns[network.currentDNS])
		{
			req->addr.sin_family = AF_INET;
			req->addr.sin_addr.s_addr = network.dns[network.currentDNS];
			req->addr.sin_port = htons(IPPORT_DNS);

			nRet = sendto(network.forwConn.sock,
						  req->raw,
						  req->bytes,
						  0,
						  (sockaddr*)&req->addr,
						  sizeof(req->addr));

			if (nRet <= 0)
			{
				if (verbatim || cfig.dnsLogLevel)
				{
					sprintf(logBuff, "Error forwarding UDP DNS Message to Forwarding Server %s",
						IP2String(network.dns[network.currentDNS]));
					logDNSMess(req, logBuff, 1);
					addRRNone(req);
					req->dnsp->header.rcode = RCODE_SERVERFAIL;
				}

				if (network.dns[1])
				{
					++network.currentDNS;

					if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
						network.currentDNS = 0;
				}

				return 0;
			}
			else
			{
				if (verbatim || cfig.dnsLogLevel >= 2)
				{
					sprintf(logBuff, "%s forwarded to Forwarding Server %s",
						strquery(req), IP2String(network.dns[network.currentDNS]));
					logDNSMess(req, logBuff, 2);
				}
			}
		}
	}

	//printf("LocalCode=%u query=%s cname=%s mapname=%s\n", req->dnType, req->query, req->cname, req->mapname);

	if (!queue || strcasecmp(queue->query, req->query))
	{
		data71 lump;
		memset(&lump, 0, sizeof lump);
		lump.dataType = QUEUE;
		lump.mapname = mapname;
		lump.addr = &req->remote;
		lump.query = req->query;
		queue = createCache(&lump);

		if (queue)
		{
			queue->expiry = 2 + t;
			addEntry(currentInd, queue);
		}
	}
	else
	{
		queue->expiry = 2 + t;
		memcpy(queue->addr, &req->remote, sizeof(req->remote));
	}

	queue->sockInd = req->sockInd;

	if (req->dnType == DNTYPE_CHILDZONE)
		queue->dnsIndex = 128 + (2 * zoneDNS) + cfig.dnsRoutes[zoneDNS].currentDNS;
	else
		queue->dnsIndex = network.currentDNS;

	//printf("%u %u\n", zoneDNS, queue->dnsIndex);

	return (nRet);
}

bool frdnmess(data5 *req)
{
	char tempbuff[512];
	//debug("frdnmess");
	memset(req, 0, sizeof(data5));
	req->sockLen = sizeof(req->remote);

	req->bytes = recvfrom(network.forwConn.sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	if (req->bytes <= 0)
		return false;

	req->dnsp = (dnsPacket*)req->raw;

	char mapname[8];
	MYWORD type = 0;
	sprintf(mapname, "%u", req->dnsp->header.xid);
	data7 *queue = findEntry(currentInd, mapname);

	if (queue && queue->expiry)
	{
		queue->expiry = 0;

		if (queue->dnsIndex < MAX_SERVERS)
		{
			if (req->remote.sin_addr.s_addr != network.dns[network.currentDNS])
			{
				for (MYBYTE i = 0; i < MAX_SERVERS && network.dns[i]; i++)
				{
					if (network.dns[i] == req->remote.sin_addr.s_addr)
					{
						network.currentDNS = i;
						break;
					}
				}
			}
		}
		else if (queue->dnsIndex >= 128 && queue->dnsIndex < 192)
		{
			data6 *dnsRoute = &cfig.dnsRoutes[(queue->dnsIndex - 128) / 2];

			if (dnsRoute->dns[0] == req->remote.sin_addr.s_addr)
				dnsRoute->currentDNS = 0;
			else if (dnsRoute->dns[1] == req->remote.sin_addr.s_addr)
				dnsRoute->currentDNS = 1;
		}

		if (queue->dataType == QUEUE)
		{
			memcpy(&req->remote, queue->addr, sizeof(req->remote));
			strcpy(req->query, queue->query);
			req->sockInd = queue->sockInd;
			req->dnsIndex = queue->dnsIndex;

			req->dp = &req->dnsp->data;

			for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
			{
				req->dp += fQu(req->cname, req->dnsp, req->dp);
				type = fUShort(req->dp);
				req->dp += 4; //type and class
			}

			if ((type == DNS_TYPE_A || type == DNS_TYPE_PTR) && !req->dnsp->header.rcode && !req->dnsp->header.tc && req->dnsp->header.ancount)
			{
				time_t expiry = 0;
				bool resultFound = false;

				for (int i = 1; i <= ntohs(req->dnsp->header.ancount); i++)
				{
					req->dp += fQu(tempbuff, req->dnsp, req->dp);
					type = fUShort(req->dp);

					//printf("%s %u=%u\n", tempbuff, type, DNS_TYPE_A);

					if (type == DNS_TYPE_A)
					{
						resultFound = true;
						strcpy(req->mapname, req->cname);
						myLower(req->mapname);
						makeLocal(req->mapname);
					}
					else if (type == DNS_TYPE_PTR)
					{
						strcpy(req->mapname, req->cname);
						myLower(req->mapname);
						char *dp = strstr(req->mapname, arpa);

						if (dp && !strcasecmp(dp, arpa))
						{
							*dp = 0;
							resultFound = true;
						}
					}

					req->dp += 4; //type and class

					if (!expiry || fULong(req->dp) < (MYDWORD)expiry)
						expiry = fULong(req->dp);

					req->dp += 4; //ttl
					int zLen = fUShort(req->dp);
					req->dp += 2; //datalength
					req->dp += zLen;
				}

				if (resultFound)
				{
					int cacheSize = req->dp - req->raw;

					if (cfig.minCache && expiry < cfig.minCache)
						expiry = cfig.minCache;

					if (cfig.maxCache && expiry > cfig.maxCache)
						expiry = cfig.maxCache;

					if (expiry < INT_MAX - t)
						expiry += t;
					else
						expiry = INT_MAX;

					data71 lump;
					memset(&lump, 0, sizeof lump);
					lump.dataType = CACHED;
					lump.mapname = req->mapname;
					lump.bytes = cacheSize;
					lump.response = (MYBYTE*)req->dnsp;
					if (data7* cache = createCache(&lump))
					{
						cache->expiry = expiry;
						addEntry(currentInd, cache);
						addRRExt(req);
						return true;
					}
				}
			}

			addRRExt(req);
			return true;
		}
	}
	return false;
}

void add2Cache(MYBYTE ind, char *hostname, MYDWORD ip, time_t expiry, MYBYTE aType, MYBYTE pType)
{
	char tempbuff[512];
	//printf("Adding %s=%s \n", hostname, IP2String(ip));

	if (!hostname || !ip)
		return;

	if (pType)
	{
		data7 *cache = NULL;
		IP2String(htonl(ip), tempbuff);

		hostMap::iterator p = dnsCache[ind].find(tempbuff);
		while (p != dnsCache[ind].end() &&
			!strcasecmp(p->second->mapname, tempbuff))
		{
			if (!strcasecmp(p->second->hostname, hostname))
			{
				cache = p->second;
				break;
			}
			++p;
		}

		if (!cache)
		{
			data71 lump;
			memset(&lump, 0, sizeof lump);
			lump.dataType = pType;
			lump.mapname = tempbuff;
			lump.hostname = hostname;
			cache = createCache(&lump);
/*
			cache = (data7*)calloc(1, sizeof(data7));

			if (cache)
			{
				cache->mapname = strdup(tempbuff);
				cache->hostname = strdup(hostname);

				if (!cache->mapname || !cache->hostname)
				{
					if (cache->mapname)
						free(cache->mapname);

					if (cache->hostname)
						free(cache->hostname);

					free(cache);

					sprintf(logBuff, "Memory Allocation Error");
					logDNSMess(logBuff, 1);
					return;
				}

				cache->dataType = pType;
				cache->expiry = expiry;
				addEntry(ind, cache);
*/
			if (cache)
			{
				cache->expiry = expiry;
				addEntry(ind, cache);

				if (cfig.replication != 2 && pType == LOCAL_PTR_AUTH)
					cfig.serial2 = t;
			}
		}
		else if (cache->expiry < expiry)
		{
			cache->dataType = pType;
			cache->expiry = expiry;
		}
		//printf("Added %s=%s\n", IP2String(ip), hostname);
	}

	if (aType)
	{
		data7 *cache = NULL;
		strcpy(tempbuff, hostname);
		makeLocal(tempbuff);
		myLower(tempbuff);

		hostMap::iterator p = dnsCache[ind].find(tempbuff);
		while (p != dnsCache[ind].end() &&
			!strcasecmp(p->second->mapname, tempbuff))
		{
			if (p->second->ip == ip)
			{
				cache = p->second;
				break;
			}
			++p;
		}

		if (!cache)
		{
			data71 lump;
			memset(&lump, 0, sizeof lump);
			lump.dataType = aType;
			lump.mapname = tempbuff;
			cache = createCache(&lump);
/*
			cache = (data7*)calloc(1, sizeof(data7));

			if (cache)
			{
				cache->mapname = strdup(tempbuff);

				if (!cache->mapname)
				{
					sprintf(logBuff, "Memory Allocation Error");
					logDNSMess(logBuff, 1);
					free(cache);
					return;
				}

				cache->ip = ip;
				cache->dataType = aType;
				cache->expiry = expiry;
				addEntry(ind, cache);
			}
*/
			if (cache)
			{
				cache->ip = ip;
				cache->expiry = expiry;
				addEntry(ind, cache);

				if (cfig.replication != 2 && aType == LOCAL_A)
					cfig.serial1 = t;
			}
		}
		else if (cache->expiry < expiry)
		{
			cache->dataType = aType;
			cache->expiry = expiry;
		}
		//printf("Added %s=%s\n", hostname, IP2String(ip));
	}
}

void addHostNotFound(MYBYTE ind, char *hostname)
{
	data71 lump;
	memset(&lump, 0, sizeof lump);
	lump.dataType = STATIC_A_NAUTH;
	lump.mapname = hostname;
	data7 *cache = createCache(&lump);
/*
	data7 *cache = (data7*)calloc(1, sizeof(data7));

	if (cache)
	{
		cache->mapname = myLower(strdup(hostname));

		if (!cache->mapname)
		{
			sprintf(logBuff, "Memory Allocation Error");
			free(cache);
			logDNSMess(logBuff, 1);
			return;
		}

		cache->ip = 0;
		cache->dataType = STATIC_A_NAUTH;
		cache->expiry = INT_MAX;
		addEntry(ind, cache);
	}
*/
	if (cache)
	{
		cache->ip = 0;
		cache->dataType = STATIC_A_NAUTH;
		cache->expiry = INT_MAX;
		addEntry(ind, cache);
	}
}

char* getResult(data5 *req, char *tempbuff)
{
	char buff[256];

	//try
	{
		tempbuff[0] = 0;
		char *raw = &req->dnsp->data;

		for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
		{
			raw += fQu(buff, req->dnsp, raw);
			raw += 4;
		}

		for (int i = 1; i <= ntohs(req->dnsp->header.ancount); i++)
		{
			raw += fQu(buff, req->dnsp, raw);
			int type = fUShort(raw);
			raw += 2; //type
			raw += 2; //class
			raw += 4; //ttl
			int zLen = fUShort(raw);
			raw += 2; //datalength

			if (type == DNS_TYPE_A)
				return IP2String(fIP(raw), tempbuff);
			else if (type == DNS_TYPE_AAAA)
				return IP62String((MYBYTE*)raw, tempbuff);
			else if (type == DNS_TYPE_PTR)
			{
				fQu(tempbuff, req->dnsp, raw);
				return tempbuff;
			}
			else if (type == DNS_TYPE_MX)
				fQu(tempbuff, req->dnsp, (raw + 2));
			else if (type == DNS_TYPE_CNAME)
				fQu(tempbuff, req->dnsp, raw);
			else if (type == DNS_TYPE_NS)
				fQu(tempbuff, req->dnsp, raw);

			raw += zLen;
		}

		if (tempbuff[0])
			return tempbuff;
		else
			return NULL;
	}
	/*catch(...)
	{
		return NULL;
	}*/
}


bool checkRange(data17 *rangeData, char rangeInd)
{
	//debug("checkRange");

	if (!cfig.hasFilter)
		return true;

	MYBYTE rangeSetInd = cfig.dhcpRanges[rangeInd].rangeSetInd;
	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];
	//printf("checkRange entering, rangeInd=%i rangeSetInd=%i\n", rangeInd, rangeSetInd);
	//printf("checkRange entered, macFound=%i vendFound=%i userFound=%i\n", macFound, vendFound, userFound);

	if((!rangeData->macFound && !rangeSet->macSize[0]) || (rangeData->macFound && rangeData->macArray[rangeSetInd]))
		if((!rangeData->vendFound && !rangeSet->vendClassSize[0]) || (rangeData->vendFound && rangeData->vendArray[rangeSetInd]))
			if((!rangeData->userFound && !rangeSet->userClassSize[0]) || (rangeData->userFound && rangeData->userArray[rangeSetInd]))
				if((!rangeData->subnetFound && !rangeSet->subnetIP[0]) || (rangeData->subnetFound && rangeData->subnetArray[rangeSetInd]))
					return true;

	//printf("checkRange, returning false rangeInd=%i rangeSetInd=%i\n", rangeInd, rangeSetInd);
	return false;
}

MYDWORD resad(data9 *req)
{
	char logBuff[256];
	//debug("resad");

	MYDWORD minRange = 0;
	MYDWORD maxRange = 0;

	if (req->dhcpp.header.bp_giaddr)
	{
		lockIP(req->dhcpp.header.bp_giaddr);
		lockIP(req->remote.sin_addr.s_addr);
	}

	req->dhcpEntry = findDHCPEntry(req->chaddr);

	if (req->dhcpEntry && req->dhcpEntry->fixed)
	{
		if (req->dhcpEntry->ip)
		{
			setTempLease(req->dhcpEntry);
			return req->dhcpEntry->ip;
		}
		else
		{
			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "Static DHCP Host %s (%s) has No IP, DHCPDISCOVER ignored", req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
			return 0;
		}
	}

	MYDWORD iipNew = 0;
	MYDWORD iipExp = 0;
	MYDWORD rangeStart = 0;
	MYDWORD rangeEnd = 0;
	char rangeInd = -1;
	bool rangeFound = false;
	data17 rangeData;
	memset(&rangeData, 0, sizeof rangeData);

	if (cfig.hasFilter)
	{
		for (MYBYTE rangeSetInd = 0; rangeSetInd < MAX_RANGE_SETS && cfig.rangeSet[rangeSetInd].active; rangeSetInd++)
		{
			data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && rangeSet->macSize[i]; i++)
			{
				//printf("%s\n", hex2String(tempbuff, rangeSet->macStart[i], rangeSet->macSize[i]));
				//printf("%s\n", hex2String(tempbuff, rangeSet->macEnd[i], rangeSet->macSize[i]));

				if(memcmp(req->dhcpp.header.bp_chaddr, rangeSet->macStart[i], rangeSet->macSize[i]) >= 0 && memcmp(req->dhcpp.header.bp_chaddr, rangeSet->macEnd[i], rangeSet->macSize[i]) <= 0)
				{
					rangeData.macArray[rangeSetInd] = 1;
					rangeData.macFound = true;
					//printf("mac Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->vendClass.size && rangeSet->vendClassSize[i]; i++)
			{
				if(rangeSet->vendClassSize[i] == req->vendClass.size && !memcmp(req->vendClass.value, rangeSet->vendClass[i], rangeSet->vendClassSize[i]))
				{
					rangeData.vendArray[rangeSetInd] = 1;
					rangeData.vendFound = true;
					//printf("vend Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->userClass.size && rangeSet->userClassSize[i]; i++)
			{
				if(rangeSet->userClassSize[i] == req->userClass.size && !memcmp(req->userClass.value, rangeSet->userClass[i], rangeSet->userClassSize[i]))
				{
					rangeData.userArray[rangeSetInd] = 1;
					rangeData.userFound = true;
					//printf("user Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->subnetIP && rangeSet->subnetIP[i]; i++)
			{
				if(req->subnetIP == rangeSet->subnetIP[i])
				{
					rangeData.subnetArray[rangeSetInd] = 1;
					rangeData.subnetFound = true;
					//printf("subnet Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}
		}

	}

//	printArray("macArray", (char*)cfig.macArray);
//	printArray("vendArray", (char*)cfig.vendArray);
//	printArray("userArray", (char*)cfig.userArray);

	if (req->dhcpEntry)
	{
		req->dhcpEntry->rangeInd = getRangeInd(req->dhcpEntry->ip);

		if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (cfig.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] == req->dhcpEntry && checkRange(&rangeData, req->dhcpEntry->rangeInd))
			{
				MYBYTE rangeSetInd = cfig.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;

				if (!cfig.rangeSet[rangeSetInd].subnetIP[0])
				{
					MYDWORD mask = cfig.dhcpRanges[req->dhcpEntry->rangeInd].mask;
					calcRangeLimits(req->subnetIP, mask, &minRange, &maxRange);

					if (htonl(req->dhcpEntry->ip) >= minRange && htonl(req->dhcpEntry->ip) <= maxRange)
					{
						setTempLease(req->dhcpEntry);
						return req->dhcpEntry->ip;
					}
				}
				else
				{
					setTempLease(req->dhcpEntry);
					return req->dhcpEntry->ip;
				}
			}
		}
	}

	if (dnsService && req->hostname[0])
	{
		char hostname[128];
		strcpy(hostname, req->hostname);
		myLower(hostname);
		hostMap::iterator it = dnsCache[currentInd].find(hostname);

		for (; it != dnsCache[currentInd].end(); it++)
		{
			data7 *cache = it->second;

			//printf("%u\n", cache->mapname);

			if (strcasecmp(cache->mapname, hostname))
				break;

			if (cache && cache->ip)
			{
				char k = getRangeInd(cache->ip);

				if (k >= 0)
				{
					if (checkRange(&rangeData, k))
					{
						data13 *range = &cfig.dhcpRanges[k];
						int ind = getIndex(k, cache->ip);

						if (ind >= 0 && range->expiry[ind] <= t)
						{
							MYDWORD iip = htonl(cache->ip);

							if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
							{
								calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);

								if (iip >= minRange && iip <= maxRange)
								{
									iipNew = iip;
									rangeInd = k;
									break;
								}
							}
							else
							{
								iipNew = iip;
								rangeInd = k;
								break;
							}
						}
					}
				}
			}
		}
	}

	if (!iipNew && req->reqIP)
	{
		char k = getRangeInd(req->reqIP);

		if (k >= 0)
		{
			if (checkRange(&rangeData, k))
			{
				data13 *range = &cfig.dhcpRanges[k];
				int ind = getIndex(k, req->reqIP);

				if (range->expiry[ind] <= t)
				{
					if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
					{
						calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);
						MYDWORD iip = htonl(req->reqIP);

						if (iip >= minRange && iip <= maxRange)
						{
							iipNew = iip;
							rangeInd = k;
						}
					}
					else
					{
						MYDWORD iip = htonl(req->reqIP);
						iipNew = iip;
						rangeInd = k;
					}
				}
			}
		}
	}


	for (char k = 0; !iipNew && k < cfig.rangeCount; k++)
	{
		if (checkRange(&rangeData, k))
		{
			data13 *range = &cfig.dhcpRanges[k];
			rangeStart = range->rangeStart;
			rangeEnd = range->rangeEnd;

			if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
			{
				calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);

				if (rangeStart < minRange)
					rangeStart = minRange;

				if (rangeEnd > maxRange)
					rangeEnd = maxRange;
			}

			if (rangeStart <= rangeEnd)
			{
				rangeFound = true;

				if (cfig.replication == 2)
				{
					for (MYDWORD m = rangeEnd; m >= rangeStart; m--)
					{
						int ind = m - range->rangeStart;

						if (!range->expiry[ind])
						{
							iipNew = m;
							rangeInd = k;
							break;
						}
						else if (!iipExp && range->expiry[ind] < t)
						{
							iipExp = m;
							rangeInd = k;
						}
					}
				}
				else
				{
					for (MYDWORD m = rangeStart; m <= rangeEnd; m++)
					{
						int ind = m - range->rangeStart;

						if (!range->expiry[ind])
						{
							iipNew = m;
							rangeInd = k;
							break;
						}
						else if (!iipExp && range->expiry[ind] < t)
						{
							iipExp = m;
							rangeInd = k;
						}
					}
				}
			}
		}
	}


	if (!iipNew && iipExp)
			iipNew = iipExp;

	if (iipNew)
	{
		if (!req->dhcpEntry)
		{
			data71 lump;
			memset(&lump, 0, sizeof lump);
			lump.dataType = DHCP_ENTRY;
			lump.mapname = req->chaddr;
			lump.hostname = req->hostname;
			req->dhcpEntry = createCache(&lump);

			if (!req->dhcpEntry)
				return 0;

/*
			req->dhcpEntry = (data7*)calloc(1, sizeof(data7));

			if (!req->dhcpEntry)
			{
				sprintf(logBuff, "Memory Allocation Error");
				logDHCPMess(logBuff, 1);
				return 0;
			}

			req->dhcpEntry->mapname = strdup(req->chaddr);

			if (!req->dhcpEntry->mapname)
			{
				sprintf(logBuff, "Memory Allocation Error");
				logDHCPMess(logBuff, 1);
				return 0;
			}
*/

			dhcpCache[req->dhcpEntry->mapname] = req->dhcpEntry;
		}

		req->dhcpEntry->ip = htonl(iipNew);
		req->dhcpEntry->rangeInd = rangeInd;
		setTempLease(req->dhcpEntry);
		return req->dhcpEntry->ip;
	}

	if (verbatim || cfig.dhcpLogLevel)
	{
		if (rangeFound)
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(network.dhcpConn[req->sockInd].server));
		}
		else
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(network.dhcpConn[req->sockInd].server));
		}
		logDHCPMess(logBuff, 1);
	}
	return 0;
}

MYDWORD chad(data9 *req)
{
	req->dhcpEntry = findDHCPEntry(req->chaddr);
	//printf("dhcpEntry=%d\n", req->dhcpEntry);

	if (req->dhcpEntry)
		return req->dhcpEntry->ip;
	else
		return 0;
}

MYDWORD sdmess(data9 *req)
{
	char logBuff[256];
	//sprintf(logBuff, "sdmess, Request Type = %u",req->req_type);
	//debug(logBuff);

	if (req->req_type == DHCP_MESS_NONE)
	{
		req->dhcpp.header.bp_yiaddr = chad(req);

		if (!req->dhcpp.header.bp_yiaddr)
		{
			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "No Static Entry found for BOOTPREQUEST from Host %s", req->chaddr);
				logDHCPMess(logBuff, 1);
			}

			return 0;
		}
	}
	else if (req->req_type == DHCP_MESS_DECLINE)
	{
		if (req->dhcpp.header.bp_ciaddr && chad(req) == req->dhcpp.header.bp_ciaddr)
		{
			lockIP(req->dhcpp.header.bp_ciaddr);

			req->dhcpEntry->ip = 0;
			req->dhcpEntry->expiry = INT_MAX;
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s declined by Host %s (%s), locked", IP2String(req->dhcpp.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_RELEASE)
	{
		if (req->dhcpp.header.bp_ciaddr && chad(req) == req->dhcpp.header.bp_ciaddr)
		{
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;
			setLeaseExpiry(req->dhcpEntry, 0);

			updateStateFile(req->dhcpEntry);

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s released by Host %s (%s)", IP2String(req->dhcpp.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_INFORM)
	{
		//printf("repl0=%s\n", IP2String(cfig.zoneServers[0]));
		//printf("repl1=%s\n", IP2String(cfig.zoneServers[1]));
		//printf("IP=%s bytes=%u replication=%i\n", IP2String(req->remote.sin_addr.s_addr), req->bytes, cfig.replication);

		if ((cfig.replication == 1 && req->remote.sin_addr.s_addr == cfig.zoneServers[1]) || (cfig.replication == 2 && req->remote.sin_addr.s_addr == cfig.zoneServers[0]))
			recvRepl(req);

		return 0;
	}
	else if (req->req_type == DHCP_MESS_DISCOVER)
	{
		if (!strcasecmp(req->hostname, cfig.servername))
			return 0;

		req->dhcpp.header.bp_yiaddr = resad(req);

		if (!req->dhcpp.header.bp_yiaddr)
			return 0;

		req->resp_type = DHCP_MESS_OFFER;
	}
	else if (req->req_type == DHCP_MESS_REQUEST)
	{
		//printf("%s\n", IP2String(req->dhcpp.header.bp_ciaddr));
		if (req->server)
		{
			if (req->server != network.dhcpConn[req->sockInd].server)
				return 0;

			if (req->reqIP && req->reqIP == chad(req) && req->dhcpEntry->expiry > t)
			{
				req->resp_type = DHCP_MESS_ACK;
				req->dhcpp.header.bp_yiaddr = req->reqIP;
			}
			else if (req->dhcpp.header.bp_ciaddr && req->dhcpp.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
			{
				req->resp_type = DHCP_MESS_ACK;
				req->dhcpp.header.bp_yiaddr = req->dhcpp.header.bp_ciaddr;
			}
			else
			{
				req->resp_type = DHCP_MESS_NAK;
				req->dhcpp.header.bp_yiaddr = 0;

				if (verbatim || cfig.dhcpLogLevel)
				{
					sprintf(logBuff,
						"DHCPREQUEST from Host %s (%s) without Discover, NAKed",
						req->chaddr, hostname2utf8(req));
					logDHCPMess(logBuff, 1);
				}
			}
		}
		else if (req->dhcpp.header.bp_ciaddr && req->dhcpp.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->dhcpp.header.bp_yiaddr = req->dhcpp.header.bp_ciaddr;
		}
		else if (req->reqIP && req->reqIP == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->dhcpp.header.bp_yiaddr = req->reqIP;
		}
		else
		{
			req->resp_type = DHCP_MESS_NAK;
			req->dhcpp.header.bp_yiaddr = 0;

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff,
					"DHCPREQUEST from Host %s (%s) without Discover, NAKed",
					req->chaddr, hostname2utf8(req));
				logDHCPMess(logBuff, 1);
			}
		}
	}
	else
		return 0;

	addOptions(req);
	int packSize = req->vp - (MYBYTE*)&req->dhcpp + 1;

	if (req->req_type == DHCP_MESS_NONE)
		packSize = req->messsize;

	if ((req->dhcpp.header.bp_giaddr || !req->remote.sin_addr.s_addr) && req->dhcpEntry && req->dhcpEntry->rangeInd >= 0)
	{
		MYBYTE rangeSetInd = cfig.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;
		req->targetIP = cfig.rangeSet[rangeSetInd].targetIP;
	}

	if (req->targetIP)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->targetIP;
	}
	else if (req->dhcpp.header.bp_giaddr)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->dhcpp.header.bp_giaddr;
	}
	else if (req->dhcpp.header.bp_broadcast || !req->remote.sin_addr.s_addr || req->reqIP)
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
		req->remote.sin_addr.s_addr = INADDR_BROADCAST;
	}
	else
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
	}

	req->dhcpp.header.bp_op = BOOTP_REPLY;

	if (req->req_type == DHCP_MESS_DISCOVER && !req->dhcpp.header.bp_giaddr)
	{
		req->bytes = sendto(network.dhcpConn[req->sockInd].sock,
							req->raw,
							packSize,
							MSG_DONTROUTE,
							(sockaddr*)&req->remote,
							sizeof(req->remote));
	}
	else
	{
		req->bytes = sendto(network.dhcpConn[req->sockInd].sock,
							req->raw,
							packSize,
							0,
							(sockaddr*)&req->remote,
							sizeof(req->remote));
	}

	if (req->bytes <= 0)
		return 0;

	//printf("goes=%s %i\n",IP2String(req->dhcpp.header.bp_yiaddr),req->sockInd);
	return req->dhcpp.header.bp_yiaddr;
}

MYDWORD alad(data9 *req)
{
	char logBuff[256];
	//debug("alad");
	//printf("in alad hostname=%s\n", req->hostname);

	if (req->dhcpEntry && (req->req_type == DHCP_MESS_NONE || req->resp_type == DHCP_MESS_ACK))
	{
		MYDWORD hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		req->dhcpEntry->display = true;
		req->dhcpEntry->local = true;
		setLeaseExpiry(req->dhcpEntry, hangTime);

		updateStateFile(req->dhcpEntry);

		if (dnsService && cfig.replication != 2)
			updateDNS(req);

		if (verbatim || cfig.dhcpLogLevel >= 1)
		{
			if (req->lease && req->reqIP)
			{
				sprintf(logBuff, "Host %s (%s = %s) allotted %s for %u seconds",
					req->chaddr, req->dhcpEntry->hostname, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_yiaddr), req->lease);
			}
			else if (req->req_type)
			{
				sprintf(logBuff, "Host %s (%s = %s) renewed %s for %u seconds",
					req->chaddr, req->dhcpEntry->hostname, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_yiaddr), req->lease);
			}
			else
			{
				sprintf(logBuff, "BOOTP Host %s (%s = %s) allotted %s",
					req->chaddr, req->dhcpEntry->hostname, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_yiaddr));
			}
			logDHCPMess(logBuff, 1);
		}

		if (cfig.replication && cfig.dhcpRepl > t)
			sendRepl(req);

		return req->dhcpEntry->ip;
	}
	else if ((verbatim || cfig.dhcpLogLevel >= 2) && req->resp_type == DHCP_MESS_OFFER)
	{
		sprintf(logBuff, "Host %s (%s) offered %s",
			req->chaddr, hostname2utf8(req),
			IP2String(req->dhcpp.header.bp_yiaddr));
		logDHCPMess(logBuff, 2);
	}
	//printf("%u=out\n", req->resp_type);
	return 0;
}

void updateCachedHostname(data9 *req)
{
	if (!req->dhcpEntry->hostname || strcasecmp(req->dhcpEntry->hostname, req->hostname))
	{
		free(req->dhcpEntry->hostname);
		MYWORD codepage = req->dhcpEntry->codepage;
		if (codepage == 0)
			codepage = cfig.codepage;
		req->dhcpEntry->hostname = AnsiToPunycode(req->hostname, codepage);
	}
}

void addOptions(data9 *req, MYBYTE *opPointer)
{
	if (opPointer)
	{
		MYBYTE requestedOnly = *opPointer++;

		while (*opPointer && *opPointer != DHCP_OPTION_END)
		{
			data3 op;
			op.opt_code = *opPointer++;
			op.size = *opPointer++;

			if (!requestedOnly || req->paramreqlist[*opPointer])
			{
				memcpy(op.value, opPointer, op.size);
				pvdata(req, &op);
			}
			opPointer += op.size;
		}
	}
}

void addOptions(data9 *req)
{
	//debug("addOptions");

	if (req->req_type && req->resp_type)
	{
		data3 op;
		op.opt_code = DHCP_OPTION_MESSAGETYPE;
		op.size = 1;
		op.value[0] = req->resp_type;
		pvdata(req, &op);
	}

	if (req->dhcpEntry && req->resp_type != DHCP_MESS_DECLINE && req->resp_type != DHCP_MESS_NAK)
	{
		strcpy(req->dhcpp.header.bp_sname, cfig.servername);

		if (req->dhcpEntry->fixed)
			addOptions(req, req->dhcpEntry->options);

		if (req->req_type && req->resp_type)
		{
			if (req->dhcpEntry->rangeInd >= 0)
				addOptions(req, cfig.dhcpRanges[req->dhcpEntry->rangeInd].options);

			addOptions(req, cfig.options);

			data3 op;

			op.opt_code = DHCP_OPTION_SERVERID;
			op.size = 4;
			pIP(op.value, network.dhcpConn[req->sockInd].server);
			pvdata(req, &op);

			op.opt_code = DHCP_OPTION_DOMAINNAME;
			op.size = static_cast<MYBYTE>(strlen(cfig.zone) + 1);
			memcpy(op.value, cfig.zone, op.size);
			pvdata(req, &op);

			if (!req->opAdded[DHCP_OPTION_IPADDRLEASE])
			{
				op.opt_code = DHCP_OPTION_IPADDRLEASE;
				op.size = 4;
				pULong(op.value, cfig.lease);
				pvdata(req, &op);
			}

			if (!req->opAdded[DHCP_OPTION_NETMASK])
			{
				op.opt_code = DHCP_OPTION_NETMASK;
				op.size = 4;

				if (req->dhcpEntry->rangeInd >= 0)
					pIP(op.value, cfig.dhcpRanges[req->dhcpEntry->rangeInd].mask);
				else
					pIP(op.value, cfig.mask);

				pvdata(req, &op);
			}

			if (!req->hostname[0])
				genHostName(req->hostname, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);

			updateCachedHostname(req);
/*
			if (!req->opAdded[DHCP_OPTION_ROUTER])
			{
				op.opt_code = DHCP_OPTION_ROUTER;
				op.size = 4;
				pIP(op.value, network.dhcpConn[req->sockInd].server);
				pvdata(req, &op);
			}
*/
			if (!req->opAdded[DHCP_OPTION_DNS])
			{
				if (dnsService)
				{
					op.opt_code = DHCP_OPTION_DNS;

					if (cfig.dhcpRepl > t && cfig.dnsRepl > t)
					{
						if (cfig.replication == 1)
						{
							op.size = 8;
							pIP(op.value, cfig.zoneServers[0]);
							pIP(op.value + 4, cfig.zoneServers[1]);
							pvdata(req, &op);
						}
						else
						{
							op.size = 8;
							pIP(op.value, cfig.zoneServers[1]);
							pIP(op.value + 4, cfig.zoneServers[0]);
							pvdata(req, &op);
						}
					}
					else if (cfig.dnsRepl > t)
					{
						op.size = 8;
						pIP(op.value, cfig.zoneServers[1]);
						pIP(op.value + 4, cfig.zoneServers[0]);
						pvdata(req, &op);
					}
					else
					{
						op.size = 4;
						pIP(op.value, network.dhcpConn[req->sockInd].server);
						pvdata(req, &op);
					}
				}
				else if (cfig.dnsRepl > t && cfig.replication == 2)
				{
					op.opt_code = DHCP_OPTION_DNS;
					op.size = 4;
					pIP(op.value, cfig.zoneServers[0]);
					pvdata(req, &op);
				}
			}
/*
			if (req->clientId.opt_code == DHCP_OPTION_CLIENTID)
				pvdata(req, &req->clientId);
*/
			if (req->subnet.opt_code == DHCP_OPTION_SUBNETSELECTION)
				pvdata(req, &req->subnet);

			if (req->agentOption.opt_code == DHCP_OPTION_RELAYAGENTINFO)
				pvdata(req, &req->agentOption);
		}
	}

	*req->vp = DHCP_OPTION_END;
}

void pvdata(data9 *req, data3 *op)
{
	//debug("pvdata");

	if (!req->opAdded[op->opt_code] && ((req->vp - (MYBYTE*)&req->dhcpp) + op->size < req->messsize))
	{
		if (op->opt_code == DHCP_OPTION_NEXTSERVER)
			req->dhcpp.header.bp_siaddr = fIP(op->value);
		else if (op->opt_code == DHCP_OPTION_BP_FILE)
		{
			if (op->size <= 128)
				memcpy(req->dhcpp.header.bp_file, op->value, op->size);
		}
		else if(op->size)
		{
			if (op->opt_code == DHCP_OPTION_IPADDRLEASE)
			{
				if (!req->lease || req->lease > fULong(op->value))
					req->lease = fULong(op->value);

				if (req->lease >= INT_MAX)
					req->lease = UINT_MAX;

				pULong(op->value, req->lease);
			}
			else if (op->opt_code == DHCP_OPTION_REBINDINGTIME)
				req->rebind = fULong(op->value);
			else if (op->opt_code == DHCP_OPTION_HOSTNAME)
			{
				memcpy(req->hostname, op->value, op->size);
				req->hostname[op->size] = 0;
				req->hostname[63] = 0;

				if (char *ptr = strchr(req->hostname, '.'))
					*ptr = 0;
			}

			MYWORD tsize = op->size + 2;
			memcpy(req->vp, op, tsize);
			(req->vp) += tsize;
		}
		req->opAdded[op->opt_code] = true;
	}
}

void updateDNS(data9 *req)
{
	MYDWORD expiry = INT_MAX;

	if (req->lease < (MYDWORD)(INT_MAX - t))
		expiry = t + req->lease;

	if (req->dhcpEntry && cfig.replication != 2)
	{
		//printf("Update DNS t=%d exp=%d\n", t, req->dhcpEntry->expiry);
		if (isLocal(req->dhcpEntry->ip))
			add2Cache(currentInd, req->hostname, req->dhcpEntry->ip, expiry, LOCAL_A, LOCAL_PTR_AUTH);
		else
			add2Cache(currentInd, req->hostname, req->dhcpEntry->ip, expiry, LOCAL_A, LOCAL_PTR_NAUTH);
	}
}

void setTempLease(data7 *dhcpEntry)
{
	if (dhcpEntry && dhcpEntry->ip)
	{
		dhcpEntry->display = false;
		dhcpEntry->local = false;
		dhcpEntry->expiry = t + 20;

		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void setLeaseExpiry(data7 *dhcpEntry, MYDWORD lease)
{
	//printf("%d=%d\n", t, lease);
	if (dhcpEntry && dhcpEntry->ip)
	{
		if (lease > (MYDWORD)(INT_MAX - t))
			dhcpEntry->expiry = INT_MAX;
		else
			dhcpEntry->expiry = t + lease;

		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void setLeaseExpiry(data7 *dhcpEntry)
{
	if (dhcpEntry && dhcpEntry->ip)
	{
		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void lockIP(MYDWORD ip)
{
	if (dhcpService && ip)
	{
		MYDWORD iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
		{
			if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - cfig.dhcpRanges[rangeInd].rangeStart;

				if (cfig.dhcpRanges[rangeInd].expiry[ind] != INT_MAX)
					cfig.dhcpRanges[rangeInd].expiry[ind] = INT_MAX;

				break;
			}
		}
	}
}

void holdIP(MYDWORD ip)
{
	if (dhcpService && ip)
	{
		MYDWORD iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
		{
			if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - cfig.dhcpRanges[rangeInd].rangeStart;

				if (cfig.dhcpRanges[rangeInd].expiry[ind] == 0)
					cfig.dhcpRanges[rangeInd].expiry[ind] = 1;

				break;
			}
		}
	}
}

void __cdecl sendToken(void *)
{
	//debug("Send Token");
	ServiceSleep(1000 * 10);

	while (kRunning)
	{
		int sent = sendto(cfig.dhcpReplConn.sock,
				token.raw,
				token.bytes,
				0,
				(sockaddr*)&token.remote,
				sizeof token.remote);

//		if (sent == token.bytes && verbatim || cfig.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Sent");
//			logDHCPMess(logBuff, 2);
//		}

		ServiceSleep(1000 * 300);
	}
	EndThread();
}

MYDWORD sendRepl(data9 *req)
{
	char logBuff[256];
	data3 op;

	MYBYTE *opPointer = req->dhcpp.vend_data;

	while ((*opPointer) != DHCP_OPTION_END && opPointer < req->vp)
	{
		if ((*opPointer) == DHCP_OPTION_MESSAGETYPE)
		{
			*(opPointer + 2) = DHCP_MESS_INFORM;
			break;
		}
		opPointer = opPointer + *(opPointer + 1) + 2;
	}

	if (!req->opAdded[DHCP_OPTION_MESSAGETYPE])
	{
		op.opt_code = DHCP_OPTION_MESSAGETYPE;
		op.size = 1;
		op.value[0] = DHCP_MESS_INFORM;
		pvdata(req, &op);
	}

	if (req->hostname[0] && !req->opAdded[DHCP_OPTION_HOSTNAME])
	{
		op.opt_code = DHCP_OPTION_HOSTNAME;
		op.size = static_cast<MYBYTE>(strlen(req->hostname));
		memcpy(op.value, req->hostname, op.size);
		pvdata(req, &op);
	}

//	op.opt_code = DHCP_OPTION_SERIAL;
//	op.size = 4;
//	pULong(op.value, cfig.serial1);
//	pvdata(req, &op);

	*req->vp++ = DHCP_OPTION_END;
	req->bytes = req->vp - (MYBYTE*)req->raw;

	req->dhcpp.header.bp_op = BOOTP_REQUEST;

	req->bytes = sendto(cfig.dhcpReplConn.sock,
	                    req->raw,
	                    req->bytes,
	                    0,
						(sockaddr*)&token.remote,
						sizeof(token.remote));

	if (req->bytes <= 0)
	{
		cfig.dhcpRepl = 0;

		if (verbatim || cfig.dhcpLogLevel >= 1)
		{
			int error = WSAGetLastError();
			if (cfig.replication == 1)
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Secondary Server", error);
			else
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Primary Server", error);

			logDHCPMess(logBuff, 1);
		}

		return 0;
	}
	else if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		sprintf(logBuff, cfig.replication == 1 ?
			"DHCP Update for host %s (%s) sent to Secondary Server" :
			"DHCP Update for host %s (%s) sent to Primary Server",
			req->dhcpEntry->mapname, IP2String(req->dhcpEntry->ip));
		logDHCPMess(logBuff, 2);
	}

	return req->dhcpp.header.bp_yiaddr;
}

/*
MYDWORD sendRepl(data7 *dhcpEntry)
{
	data9 req;
	memset(&req, 0, req);
	req.vp = req.dhcpp.vend_data;
	req.messsize = sizeof(dhcp_packet);
	req.dhcpEntry = dhcpEntry;

	req.dhcpp.header.bp_op = BOOTP_REQUEST;
	req.dhcpp.header.bp_xid = t;
	req.dhcpp.header.bp_ciaddr = dhcpEntry->ip;
	req.dhcpp.header.bp_yiaddr = dhcpEntry->ip;
	req.dhcpp.header.bp_hlen = 16;
	getHexValue(req.dhcpp.header.bp_chaddr, req.dhcpEntry->mapname, &(req.dhcpp.header.bp_hlen));
	req.dhcpp.header.bp_magic_num[0] = 99;
	req.dhcpp.header.bp_magic_num[1] = 130;
	req.dhcpp.header.bp_magic_num[2] = 83;
	req.dhcpp.header.bp_magic_num[3] = 99;
	strcpy(req.hostname, dhcpEntry->hostname);

	return sendRepl(&req);
}
*/

void recvRepl(data9 *req)
{
	char logBuff[256];
	cfig.dhcpRepl = t + 600;

	MYDWORD ip = req->dhcpp.header.bp_yiaddr ? req->dhcpp.header.bp_yiaddr : req->dhcpp.header.bp_ciaddr;

	if (!ip || !req->dhcpp.header.bp_hlen)
	{
//		if (verbatim || cfig.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Received");
//			logDHCPMess(logBuff, 2);
//		}

		if (req->dns)
			cfig.dnsRepl = t + 600;

		if (cfig.replication == 1)
		{
			if (req->hostname[0])
				add2Cache(0, req->hostname, cfig.zoneServers[1], INT_MAX, LOCAL_A, LOCAL_PTR_AUTH);

			int sent = sendto(cfig.dhcpReplConn.sock,
					token.raw,
					token.bytes,
					0,
					(sockaddr*)&token.remote,
					sizeof token.remote);

//			if (sent == token.bytes && (verbatim || cfig.dhcpLogLevel >= 2))
//			{
//				sprintf(logBuff, "Token Responded");
//				logDHCPMess(logBuff, 2);
//			}
		}
		return;
	}

	char rInd = getRangeInd(ip);

	if (rInd >= 0)
	{
		int ind  = getIndex(rInd, ip);
		req->dhcpEntry = cfig.dhcpRanges[rInd].dhcpEntry[ind];

		if (req->dhcpEntry && !req->dhcpEntry->fixed && strcasecmp(req->dhcpEntry->mapname, req->chaddr))
			req->dhcpEntry->expiry = 0;
	}

	req->dhcpEntry = findDHCPEntry(req->chaddr);

	if (req->dhcpEntry && req->dhcpEntry->ip != ip)
	{
		if (req->dhcpEntry->fixed)
		{
			sprintf(logBuff, cfig.replication == 1 ?
				"DHCP Update ignored for %s (%s) from Secondary Server" :
				"DHCP Update ignored for %s (%s) from Primary Server",
				req->chaddr, IP2String(ip));

			logDHCPMess(logBuff, 1);
			return;
		}
		else if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind  = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (ind >= 0)
				cfig.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] = 0;
		}
	}

	if (!req->dhcpEntry && rInd >= 0)
	{
		data71 lump;
		memset(&lump, 0, sizeof lump);
		lump.dataType = DHCP_ENTRY;
		lump.mapname = req->chaddr;
		lump.hostname = req->hostname;
		req->dhcpEntry = createCache(&lump);

		if (req->dhcpEntry)
			dhcpCache[req->dhcpEntry->mapname] = req->dhcpEntry;
/*
		req->dhcpEntry = (data7*)calloc(1, sizeof(data7));

		if (!req->dhcpEntry)
		{
			sprintf(logBuff, "Memory Allocation Error");
			logDHCPMess(logBuff, 1);
			return;
		}

		req->dhcpEntry->mapname = strdup(req->chaddr);

		if (!req->dhcpEntry->mapname)
		{
			sprintf(logBuff, "Memory Allocation Error");
			free(req->dhcpEntry);
			logDHCPMess(logBuff, 1);
			return;
		}
*/
	}

	if (req->dhcpEntry)
	{
		req->dhcpEntry->ip = ip;
		req->dhcpEntry->rangeInd = rInd;
		req->dhcpEntry->display = true;
		req->dhcpEntry->local = false;

		MYDWORD hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		setLeaseExpiry(req->dhcpEntry, hangTime);

		if (req->hostname[0])
			updateCachedHostname(req);

		updateStateFile(req->dhcpEntry);

		if (dnsService && cfig.replication == 1)
			updateDNS(req);
	}
	else
	{
		sprintf(logBuff, cfig.replication == 1 ?
			"DHCP Update ignored for %s (%s) from Secondary Server" :
			"DHCP Update ignored for %s (%s) from Primary Server",
			req->chaddr, IP2String(ip));
		logDHCPMess(logBuff, 1);
		return;
	}

	if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		sprintf(logBuff, cfig.replication == 1 ?
			"DHCP Update received for %s (%s) from Secondary Server" :
			"DHCP Update received for %s (%s) from Primary Server",
			req->chaddr, IP2String(ip));
		logDHCPMess(logBuff, 2);
	}
}

char getRangeInd(MYDWORD ip)
{
	if (ip)
	{
		MYDWORD iip = htonl(ip);

		for (char k = 0; k < cfig.rangeCount; k++)
			if (iip >= cfig.dhcpRanges[k].rangeStart && iip <= cfig.dhcpRanges[k].rangeEnd)
				return k;
	}
	return -1;
}

int getIndex(char rangeInd, MYDWORD ip)
{
	if (ip && rangeInd >= 0 && rangeInd < cfig.rangeCount)
	{
		MYDWORD iip = htonl(ip);
		if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			return (iip - cfig.dhcpRanges[rangeInd].rangeStart);
	}
	return -1;
}

const data4 *findOption(const char *name)
{
	const data4 *p = opData;
	if (MYDWORD i = atoi(name))
	{
		if (i >= 254)
			return NULL;
		MYBYTE opTag = static_cast<MYBYTE>(i);
		do
		{
			if (opTag == p->opTag)
				return p;
		} while (++p < opData + _countof(opData));
	}
	else
	{
		do
		{
			if (!strcasecmp(name, p->opName))
				return p;
		} while (++p < opData + _countof(opData));
	}
	return NULL;
}

bool loadOptions(FILE *f, const char *sectionName, data20 *optionData)
{
	char logBuff[256];

	optionData->ip = 0;
	optionData->mask = 0;
	optionData->codepage = 0;
	MYWORD buffsize = sizeof(dhcp_packet) - sizeof(dhcp_header);
	MYBYTE *dp = optionData->options;
	MYBYTE op_specified[256];

	memset(op_specified, 0, 256);
	*dp++ = 0;

	char raw[512];
	char name[512];
	char value[512];

	for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
	{
		//MYBYTE *ddp = dp;
		MYBYTE hoption[256];
		MYBYTE valSize = 0;
		MYBYTE valType = 0;

		mySplit(name, value, raw, '=');

		//printf("%s=%s\n", name, value);

		if (!name[0])
		{
			sprintf(logBuff, "Warning: section [%s] invalid option %s ignored", sectionName, raw);
			logDHCPMess(logBuff, 1);
			continue;
		}

		if (!strcasecmp(name, "DHCPRange"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addDHCPRange(value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "IP"))
		{
			if (!strcasecmp(sectionName, GLOBALOPTIONS) || !strcasecmp(sectionName, RANGESET))
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!isIP(value) && strcasecmp(value, "0.0.0.0"))
			{
				sprintf(logBuff, "Warning: section [%s] option Invalid IP Addr %s option ignored", sectionName, value);
				logDHCPMess(logBuff, 1);
			}
			else
				optionData->ip = inet_addr(value);
			continue;
		}
		else if (!strcasecmp(name, "CodePage"))
		{
			optionData->codepage = static_cast<MYWORD>(atoi(value));
			continue;
		}
		else if (!strcasecmp(name, "FilterMacRange"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addMacRange(optionData->rangeSetInd, value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}

		unsigned long j = 0;

		size_t len = strlen(value);
		if (len == 0)
			valType = 9;
		else if (value[0] == '"' && value[len - 1] == '"')
		{
			valType = 2;
			value[0] = NBSP;
			value[len - 1] = NBSP;
			myTrim(value);
			len = strlen(value);
			if (len > UCHAR_MAX)
			{
				sprintf(logBuff, "Warning: section [%s] option %s value too big, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}
			valSize = static_cast<MYBYTE>(len);
		}
		else if (strchr(value, ':'))
		{
			valType = 2;
			valSize = sizeof hoption - 1;
			if (const char *errorPos = getHexValue(hoption, value, &valSize))
			{
				valType = 1;
				valSize = static_cast<MYBYTE>(len);
			}
			else
				memcpy(value, hoption, valSize);
		}
		else if (parseInt(value, j) == len)
		{
			if (j > USHRT_MAX)
				valType = 4;
			else if (j > UCHAR_MAX)
				valType = 5;
			else
				valType = 6;
		}
//		else if ((strchr(value, '.') && (opType == 2 || opType == 3 || opType == 8 || opType == 0)) || (!strchr(value, '.') && strchr(value, ',')))
		else if (strchr(value, '.') || strchr(value, ','))
		{
			valType = 2;
			const char *ptr = value;
			while (size_t len = parseInt(ptr += strspn(ptr, "/,.\t "), j))
			{
				if (j > UCHAR_MAX)
					break;
				if (valSize > UCHAR_MAX)
					break;
				hoption[valSize++] = static_cast<char>(j);
				ptr += len;
			}
			if (*ptr)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, too many bytes or value range exceeded, entry ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}
			memcpy(value, hoption, valSize);
		}
		else
		{
			if (len > UCHAR_MAX)
			{
				sprintf(logBuff, "Warning: section [%s] option %s value too long, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}
			valSize = static_cast<MYBYTE>(len);
			valType = 1;
		}

		if (!strcasecmp(name, "FilterVendorClass"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addVendClass(optionData->rangeSetInd, value, valSize);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "FilterUserClass"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addUserClass(optionData->rangeSetInd, value, valSize);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "FilterSubnetSelection"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				addServer(cfig.rangeSet[optionData->rangeSetInd].subnetIP, MAX_RANGE_FILTERS, fIP(value));
				cfig.hasFilter = 1;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "TargetRelayAgent"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				cfig.rangeSet[optionData->rangeSetInd].targetIP = fIP(value);
				//printf("TARGET IP %s set RangeSetInd  %d\n", IP2String(cfig.rangeSet[optionData->rangeSetInd].targetIP), optionData->rangeSetInd);
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}

		const data4 *op = findOption(name);
		if (!op)
		{
			sprintf(logBuff, "Warning: section [%s] invalid option %s, ignored", sectionName, raw);
			logDHCPMess(logBuff, 1);
			continue;
		}

		const MYBYTE opTag = op->opTag;
		const MYBYTE opType = op->opType;
		assert(opType);
		//sprintf(logBuff, "Tag %i ValType %i opType %i value=%s size=%u", opTag, valType, opType, value, valSize);
		//logDHCPMess(logBuff, 1);

		if (op_specified[opTag])
		{
			sprintf(logBuff, "Warning: section [%s] duplicate option %s, ignored", sectionName, raw);
			logDHCPMess(logBuff, 1);
			continue;
		}

		//printf("Option=%u opType=%u valueType=%u valSize=%u\n", opTag, opType, valType, valSize);

		op_specified[opTag] = true;

		if (valType == 9)
		{
			if (buffsize > 2)
			{
				*dp++ = opTag;
				*dp++ = 0;
				buffsize -= 2;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}

		switch (opType)
		{
		case 1:
			value[valSize++] = 0;

			if (valType != 1 && valType != 2)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, need string value, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (opTag == DHCP_OPTION_DOMAINNAME)
			{
				sprintf(logBuff, "Warning: section [%s] option %u should be under [DOMAIN_NAME], ignored", sectionName, opTag);
				logDHCPMess(logBuff, 1);
				continue;
			}
			else if (buffsize > valSize + 2)
			{
				*dp++ = opTag;
				*dp++ = valSize;
				memcpy(dp, value, valSize);
				dp += valSize;
				buffsize -= (valSize + 2);
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;

		case 3:
		case 8:
			if (valType == 2)
			{
				if (opType == 3 && valSize % 4)
				{
					sprintf(logBuff, "Warning: section [%s] option %s, missing/extra bytes/octates in IP, option ignored", sectionName, raw);
					logDHCPMess(logBuff, 1);
					continue;
				}
				else if (opType == 8 && valSize % 8)
				{
					sprintf(logBuff, "Warning: section [%s] option %s, some values not in IP/Mask form, option ignored", sectionName, raw);
					logDHCPMess(logBuff, 1);
					continue;
				}

				if (opTag == DHCP_OPTION_NETMASK)
				{
					if (valSize != 4 || !checkMask(fIP(value)))
					{
						sprintf(logBuff, "Warning: section [%s] Invalid subnetmask %s, option ignored", sectionName, raw);
						logDHCPMess(logBuff, 1);
						continue;
					}
					else
						optionData->mask = fIP(value);
				}

				if (buffsize > valSize + 2)
				{
					*dp++ = opTag;
					*dp++ = valSize;
					memcpy(dp, value, valSize);
					dp += valSize;
					buffsize -= (valSize + 2);
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMess(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, Invalid value, should be one or more IP/4 Bytes", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;

		case 4:
			if (valType == 2 && valSize == 4)
				j = fULong(value);
			else if (valType < 4 || valType > 6)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, value should be integer between 0 & %u or 4 bytes, option ignored", sectionName, name, UINT_MAX);
				logDHCPMess(logBuff, 1);
				continue;
			}

			if (opTag == DHCP_OPTION_IPADDRLEASE)
			{
				if (j == 0)
					j = UINT_MAX;

				if (!strcasecmp(sectionName, GLOBALOPTIONS))
				{
					sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, please set it in [TIMINGS] section", sectionName, raw);
					logDHCPMess(logBuff, 1);
					continue;
				}
				else if (j > cfig.lease)
				{
					sprintf(logBuff, "Warning: section [%s] option %s value should be less then %u (max lease), ignored", sectionName, name, cfig.lease);
					logDHCPMess(logBuff, 1);
					continue;
				}
			}

			if (buffsize > 6)
			{
				*dp++ = opTag;
				*dp++ = 4;
				dp += pULong(dp, j);
				buffsize -= 6;
				//printf("%s=%u=%u\n",opData[op_index].opName,opData[op_index].opType,htonl(j));
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;

		case 5:
			if (valType == 2 && valSize == 2)
				j = fUShort(value);
			else if (valType < 5 || valType > 6)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or 2 bytes, option ignored", sectionName, name, USHRT_MAX);
				logDHCPMess(logBuff, 1);
				continue;
			}

			if (buffsize > 4)
			{
				*dp++ = opTag;
				*dp++ = 2;
				dp += pUShort(dp, static_cast<MYWORD>(j));
				buffsize -= 4;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;

		case 6:
			if (valType == 2 && valSize == 1)
				j = *value;
			else if (valType != 6)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or single byte, option ignored", sectionName, name, UCHAR_MAX);
				logDHCPMess(logBuff, 1);
				continue;
			}

			if (buffsize > 3)
			{
				*dp++ = opTag;
				*dp++ = 1;
				*dp++ = static_cast<MYBYTE>(j);
				buffsize -= 3;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}

		case 7:
			if (valType == 2 && valSize == 1 && *value < 2)
				j = *value;
			else if (valType == 1 && (!strcasecmp(value, "yes") || !strcasecmp(value, "on") || !strcasecmp(value, "true")))
				j = 1;
			else if (valType == 1 && (!strcasecmp(value, "no") || !strcasecmp(value, "off") || !strcasecmp(value, "false")))
				j = 0;
			else if (valType != 6 || j > 1)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, value should be yes/on/true/1 or no/off/false/0, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}

			if (buffsize > 3)
			{
				*dp++ = opTag;
				*dp++ = 1;
				*dp++ = static_cast<MYBYTE>(j);
				buffsize -= 3;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;

		default:
			if (valType == 6)
			{
				valType = 2;
				valSize = 1;
				*value = static_cast<char>(atoi(value));
			}

			if (opType == 2 && valType != 2)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, value should be comma separated bytes or hex string, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}
			else if (buffsize > valSize + 2)
			{
				*dp++ = opTag;
				*dp++ = valSize;
				memcpy(dp, value, valSize);
				dp += valSize;
				buffsize -= (valSize + 2);
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			break;
		}

		//printf("%s Option=%u opType=%u valType=%u  valSize=%u\n", raw, opTag, opType, valType, valSize);
		//printf("%s %s\n", name, hex2String(tempbuff, ddp, valSize+2, ':'));
	}

	//printf("%s=%s\n", sectionName, optionData->vendClass);

	*dp++ = DHCP_OPTION_END;
	optionData->optionSize = static_cast<MYWORD>(dp - optionData->options);
	//printf("section=%s buffersize = %u option size=%u\n", sectionName, buffsize, optionData->optionSize);
	return !strcasecmp(raw, sectionName);
}

bool lockOptions(FILE *f, const char *sectionName)
{
	char raw[512];
	char name[512];
	char value[512];

	for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
	{
		if (!mySplit(name, value, raw, '='))
			continue;

		const data4 *op = findOption(name);
		if (!op)
			continue;

		if (op->opType == 3)
		{
			char hoption[256];
			MYBYTE valSize = 0;
			unsigned long j;
			const char *ptr = value;
			while (size_t len = parseInt(ptr += strspn(ptr, "/,.\t "), j))
			{
				if (j > UCHAR_MAX)
					break;
				if (valSize > UCHAR_MAX)
					break;
				hoption[valSize++] = static_cast<char>(j);
				ptr += len;
			}

			if (*ptr)
				continue;

			if (valSize % 4)
				continue;

			for (MYBYTE i = 0; i < valSize; i += 4)
			{
				MYDWORD ip = *((MYDWORD*)&(hoption[i]));

				if (ip != INADDR_ANY && ip != INADDR_NONE)
					lockIP(ip);
			}
		}
	}
	return !strcasecmp(raw, sectionName);
}

void addDHCPRange(char *dp)
{
	char logBuff[256];

	MYDWORD rs = 0;
	MYDWORD re = 0;
	char name[512];
	char value[512];
	mySplit(name, value, dp, '-');

	if (isIP(name) && isIP(value))
	{
		rs = htonl(inet_addr(name));
		re = htonl(inet_addr(value));

		if (rs && re && rs <= re)
		{
			MYBYTE m = 0;

			for (; m < MAX_DHCP_RANGES && cfig.dhcpRanges[m].rangeStart; m++)
			{
				data13 *range = &cfig.dhcpRanges[m];

				if ((rs >= range->rangeStart && rs <= range->rangeEnd)
						|| (re >= range->rangeStart && re <= range->rangeEnd)
						|| (range->rangeStart >= rs && range->rangeStart <= re)
						|| (range->rangeEnd >= rs && range->rangeEnd <= re))
				{
					sprintf(logBuff, "Warning: DHCP Range %s overlaps with another range, ignored", dp);
					logDHCPMess(logBuff, 1);
					return;
				}
			}

			if (m < MAX_DHCP_RANGES)
			{
				cfig.dhcpSize += (re - rs + 1);
				data13 *range = &cfig.dhcpRanges[m];
				range->rangeStart = rs;
				range->rangeEnd = re;
				range->expiry = (time_t*)calloc((re - rs + 1), sizeof(time_t));
				range->dhcpEntry = (data7**)calloc((re - rs + 1), sizeof(data7*));

				if (!range->expiry || !range->dhcpEntry)
				{
					free(range->expiry);
					free(range->dhcpEntry);
					sprintf(logBuff, "DHCP Ranges Load, Memory Allocation Error");
					logDHCPMess(logBuff, 1);
					return;
				}
			}
		}
		else
		{
			sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
			logDHCPMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
		logDHCPMess(logBuff, 1);
	}
}

void addVendClass(MYBYTE rangeSetInd, char *vendClass, MYBYTE vendClassSize)
{
	char logBuff[256];

	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

	MYBYTE i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->vendClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !vendClassSize)
		return;

	rangeSet->vendClass[i] = (MYBYTE*)calloc(vendClassSize, 1);

	if(!rangeSet->vendClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMess(logBuff, 1);
	}
	else
	{
		cfig.hasFilter = true;
		rangeSet->vendClassSize[i] = vendClassSize;
		memcpy(rangeSet->vendClass[i], vendClass, vendClassSize);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", rangeSet->vendClass[i], rangeSet->vendClassSize[i], rangeSetInd, i);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->vendClass[i], rangeSet->vendClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addUserClass(MYBYTE rangeSetInd, char *userClass, MYBYTE userClassSize)
{
	char logBuff[256];

	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

	MYBYTE i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->userClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !userClassSize)
		return;

	rangeSet->userClass[i] = (MYBYTE*)calloc(userClassSize, 1);

	if(!rangeSet->userClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMess(logBuff, 1);
	}
	else
	{
		cfig.hasFilter = true;
		rangeSet->userClassSize[i] = userClassSize;
		memcpy(rangeSet->userClass[i], userClass, userClassSize);
		//printf("Loaded User Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->userClass[i], rangeSet->userClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addMacRange(MYBYTE rangeSetInd, char *macRange)
{
	char logBuff[256];

	if (macRange[0])
	{
		data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

		MYBYTE i = 0;

		for (; i <= MAX_RANGE_FILTERS && rangeSet->macSize[i]; i++);

		if (i >= MAX_RANGE_FILTERS)
			return;

		char name[256];
		char value[256];

		if (mySplit(name, value, macRange, '-'))
		{
			//printf("%s=%s\n", name, value);
			MYBYTE macSize1 = 16;
			MYBYTE macSize2 = 16;
			MYBYTE *macStart = (MYBYTE*)calloc(1, macSize1);
			MYBYTE *macEnd = (MYBYTE*)calloc(1, macSize2);

			if(!macStart || !macEnd)
			{
				sprintf(logBuff, "DHCP Range Load, Memory Allocation Error");
				logDHCPMess(logBuff, 1);
			}
			else if (getHexValue(macStart, name, &macSize1) || getHexValue(macEnd, value, &macSize2))
			{
				sprintf(logBuff, "Section [%s], Invalid character in Filter_Mac_Range %s", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (memcmp(macStart, macEnd, 16) > 0)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (higher bound specified on left), ignored", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (macSize1 != macSize2)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (start/end size mismatched), ignored", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else
			{
				cfig.hasFilter = true;
				rangeSet->macSize[i] = macSize1;
				rangeSet->macStart[i] = macStart;
				rangeSet->macEnd[i] = macEnd;
				//printf("Mac Loaded, Size=%i Start=%s rangeSetInd=%i Ind=%i\n", rangeSet->macSize[i], hex2String(tempbuff, rangeSet->macStart[i], rangeSet->macSize[i]), rangeSetInd, i);
			}
		}
		else
		{
			sprintf(logBuff, "Section [%s], invalid Filter_Mac_Range %s, ignored", RANGESET, macRange);
			logDHCPMess(logBuff, 1);
		}
	}
}

void loadDHCP(FILE *ff)
{
	char logBuff[256];

	if (FILE *f = findSection(GLOBALOPTIONS, ff))
	{
		data20 optionData;
		loadOptions(f, GLOBALOPTIONS, &optionData);
		cfig.options = (MYBYTE*)calloc(1, optionData.optionSize);
		memcpy(cfig.options, optionData.options, optionData.optionSize);
		cfig.mask = optionData.mask;
		cfig.codepage = optionData.codepage;
		rewind(ff);
	}

	if (!cfig.mask)
		cfig.mask = inet_addr("255.255.255.0");

	while (FILE *f = findSection(RANGESET, ff))
	{
		bool followup;
		MYBYTE i = 0;
		do
		{
			MYBYTE m = cfig.rangeCount;
			data20 optionData;
			optionData.rangeSetInd = i;
			followup = loadOptions(f, RANGESET, &optionData);
			MYBYTE *options = NULL;
			cfig.rangeSet[optionData.rangeSetInd].active = true;

			for (; m < MAX_DHCP_RANGES && cfig.dhcpRanges[m].rangeStart; m++)
			{
				if (options == NULL && optionData.optionSize > 3)
				{
					options = (MYBYTE*)calloc(1, optionData.optionSize);
					memcpy(options, optionData.options, optionData.optionSize);
				}
				cfig.dhcpRanges[m].rangeSetInd = optionData.rangeSetInd;
				cfig.dhcpRanges[m].options = options;
				cfig.dhcpRanges[m].mask = optionData.mask;
			}
			cfig.rangeCount = m;
		} while (followup && ++i < MAX_RANGE_SETS);
		// no rewind(ff) here because we iterate over all matching sections
	}

	//printf("%s\n", IP2String(cfig.mask));

	for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
	{
		if (!cfig.dhcpRanges[rangeInd].mask)
			cfig.dhcpRanges[rangeInd].mask = cfig.mask;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++)
		{
			MYDWORD ip = htonl(iip);

			if ((cfig.dhcpRanges[rangeInd].mask | (~ip)) == UINT_MAX || (cfig.dhcpRanges[rangeInd].mask | ip) == UINT_MAX)
				cfig.dhcpRanges[rangeInd].expiry[iip - cfig.dhcpRanges[rangeInd].rangeStart] = INT_MAX;
		}
	}

	if (FILE *f = findSection(GLOBALOPTIONS, ff))
	{
		lockOptions(f, GLOBALOPTIONS);
		rewind(ff);
	}

	while (FILE *f = findSection(RANGESET, ff))
	{
		bool followup;
		MYBYTE i = 0;
		do
		{
			followup = lockOptions(f, RANGESET);
		} while (followup && ++i < MAX_RANGE_SETS);
		// no rewind(ff) here because we iterate over all matching sections
	}

	char sectionName[512];
	while (readSection(sectionName, ff))
	{
		if (!strchr(sectionName, ':'))
			continue;

		//printf("%s\n", sectionName);

		MYBYTE hexValue[UCHAR_MAX];
		MYBYTE hexValueSize = sizeof hexValue;

		if (strlen(sectionName) > 48 || getHexValue(hexValue, sectionName, &hexValueSize))
		{
			sprintf(logBuff, "Invalid Static DHCP Host MAC Addr [%s] ignored", sectionName);
			logDHCPMess(logBuff, 1);
			continue;
		}
		if (hexValueSize > 16)
		{
			sprintf(logBuff, "Invalid Static DHCP Host [%s] MAC Addr size, ignored", sectionName);
			logDHCPMess(logBuff, 1);
			continue;
		}

		char mapname[64];
		hex2String(mapname, hexValue, hexValueSize);
		if (findDHCPEntry(mapname))
		{
			sprintf(logBuff, "Duplicate Static DHCP Host [%s] ignored", sectionName);
			logDHCPMess(logBuff, 1);
			continue;
		}

		data20 optionData;
		long fpos = ftell(ff);
		loadOptions(ff, sectionName, &optionData);
		fseek(ff, fpos, SEEK_SET);
		lockOptions(ff, sectionName);
		fseek(ff, fpos, SEEK_SET);

		dhcpMap::iterator p = dhcpCache.begin();

		for (; p != dhcpCache.end(); p++)
		{
			if (p->second->ip && p->second->ip == optionData.ip)
				break;
		}

		if (p != dhcpCache.end())
		{
			sprintf(logBuff, "Static DHCP Host [%s] Duplicate IP Address %s, Entry ignored", sectionName, IP2String(optionData.ip));
			logDHCPMess(logBuff, 1);
			continue;
		}

		data71 lump;
		memset(&lump, 0, sizeof lump);
		lump.dataType = DHCP_ENTRY;
		lump.mapname = mapname;
		lump.optionSize = optionData.optionSize;
		lump.options = optionData.options;
		if (data7 *dhcpEntry = createCache(&lump))
		{
			dhcpEntry->ip = optionData.ip;
			dhcpEntry->codepage = optionData.codepage;
			dhcpEntry->rangeInd = getRangeInd(optionData.ip);
			dhcpEntry->fixed = 1;
			lockIP(optionData.ip);
			dhcpCache[dhcpEntry->mapname] = dhcpEntry;
			//printf("%s=%s=%s size=%u %u\n", mapname, dhcpEntry->mapname, IP2String(optionData.ip), optionData.optionSize, dhcpEntry->options);
		}

		if (!optionData.ip)
		{
			sprintf(logBuff, "Warning: No IP Address for Static DHCP Host [%s] specified", sectionName);
			logDHCPMess(logBuff, 1);
		}
	}

	if (FILE *ff = fopen(leaFile, "rb"))
	{
		data8 dhcpData;

		while (fread(&dhcpData, sizeof(data8), 1, ff))
		{
			char rangeInd = -1;

			//printf("Loading %s=%s\n", dhcpData.hostname, IP2String(dhcpData.ip));

			if (dhcpData.bp_hlen <= 16 && !findServer(network.allServers, MAX_SERVERS, dhcpData.ip))
			{
				char mapname[64];
				hex2String(mapname, dhcpData.bp_chaddr, dhcpData.bp_hlen);

				dhcpMap::iterator p = dhcpCache.begin();

				data7 *dhcpEntry = NULL;
				for (; p != dhcpCache.end(); ++p)
				{
					dhcpEntry = p->second;
					if (!strcasecmp(mapname, dhcpEntry->mapname) || dhcpEntry->ip == dhcpData.ip)
						break;
				}

				if (p != dhcpCache.end() && (strcasecmp(mapname, dhcpEntry->mapname) || dhcpEntry->ip != dhcpData.ip))
					continue;

				dhcpEntry = findDHCPEntry(mapname);
				rangeInd = getRangeInd(dhcpData.ip);

				if (!dhcpEntry && rangeInd >= 0)
				{
					data71 lump;
					memset(&lump, 0, sizeof lump);
					lump.dataType = DHCP_ENTRY;
					lump.mapname = mapname;
					dhcpEntry = createCache(&lump);
/*
					dhcpEntry = (data7*)calloc(1, sizeof(data7));

					if (!dhcpEntry)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						logDHCPMess(logBuff, 1);
						return;
					}

					dhcpEntry->mapname = strdup(mapname);

					if (!dhcpEntry->mapname)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						free(dhcpEntry);
						logDHCPMess(logBuff, 1);
						return;
					}
*/
				}

				if (dhcpEntry)
				{
					dhcpCache[dhcpEntry->mapname] = dhcpEntry;
					dhcpEntry->ip = dhcpData.ip;
					dhcpEntry->rangeInd = rangeInd;
					dhcpEntry->expiry = dhcpData.expiry;
					dhcpEntry->local = dhcpData.local;
					dhcpEntry->display = true;

					if (dhcpData.hostname[0])
						dhcpEntry->hostname = strdup(dhcpData.hostname);

					setLeaseExpiry(dhcpEntry);

					if (dnsService && dhcpData.hostname[0] && cfig.replication != 2 && dhcpData.expiry > t)
					{
						if (isLocal(dhcpEntry->ip))
							add2Cache(0, dhcpData.hostname, dhcpEntry->ip, dhcpData.expiry, LOCAL_A, LOCAL_PTR_AUTH);
						else
							add2Cache(0, dhcpData.hostname, dhcpEntry->ip, dhcpData.expiry, LOCAL_A, LOCAL_PTR_NAUTH);
					}
					//printf("Loaded %s=%s\n", dhcpData.hostname, IP2String(dhcpData.ip));
				}
			}
		}

		fclose(ff);

		ff = fopen(leaFile, "wb");
		cfig.dhcpInd = 0;

		if (ff)
		{
			dhcpMap::iterator p = dhcpCache.begin();

			for (; p != dhcpCache.end(); ++p)
			{
				data7 *dhcpEntry = p->second;
				if (dhcpEntry->expiry > t || !dhcpEntry->fixed)
				{
					memset(&dhcpData, 0, sizeof dhcpData);
					dhcpData.bp_hlen = 16;
					getHexValue(dhcpData.bp_chaddr, dhcpEntry->mapname, &dhcpData.bp_hlen);
					dhcpData.ip = dhcpEntry->ip;
					dhcpData.expiry = dhcpEntry->expiry;
					dhcpData.local = dhcpEntry->local;

					if (dhcpEntry->hostname)
						strcpy(dhcpData.hostname, dhcpEntry->hostname);

					++cfig.dhcpInd;
					dhcpData.dhcpInd = cfig.dhcpInd;
					dhcpEntry->dhcpInd = cfig.dhcpInd;
					fwrite(&dhcpData, sizeof(data8), 1, ff);
				}
			}
			fclose(ff);
		}
	}
}

FILE *findSection(const char *sectionName, FILE *f)
{
	char buff[512];
	while (readSection(buff, f))
		if (strcasecmp(buff, sectionName) == 0)
			return f;
	return NULL;
}

FILE *readSection(char* buff, FILE *f, FILE *ff)
{
	do
	{
		if (fgets(buff, 512, f))
		{
			myTrim(buff, utf8bom(buff));

			if ((*buff) >= '0' && (*buff) <= '9' ||
				(*buff) >= 'A' && (*buff) <= 'Z' ||
				(*buff) >= 'a' && (*buff) <= 'z' ||
				((*buff) && strchr("/\\?*", (*buff))))
			{
				return f;
			}

			if (*buff == '[')
			{
				if (char *secend = strchr(buff, ']'))
				{
					*secend = 0;
					buff[0] = NBSP;
					myTrim(buff);
				}
				if (ff != NULL)
					break;
				return f;
			}

			if (f == ff && *buff == '@')
			{
				*buff = NBSP;
				myTrim(buff);

				char path[512];
				if (strpbrk(buff, "\\/"))
					strcpy(path, buff);
				else
					sprintf(path, "%s%s", filePATH, buff);

				f = fopen(path, "rt");
				if (f == NULL)
				{
					char logBuff[256];
					sprintf(logBuff, "Error: file %s not found", path);
					logMess(logBuff, 1);
					f = ff;
				}
			}
		}
		else if (f != ff)
		{
			if (ff != NULL)
				fclose(f);
			else
				rewind(f);
			f = ff;
		}
		else
		{
			f = NULL;
		}
	} while (f != NULL);

	return NULL;
}

int utf8bom(const char *buff)
{
	return buff[0] == '\xEF' && buff[1] == '\xBB' && buff[2] == '\xBF' ? 3 : 0;
}

char *myTrim(char *buff, int i)
{
	while (buff[i] && static_cast<MYBYTE>(buff[i]) <= NBSP)
		++i;

	int j = 0;
	while (char c = buff[i++])
		buff[j++] = c;

	do
	{
		buff[j] = '\0';
	} while (j > 0 && static_cast<MYBYTE>(buff[--j]) <= NBSP);

	return buff;
}

bool mySplit(char *name, char *value, const char *source, char splitChar)
{
	char c;
	int i = 0;
	int j = 0;

	do
	{
		c = source[i];
		// don't advance i beyond the terminating zero
		if (c != '\0')
		{
			++i;
			if (c == splitChar)
				c = '\0';
		}	
		name[j++] = c;
	} while (c != '\0' && j < 512);

	j = 0;

	do
	{
		c = source[i++];
		value[j++] = c;
	} while (c != '\0' && j < 512);

	myTrim(name);
	myTrim(value);
	//printf("%s %s\n", name, value);
	return name[0] && value[0];
}

char *strquery(data5 *req, char *extbuff)
{
	strcpy(extbuff, req->cname);

	switch (req->qtype)
	{
	case 1:
		strcat(extbuff, " A");
		break;
	case 2:
		strcat(extbuff, " NS");
		break;
	case 3:
		strcat(extbuff, " MD");
		break;
	case 4:
		strcat(extbuff, " MF");
		break;
	case 5:
		strcat(extbuff, " CNAME");
		break;
	case 6:
		strcat(extbuff, " SOA");
		break;
	case 7:
		strcat(extbuff, " MB");
		break;
	case 8:
		strcat(extbuff, " MG");
		break;
	case 9:
		strcat(extbuff, " MR");
		break;
	case 10:
		strcat(extbuff, " NULL");
		break;
	case 11:
		strcat(extbuff, " WKS");
		break;
	case 12:
		strcat(extbuff, " PTR");
		break;
	case 13:
		strcat(extbuff, " HINFO");
		break;
	case 14:
		strcat(extbuff, " MINFO");
		break;
	case 15:
		strcat(extbuff, " MX");
		break;
	case 16:
		strcat(extbuff, " TXT");
		break;
	case 28:
		strcat(extbuff, " AAAA");
		break;
	case 251:
		strcat(extbuff, " IXFR");
		break;
	case 252:
		strcat(extbuff, " AXFR");
		break;
	case 253:
		strcat(extbuff, " MAILB");
		break;
	case 254:
		strcat(extbuff, " MAILA");
		break;
	default:
		strcat(extbuff, " ANY");
		break;
	}
	return extbuff;
}

MYDWORD getClassNetwork(MYDWORD ip)
{
	data15 data;
	data.ip = ip;
	data.octate[3] = 0;

	if (data.octate[0] < 192)
		data.octate[2] = 0;

	if (data.octate[0] < 128)
		data.octate[1] = 0;

	return data.ip;
}

char *IP2String(MYDWORD ip, char *target)
{
	data15 inaddr;
	inaddr.ip = ip;
	sprintf(target, "%u.%u.%u.%u", inaddr.octate[0], inaddr.octate[1], inaddr.octate[2], inaddr.octate[3]);
	//MYBYTE *octate = (MYBYTE*)&ip;
	//sprintf(target, "%u.%u.%u.%u", octate[0], octate[1], octate[2], octate[3]);
	return target;
}

MYDWORD *addServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip)
{
	for (MYBYTE i = 0; i < maxServers; i++)
	{
		if (array[i] == ip)
			return &(array[i]);
		else if (!array[i])
		{
			array[i] = ip;
			return &(array[i]);
		}
	}
	return NULL;
}

MYDWORD *findServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip)
{
	if (ip)
	{
		for (MYBYTE i = 0; i < maxServers && array[i]; i++)
		{
			if (array[i] == ip)
				return &(array[i]);
		}
	}
	return NULL;
}

size_t parseInt(const char *p, unsigned long &value)
{
	char *q = NULL;
	value = strtoul(p, &q, 0);
	return q - p;
 }

bool isIP(char *str)
{
	if (!str || !(*str))
		return false;

	MYDWORD ip = inet_addr(str);
	int j = 0;

	for (; *str; str++)
	{
		if (*str == '.' && *(str + 1) != '.')
			++j;
		else if (*str < '0' || *str > '9')
			return false;
	}

	if (j == 3)
	{
		if (ip == INADDR_NONE || ip == INADDR_ANY)
			return false;
		else
			return true;
	}
	else
		return false;
}

char *hex2String(char *target, const MYBYTE *hex, MYBYTE bytes)
{
	char *dp = target;
	const char *fmt = "%02x";
	for (MYBYTE i = 0; i < bytes; ++i)
	{
		dp += sprintf(dp, fmt, hex[i]);
		fmt = ":%02x";
	}
	*dp = '\0';
	return target;
}

char *genHostName(char *target, const MYBYTE *hex, MYBYTE bytes)
{
	char *dp = target;
	const char *fmt = "Host%02x";
	for (MYBYTE i = 0; i < bytes; ++i)
	{
		dp += sprintf(dp, fmt, hex[i]);
		fmt = "%02x";
	}
	*dp = '\0';
	return target;
}

/*
char *IP62String(MYBYTE *source, char *target)
{
	MYWORD *dw = (MYWORD*)source;
	char *dp = target;
	MYBYTE markbyte;

	for (markbyte = 4; markbyte > 0 && !dw[markbyte - 1]; markbyte--);

	for (MYBYTE i = 0; i < markbyte; i++)
		dp += sprintf(dp, "%x:", ntohs(dw[i]));

	for (markbyte = 4; markbyte < 8 && !dw[markbyte]; markbyte++);

	for (MYBYTE i = markbyte; i < 8; i++)
		dp += sprintf(dp, ":%x", htons(dw[i]));

	return target;
}
*/

char *IP62String(MYBYTE *source, char *target)
{
	char *dp = target;
	bool zerostarted = false;
	bool zeroended = false;

	for (MYBYTE i = 0; i < 16; i += 2, source += 2)
	{
		if (source[0])
		{
			if (zerostarted)
				zeroended = true;

			if (zerostarted && zeroended)
			{
				dp += sprintf(dp, "::");
				zerostarted = false;
			}
			else if (dp != target)
				dp += sprintf(dp, ":");

			dp += sprintf(dp, "%x", source[0]);
			dp += sprintf(dp, "%02x", source[1]);
		}
		else if (source[1])
		{
			if (zerostarted)
				zeroended = true;

			if (zerostarted && zeroended)
			{
				dp += sprintf(dp, "::");
				zerostarted = false;
			}
			else if (dp != target)
				dp += sprintf(dp, ":");

			dp += sprintf(dp, "%0x", source[1]);
		}
		else if (!zeroended)
			zerostarted = true;
	}

	return target;
}

const char *getHexValue(MYBYTE *target, const char *source, MYBYTE *size)
{
	if (*size)
		memset(target, 0, (*size));

	for ((*size) = 0; (*source) && (*size) < UCHAR_MAX; (*size)++, target++)
	{
		if ((*source) >= '0' && (*source) <= '9')
		{
			(*target) = (*source) - '0';
		}
		else if ((*source) >= 'a' && (*source) <= 'f')
		{
			(*target) = (*source) - 'a' + 10;
		}
		else if ((*source) >= 'A' && (*source) <= 'F')
		{
			(*target) = (*source) - 'A' + 10;
		}
		else
		{
			return source;
		}

		++source;

		if ((*source) >= '0' && (*source) <= '9')
		{
			(*target) *= 16;
			(*target) += (*source) - '0';
		}
		else if ((*source) >= 'a' && (*source) <= 'f')
		{
			(*target) *= 16;
			(*target) += (*source) - 'a' + 10;
		}
		else if ((*source) >= 'A' && (*source) <= 'F')
		{
			(*target) *= 16;
			(*target) += (*source) - 'A' + 10;
		}
		else if ((*source) == ':' || (*source) == '-')
		{
			++source;
			continue;
		}
		else if (*source)
		{
			return source;
		}
		else
		{
			continue;
		}

		++source;

		if ((*source) == ':' || (*source) == '-')
		{
			++source;
		}
		else if (*source)
			return source;
	}

	if (*source)
		return source;

	//printf("macfucked in=%s\n", tSource);
	//printf("macfucked out=%s\n", hex2String(tempbuff, tTarget, *size));
	return NULL;
}

char *myLower(char *string)
{
	const char diff = 'a' - 'A';
	bool xn = false;
	size_t len = strlen(string);
	for (size_t i = 0; i < len; i++)
		if (string[i] >= 'A' && string[i] <= 'Z')
			string[i] += diff;
		else if (string[i] & 0x80)
			xn = true;
	if (xn)
	{
		const UTF8 *source = reinterpret_cast<const UTF8 *>(string);
		punycode_uint codepoints[512];
		UTF32 *target = reinterpret_cast<UTF32 *>(codepoints);
		if (ConvertUTF8toUTF32(
			&source, source + len,
			&target, target + len,
			strictConversion) == conversionOK)
		{
			punycode_uint n = target - reinterpret_cast<UTF32 *>(codepoints);
			punycode_uint k = 0;
			punycode_uint m = 0;
			punycode_uint i = 0;
			punycode_uint j = 0;
			xn = false;
			*target = '.';
			while (i <= n)
			{
				UTF32 codepoint = codepoints[i++];
				if (codepoint != '.')
				{
					if (codepoint > 0x7F)
						xn = true;
					++m;
				}
				else
				{
					if (xn)
					{
						xn = false;
						string[j++] = 'x';
						string[j++] = 'n';
						string[j++] = '-';
						string[j++] = '-';
						punycode_uint n = _countof(codepoints) - 1 - j;
						if (punycode_encode(m, codepoints + k,
							NULL, &n, string + j) == punycode_success)
						{
							j += n;
							k += m;
						}
					}
					while (k < i && k < n)
						string[j++] = static_cast<char>(codepoints[k++]);
					m = 0;
				}
			}
			string[j] = '\0';
		}
	}
	return string;
}

bool wildcmp(char *string, char *wild)
{
	// Written by Jack Handy - jakkhandy@hotmail.com
	// slightly modified
	char *cp = NULL;
	char *mp = NULL;

	while ((*string) && (*wild != '*'))
	{
		if ((*wild != *string) && (*wild != '?'))
		{
			return 0;
		}
		++wild;
		++string;
	}

	while (*string)
	{
		if (*wild == '*')
		{
			if (!*++wild)
				return 1;

			mp = wild;
			cp = string + 1;
		}
		else if ((*wild == *string) || (*wild == '?'))
		{
			++wild;
			++string;
		}
		else
		{
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*')
		++wild;

	return !(*wild);
}

bool isLocal(MYDWORD ip)
{
	if (cfig.rangeStart && htonl(ip) >= cfig.rangeStart && htonl(ip) <= cfig.rangeEnd)
		return true;
	else if (getRangeInd(ip) >= 0)
		return true;
	else
		return false;
}

MYBYTE makeLocal(char *mapname)
{
	if (!strcasecmp(mapname, cfig.zone))
	{
		mapname[0] = 0;
		return DNTYPE_A_ZONE;
	}
	else if (!strcasecmp(mapname, cfig.authority))
		return DNTYPE_P_ZONE;
	else if (char *dp = strchr(mapname, '.'))
	{
		if (!strcasecmp(dp + 1, cfig.zone))
		{
			*dp = 0;
			return DNTYPE_A_LOCAL;
		}
		else if ((dp = strstr(mapname, arpa)) != NULL)
		{
			if (strstr(mapname, cfig.authority))
			{
				*dp = 0;
				return DNTYPE_P_LOCAL;
			}
			else
			{
				*dp = 0;
				return DNTYPE_P_EXT;
			}
		}
		else if (strstr(mapname, ip6arpa))
			return DNTYPE_P_EXT;
		else
			return DNTYPE_A_EXT;
	}
	else
		return DNTYPE_A_BARE;
}

void listCache()
{
	hostMap::iterator p = dnsCache[currentInd].begin();
	for (; p != dnsCache[currentInd].end(); ++p)
	{
		data7 *cache = p->second;

		char logBuff[256];
		if (cache->hostname && cache->bytes == 0)
			sprintf(logBuff, "%s=%s", cache->mapname, cache->hostname);
		else
			sprintf(logBuff, "%s=%s", cache->mapname, IP2String(cache->ip));

		logDNSMess(logBuff, 1);
	}
}

void listDhcpCache()
{
	dhcpMap::iterator p = dhcpCache.begin();
	for (; p != dhcpCache.end(); ++p)
	{
		data7 *cache = p->second;
		char logBuff[256];
		sprintf(logBuff, cache->mapname);
		logDHCPMess(logBuff, 1);
	}
}

void checkSize(MYBYTE ind)
{
	//listCache();
	//listDhcpCache();
	//printf("Start %u=%u\n",dnsCache[ind].size(),dnsAge[ind].size());
	//sprintf(logBuff, "Start Cache size %u=%u",dnsCache[ind].size(),dnsAge[ind].size());
	//debug(logBuff);

	//MYBYTE maxDelete = 3;
	expiryMap::iterator p = dnsAge[ind].begin();

	//while (p != dnsAge[ind].end() && p->first < t && maxDelete > 0)
	while (p != dnsAge[ind].end() && p->first <= t)
	{
		data7 *cache = p->second;
		//printf("processing %s=%i\n", cache->mapname, p->first - t);

		if (cache->expiry <= t)
		{
			dnsAge[ind].erase(p++);

			if (cache->dataType == QUEUE && cache->expiry)
			{
				if (cache->dnsIndex < MAX_SERVERS)
				{
					if (network.currentDNS == cache->dnsIndex)
					{
						if (network.dns[1])
						{
							++network.currentDNS;

							if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
								network.currentDNS = 0;
						}
					}
				}
				else if (cache->dnsIndex >= 128 && cache->dnsIndex < 192)
				{
					data6 *dnsRoute = &cfig.dnsRoutes[(cache->dnsIndex - 128) / 2];
					MYBYTE currentDNS = cache->dnsIndex % 2;

					if (dnsRoute->currentDNS == currentDNS && dnsRoute->dns[1])
						dnsRoute->currentDNS = 1 - dnsRoute->currentDNS;
				}
			}


			if (cfig.replication != 2)
			{
				if (cache->dataType == LOCAL_A)
					cfig.serial1 = t;
				else if (cache->dataType == LOCAL_PTR_AUTH)
					cfig.serial2 = t;
			}

			//sprintf(logBuff, "Data Type=%u Cache Size=%u, Age Size=%u, Entry %s being deleted", cache->dataType, dnsCache[ind].size(), dnsAge[ind].size(), cache->mapname);
			//logMess(logBuff, 1);
			delDnsEntry(ind, cache);
			//maxDelete--;
		}
		else
		{
			dnsAge[ind].erase(p++);
			dnsAge[ind].insert(pair<time_t, data7*>(cache->expiry, cache));
			//sprintf(logBuff, "Entry %s being advanced", cache->mapname);
			//logMess(logBuff, 1);
		}
	}

	//sprintf(logBuff, "End Cache size %u=%u",dnsCache[ind].size(),dnsAge[ind].size());
	//debug(logBuff);

/*
	if (ind == currentInd && dhcpService)
	{
		//printf("dhcpAge=%u\n", dhcpAge.size());

		p = dhcpAge.begin();

		while (p != dhcpAge.end() && p->first < t)
		{
			cache = p->second;
			//printf("processing %s=%i\n", cache->mapname, p->first - t);

			if (cache->hanged && cache->expiry > t)
			{
				dhcpAge.erase(p++);
				dhcpAge.insert(pair<time_t, data7*>(cache->expiry, cache));
			}
			else
			{
				dhcpAge.erase(p++);

				if (cache->hanged && cache->expiry < t)
				{
					sendRepl(cache);
					printf("Lease released\n");
				}

				cache->hanged = false;
			}
		}
	}
*/
}

void calcRangeLimits(MYDWORD ip, MYDWORD mask, MYDWORD *rangeStart, MYDWORD *rangeEnd)
{
	*rangeStart = htonl(ip & mask) + 1;
	*rangeEnd = htonl(ip | (~mask)) - 1;
}

bool checkMask(MYDWORD mask)
{
	mask = htonl(mask);

	while (mask)
	{
		if (mask < (mask << 1))
			return false;

		mask <<= 1;
	}
	return true;
}

MYDWORD calcMask(MYDWORD rangeStart, MYDWORD rangeEnd)
{
	data15 ip1, ip2, mask;

	ip1.ip = htonl(rangeStart);
	ip2.ip = htonl(rangeEnd);

	for (MYBYTE i = 0; i < 4; i++)
	{
		mask.octate[i] = ip1.octate[i] ^ ip2.octate[i];

		if (i && mask.octate[i - 1] < 255)
			mask.octate[i] = 0;
		else if (mask.octate[i] == 0)
			mask.octate[i] = 255;
		else if (mask.octate[i] < 2)
			mask.octate[i] = 254;
		else if (mask.octate[i] < 4)
			mask.octate[i] = 252;
		else if (mask.octate[i] < 8)
			mask.octate[i] = 248;
		else if (mask.octate[i] < 16)
			mask.octate[i] = 240;
		else if (mask.octate[i] < 32)
			mask.octate[i] = 224;
		else if (mask.octate[i] < 64)
			mask.octate[i] = 192;
		else if (mask.octate[i] < 128)
			mask.octate[i] = 128;
		else
			mask.octate[i] = 0;
	}

	return mask.ip;
}

data7 *findEntry(MYBYTE ind, char *key, MYBYTE entryType)
{
	myLower(key);
	hostMap::iterator it = dnsCache[ind].find(key);

	while (it != dnsCache[ind].end() && !strcasecmp(it->second->mapname, key))
	{
		if (it->second->dataType == entryType)
			return it->second;
		++it;
	}

	return NULL;
}

data7 *findEntry(MYBYTE ind, char *key)
{
	//printf("finding %u=%s\n",ind,key);
	myLower(key);
	hostMap::iterator it = dnsCache[ind].find(key);

	if (it != dnsCache[ind].end())
		return it->second;

	return NULL;
}

data7 *findDHCPEntry(char *key)
{
	//printf("finding %u=%s\n",ind,key);
	myLower(key);
	dhcpMap::iterator it = dhcpCache.find(key);

	if (it != dhcpCache.end())
		return it->second;

	return NULL;
}

void addEntry(MYBYTE ind, data7 *entry)
{
	myLower(entry->mapname);
	dnsCache[ind].insert(pair<string, data7*>(entry->mapname, entry));

	if (entry->expiry && entry->expiry < INT_MAX)
		dnsAge[ind].insert(pair<time_t, data7*>(entry->expiry, entry));
}

void delDnsEntry(MYBYTE ind, data7* cache)
{
	if (cache)
	{
		//sprintf(logBuff, "DataType=%u Size=%u, Entry %s being deleted", cache->dataType, dnsCache[ind].size(), cache->mapname);
		//debug(logBuff);

		if (ind <= 1)
		{
			hostMap::iterator r = dnsCache[ind].find(cache->mapname);

			for (; r != dnsCache[ind].end(); r++)
			{
				if (strcasecmp(r->second->mapname, cache->mapname))
					break;
				else if (r->second == cache)
				{
					dnsCache[ind].erase(r);
					free(cache);
					break;
				}
			}
		}
	}
}

MYDWORD getSerial(const char *zone)
{
	char tempbuff[256];
	char logBuff[256];
	MYDWORD serial1 = 0;
	data5 req;
	memset(&req, 0, sizeof req);
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);

	if (cfig.replication == 2)
		req.remote.sin_addr.s_addr = cfig.zoneServers[0];
	else
		req.remote.sin_addr.s_addr = cfig.zoneServers[1];

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	req.dnsp = (dnsPacket*)req.raw;
	req.dnsp->header.qdcount = htons(1);
	req.dnsp->header.xid = (t % USHRT_MAX);
	req.dp = &req.dnsp->data;
	req.dp += pQu(req.dp, zone);
	req.dp += pUShort(req.dp, DNS_TYPE_SOA);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.bytes = req.dp - req.raw;
	//pUShort(req.raw, req.bytes - 2);

	if ((req.bytes = sendto(req.sock, req.raw, req.bytes, 0, (sockaddr*)&req.remote, sizeof(req.remote))) <= 0)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Failed to send request to Primary Server %s", IP2String(req.remote.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
		return 0;
	}

	timeval tv1;
	tv1.tv_sec = 3;
	tv1.tv_usec = 0;

	fd_set readfds1;
	FD_ZERO(&readfds1);
	FD_SET(req.sock, &readfds1);

	select(USHRT_MAX, &readfds1, NULL, NULL, &tv1);

	if (FD_ISSET(req.sock, &readfds1))
	{
		req.sockLen = sizeof(req.remote);
		req.bytes = recvfrom(req.sock, req.raw, sizeof(req.raw), 0, (sockaddr*)&req.remote, &req.sockLen);

		if (req.bytes > 0 && req.dnsp->header.qr && !req.dnsp->header.rcode && ntohs(req.dnsp->header.ancount))
		{
			req.dp = &req.dnsp->data;
			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(tempbuff, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				req.dp += fQu(tempbuff, req.dnsp, req.dp);
				req.qtype = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				fULong(req.dp);
				req.dp += 4; //ttl
				req.dp += 2; //datalength

				if (req.qtype == DNS_TYPE_SOA)
				{
					req.dp += fQu(tempbuff, req.dnsp, req.dp);
					req.dp += fQu(tempbuff, req.dnsp, req.dp);
					serial1 = fULong(req.dp);
				}
			}
		}
	}

	closesocket(req.sock);
	return serial1;
}

/*char *getServerName(MYDWORD ip)
{
	data5 req;
	memset(&req, 0, sizeof req);
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = ip;

	timeval tv1;
	fd_set readfds1;

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	req.dnsp = (dnsPacket*)req.raw;
	req.dnsp->header.qdcount = htons(1);
	req.dnsp->header.xid = (t % USHRT_MAX);
	req.dp = &req.dnsp->data;
	IP2String(htonl(ip), tempbuff);
	strcat(tempbuff, arpa);
	req.dp += pQu(req.dp, tempbuff);
	req.dp += pUShort(req.dp, DNS_TYPE_PTR);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.bytes = req.dp - req.raw;
	//pUShort(req.raw, req.bytes - 2);

	if ((req.bytes = sendto(req.sock, req.raw, req.bytes, 0, (sockaddr*)&req.remote, sizeof(req.remote))) <= 0)
	{
		closesocket(req.sock);
		return NULL;
	}

	FD_ZERO(&readfds1);
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;
	FD_SET(req.sock, &readfds1);
	select(USHRT_MAX, &readfds1, NULL, NULL, &tv1);

	if (FD_ISSET(req.sock, &readfds1))
	{
		req.sockLen = sizeof(req.remote);
		req.bytes = recvfrom(req.sock, req.raw, sizeof(req.raw), 0, (sockaddr*)&req.remote, &req.sockLen);
		if (req.bytes > 0 && req.dnsp->header.qr && !req.dnsp->header.rcode && ntohs(req.dnsp->header.ancount))
		{
			closesocket(req.sock);
			return getResult(&req);
		}
	}

	closesocket(req.sock);
	return NULL;
}*/

int recvTcpDnsMess(char *target, SOCKET sock, int targetSize)
{
	timeval tv1;
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;

	fd_set readfds1;
	FD_ZERO(&readfds1);
	FD_SET(sock, &readfds1);

	if (select(sock + 1, &readfds1, NULL, NULL, &tv1))
	{
		int chunk = recv(sock, target, 2, 0);

		if (chunk == 2)
		{
			char *ptr;
			int rcd = chunk;
			int bytes = fUShort(target) + rcd;

			if (bytes > targetSize)
				return 0;

			while (rcd < bytes)
			{
				FD_ZERO(&readfds1);
				FD_SET(sock, &readfds1);
				tv1.tv_sec = 5;
				tv1.tv_usec = 0;

				if (select(sock + 1, &readfds1, NULL, NULL, &tv1))
				{
					ptr = target + rcd;
					chunk = recv(sock, ptr, bytes - rcd, 0);

					if (chunk <= 0)
						return 0;
					else
						rcd += chunk;
				}
				else
					return 0;
			}

			return rcd;
		}
	}

	return 0;
}

void emptyCache(MYBYTE rInd)
{
	//debug("emptyCache");
	data7 *cache = NULL;

	//sprintf(logBuff, "Emptying cache[%d] Start %d=%d",rInd, dnsCache[rInd].size(), dnsAge[rInd].size());
	//logMess(logBuff, 2);

	cfig.mxCount[rInd] = 0;
	dnsAge[rInd].clear();
	hostMap::iterator p = dnsCache[rInd].begin();

	while (p != dnsCache[rInd].end())
	{
		cache = p->second;
		++p;
		delDnsEntry(rInd, cache);
	}

	dnsCache[rInd].clear();
}

void __cdecl checkZone(void *)
{
	char logBuff[256];

	ServiceSleep(1000 * cfig.refresh);

	while (kRunning)
	{
		MYBYTE updateCache = 1 - currentInd;
		emptyCache(updateCache);
		sprintf(logBuff, "Checking Serial from Primary Server %s", IP2String(cfig.zoneServers[0]));
		logDNSMess(logBuff, 2);

		MYDWORD serial1 = getSerial(cfig.zone);
		MYDWORD serial2 = getSerial(cfig.authority);

		if (!serial1 || !serial2)
		{
			cfig.dnsRepl = 0;
			cfig.dhcpRepl = 0;
			sprintf(logBuff, "Failed to get Serial from %s, waiting %i seconds to retry", IP2String(cfig.zoneServers[0]), cfig.retry);
			logDNSMess(logBuff, 1);
			ServiceSleep(1000 * cfig.retry);
		}
		else if (cfig.serial1 && cfig.serial1 == serial1 && cfig.serial2 && cfig.serial2 == serial2)
		{
			cfig.dnsRepl = t + cfig.refresh;
			sprintf(logBuff, "Zone Refresh not required");
			logDNSMess(logBuff, 2);

			if (cfig.expire > (MYDWORD)(INT_MAX - t))
				cfig.expireTime = INT_MAX;
			else
				cfig.expireTime = t + cfig.expire;

			ServiceSleep(1000 * cfig.refresh);
		}
		else
		{
			serial1 = getZone(updateCache, cfig.zone);
			serial2 = getZone(updateCache, cfig.authority);

			if (!serial1 || !serial2)
			{
				sprintf(logBuff, "Waiting %u seconds to retry", cfig.retry);
				logDNSMess(logBuff, 1);
				ServiceSleep(1000 * cfig.retry);
			}
			else
			{
				cfig.dnsRepl = t + cfig.refresh;
				newInd = updateCache;
				cfig.serial1 = serial1;
				cfig.serial2 = serial2;

				if (cfig.expire > (MYDWORD)(INT_MAX - t))
					cfig.expireTime = INT_MAX;
				else
					cfig.expireTime = t + cfig.expire;

				ServiceSleep(1000 * cfig.refresh);
			}
		}
	}
	EndThread();
}

MYDWORD getZone(MYBYTE updateCache, char *zone)
{
	//debug("getZone");

	data71 lump;
	char logBuff[256];
	char hostname[256];
	char cname[256];
	char localhost[] = "localhost";
	MYBYTE zoneType = 0;
	MYDWORD serial1 = 0;
	MYDWORD serial2 = 0;
	MYDWORD hostExpiry = 0;
	MYDWORD refresh = 0;
	MYDWORD retry = 0;
	MYDWORD expire = 0;
	MYDWORD expiry;
	MYDWORD minimum = 0;
	int added = 0;
	char *data;
	char *dp;
	MYDWORD ip;
	data5 req;

	if (!strcasecmp(zone, cfig.zone))
	{
		zoneType = DNTYPE_A_ZONE;
		add2Cache(updateCache, localhost, inet_addr("127.0.0.1"), INT_MAX, LOCALHOST_A, 0);
	}
	else if (!strcasecmp(zone, cfig.authority))
	{
		zoneType = DNTYPE_P_ZONE;
		add2Cache(updateCache, localhost, inet_addr("127.0.0.1"), INT_MAX, 0, LOCALHOST_PTR);
	}
	else
		return 0;

	memset(&req, 0, sizeof req);
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
	{
		sprintf(logBuff, "Failed to Create Socket, Zone Transfer Failed");
		logDNSMess(logBuff, 1);
		return 0;
	}

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = cfig.zoneServers[1];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Error: Interface %s not ready, Zone Transfer Failed", IP2String(req.addr.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
		return 0;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = cfig.zoneServers[0];

	req.sockLen = sizeof(req.remote);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) >= 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsp = (dnsPacket*)req.dp;
		req.dnsp->header.qdcount = htons(1);
		req.dnsp->header.xid = (t % USHRT_MAX);
		req.dp = &req.dnsp->data;
		req.dp += pQu(req.dp, zone);
		req.dp += pUShort(req.dp, DNS_TYPE_AXFR);
		req.dp += pUShort(req.dp, DNS_CLASS_IN);
		req.bytes = req.dp - req.raw;
		pUShort(req.raw, static_cast<MYWORD>(req.bytes - 2));

		if (send(req.sock, req.raw, req.bytes, 0) < req.bytes)
		{
			closesocket(req.sock);
			sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(req.remote.sin_addr.s_addr));
			logDNSMess(logBuff, 1);
			return 0;
		}

		while (kRunning)
		{
			req.bytes = recvTcpDnsMess(req.raw, req.sock, sizeof(req.raw));
			//printf("bytes = %u\n", req.bytes);

			if (req.bytes < 2)
				break;

			MYWORD pktSize = fUShort(req.raw);

			if ((MYWORD)req.bytes < pktSize + 2)
				break;

			req.dnsp = (dnsPacket*)(req.raw + 2);
			req.dp = &req.dnsp->data;

			if (!req.dnsp->header.qr || req.dnsp->header.rcode || !ntohs(req.dnsp->header.ancount))
				break;

			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(hostname, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(hostname, req.dnsp, req.dp);

				if (!hostname[0])
					continue;

				//printf("%s\n", hostname);
				req.qtype = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				expiry = fULong(req.dp);
				req.dp += 4; //ttl
				int dataSize = fUShort(req.dp);
				req.dp += 2; //datalength
				data = req.dp;
				req.dp += dataSize;

				switch (req.qtype)
				{
				case DNS_TYPE_SOA:
					data += fQu(hostname, req.dnsp, data);
					data += fQu(cname, req.dnsp, data);

					if (!serial1)
					{
						hostExpiry = expiry;
						serial1 = fULong(data);
						data += 4;
						refresh = fULong(data);
						data += 4;
						retry = fULong(data);
						data += 4;
						expire = fULong(data);
						data += 4;
						minimum = fULong(data);
						data += 4;
						++added;
					}
					else if (!serial2)
						serial2 = fULong(data);

					break;

				case DNS_TYPE_A:
					ip = fIP(data);
					makeLocal(hostname);
					add2Cache(updateCache, hostname, ip, INT_MAX, STATIC_A_AUTH, NONE);
					++added;
					break;

				case DNS_TYPE_PTR:
					myLower(hostname);
					dp = strstr(hostname, arpa);

					if (dp)
					{
						*dp = 0;
						ip = ntohl(inet_addr(hostname));
						fQu(hostname, req.dnsp, data);
						makeLocal(hostname);
						add2Cache(updateCache, hostname, ip, INT_MAX, NONE, STATIC_PTR_AUTH);
						++added;
					}
					break;

				case DNS_TYPE_MX:
					if (makeLocal(hostname) == DNTYPE_A_ZONE)
					{
						cfig.mxServers[updateCache][cfig.mxCount[updateCache]].pref = fUShort(data);
						data += sizeof(MYWORD);
						fQu(cname, req.dnsp, data);
						strcpy(cfig.mxServers[updateCache][cfig.mxCount[updateCache]].hostname, cname);
						++cfig.mxCount[updateCache];
						++added;
					}
					break;

				case DNS_TYPE_NS:
					if (zoneType == DNTYPE_A_ZONE)
					{
						fQu(cfig.nsA, req.dnsp, data);
						strcpy(cfig.nsABare, cfig.nsA);
						makeLocal(cfig.nsABare);
					}
					else
					{
						fQu(cfig.nsP, req.dnsp, data);
						strcpy(cfig.nsPBare, cfig.nsP);
						makeLocal(cfig.nsPBare);
					}
					break;

				case DNS_TYPE_CNAME:
					fQu(cname, req.dnsp, data);
					makeLocal(hostname);
					memset(&lump, 0, sizeof lump);

					if (makeLocal(cname) == DNTYPE_A_EXT)
						lump.dataType = EXT_CNAME;
					else
						lump.dataType = LOCAL_CNAME;

					lump.mapname = hostname;
					lump.hostname = cname;
					data7 *cache = createCache(&lump);
/*
					cache = (data7*)calloc(1, sizeof(data7));

					if (cache)
					{
						cache->mapname = strdup(hostname);
						cache->dataType = cname_type;
						cache->hostname = strdup(cname);

						if (cache->mapname && cache->hostname)
						{
							addEntry(updateCache, cache);
						}
						else
						{
							sprintf(logBuff, "Memory Error");
							logDNSMess(logBuff, 1);
							continue;
						}
					}
*/
					if (cache)
					{
						addEntry(updateCache, cache);
						cache->expiry = INT_MAX;
//						cache->serial = serial1;
						++added;
					}
					break;
				}
				//printf("serial=%u %u %u\n", serial1, serial2, hostExpiry);
			}
		}

		closesocket(req.sock);

		if (serial1 && serial1 == serial2 && hostExpiry)
		{
			if (cfig.replication == 2)
			{
				cfig.lease = hostExpiry;
				cfig.refresh = refresh;
				cfig.retry = retry;
				cfig.expire = expire;
				cfig.minimum = minimum;
			}

			//printf("Refresh ind %i serial %u size %i\n", updateCache, serial1, dnsCache[updateCache].size());
			sprintf(logBuff, "Zone %s Transferred from Primary Server, %u RRs imported", zone, added);
			logDNSMess(logBuff, 1);
			return serial1;
		}
		else if (!serial1)
		{
			sprintf(logBuff, "Replication Server %s, Missing Serial", IP2String(req.remote.sin_addr.s_addr));
			logDNSMess(logBuff, 1);
		}
		else if (serial1 != serial2)
		{
			sprintf(logBuff, "Replication Server %s, Serial Changed %u %u", IP2String(req.remote.sin_addr.s_addr), serial1, serial2);
			logDNSMess(logBuff, 1);
		}
		else
		{
			sprintf(logBuff, "Replication Server %s, Invalid AXFR data", IP2String(req.remote.sin_addr.s_addr));
			logDNSMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(req.remote.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
		closesocket(req.sock);
	}

	return 0;
}

bool getSecondary()
{
	char logBuff[256];
	char hostname[256];
	MYDWORD ip;
	MYDWORD expiry = 0;
	char *data = NULL;
	char *dp = NULL;
	unsigned rr = 0;
	data5 req;

	memset(&req, 0, sizeof req);
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
		return false;

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = cfig.zoneServers[0];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		return false;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);

	if (dhcpService && cfig.replication == 1)
		req.remote.sin_addr.s_addr = cfig.zoneServers[1];
	else
		return false;

	req.sockLen = sizeof(req.remote);
	time_t t = time(NULL);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) == 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsp = (dnsPacket*)req.dp;
		req.dnsp->header.qdcount = htons(1);
		req.dnsp->header.xid = (t % USHRT_MAX);
		req.dp = &req.dnsp->data;
		req.dp += pQu(req.dp, cfig.authority);
		req.dp += pUShort(req.dp, DNS_TYPE_AXFR);
		req.dp += pUShort(req.dp, DNS_CLASS_IN);
		req.bytes = req.dp - req.raw;
		pUShort(req.raw, static_cast<MYWORD>(req.bytes - 2));

		if (send(req.sock, req.raw, req.bytes, 0) < req.bytes)
		{
			closesocket(req.sock);
			return false;
		}

		while (kRunning)
		{
			req.bytes = recvTcpDnsMess(req.raw, req.sock, sizeof(req.raw));
			//printf("bytes = %u\n", req.bytes);

			if (req.bytes < 2)
				break;

			MYWORD pktSize = fUShort(req.raw);

			if ((MYWORD)req.bytes < pktSize + 2)
				break;

			req.dnsp = (dnsPacket*)(req.raw + 2);
			req.dp = &req.dnsp->data;

			if (!req.dnsp->header.qr || req.dnsp->header.rcode || !ntohs(req.dnsp->header.ancount))
				break;

			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(hostname, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(hostname, req.dnsp, req.dp);
				//printf("%s\n", hostname);
				req.qtype = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				expiry = fULong(req.dp);
				req.dp += 4; //ttl
				int dataSize = fUShort(req.dp);
				req.dp += 2; //datalength
				data = req.dp;
				req.dp += dataSize;

				if (req.qtype == DNS_TYPE_PTR)
				{
					myLower(hostname);
					dp = strstr(hostname, arpa);

					if (dp)
					{
						*dp = 0;
						ip = ntohl(inet_addr(hostname));
						fQu(hostname, req.dnsp, data);
						makeLocal(hostname);

						//printf("candidate %s=%s\n", hostname, IP2String(ip));

						dhcpMap::iterator p = dhcpCache.begin();

						for (; p != dhcpCache.end(); ++p)
						{
							data7 *dhcpEntry = p->second;
							if (dhcpEntry->ip && dhcpEntry->hostname)
							{
								//printf("%s=%s\n", dhcpEntry->hostname, hostname);
								if (ip == dhcpEntry->ip && !strcasecmp(hostname, dhcpEntry->hostname))
								{
									//printf("added %s=%s\n", hostname, IP2String(ip));
									if (expiry < (MYDWORD)(INT_MAX - t))
										expiry += t;
									else
										expiry = INT_MAX;

									add2Cache(0, hostname, ip, expiry, LOCAL_A, LOCAL_PTR_AUTH);
									++rr;
									break;
								}
							}
						}
					}
				}
			}
		}

		sprintf(logBuff, "%u RRs rebuild from Secondary Server", rr);
		logDNSMess(logBuff, 2);
		closesocket(req.sock);
		return true;
	}
	else
	{
//		int error = WSAGetLastError();
//		sprintf(logBuff, "Failed to connect to Secondary Server %s, WSAError %u", IP2String(req.remote.sin_addr.s_addr), error);
//		logDNSMess(logBuff, 1);
		closesocket(req.sock);
		return false;
	}
}

void freeDhcpMapData(dhcpMap::iterator p, dhcpMap::iterator q)
{
	for (; p != q; ++p)
	{
		free(p->second->hostname);
		free(p->second);
	}
}

void freeHostMapData(hostMap::iterator p, hostMap::iterator q)
{
	for (; p != q; ++p)
	{
		free(p->second);
	}
}

void freeDhcpRanges(data13 *p, data13 *q)
{
	MYBYTE *options = NULL;
	for (; p != q && p->rangeStart; ++p)
	{
		if (options != p->options)
			free(options = p->options);
		free(p->expiry);
		free(p->dhcpEntry);
	}
}

int runProg()
{
	LeakDetector ld;
	char logBuff[256];

	lEvent = CreateEvent(
		NULL,                  // default security descriptor
		FALSE,                 // ManualReset
		TRUE,                  // Signalled
		TEXT("AchalDualServerLogEvent"));  // object name
	DWORD dwError = GetLastError();
	if (lEvent == NULL)
	{
		printf("CreateEvent error: %d\n", dwError);
		return -1;
	}
	if (dwError == ERROR_ALREADY_EXISTS)
	{
		sprintf(logBuff, "CreateEvent opened an existing Event\nServer May already be Running");
		logDHCPMess(logBuff, 0);
		return -1;
	}

	//printf("%i\n",t);
	//printf("%i\n",sizeof(data7));
	//printf("%d\n",dnsCache[currentInd].max_size());
	if (!BeginThread(serverloop, 0, NULL))
	{
		sprintf(logBuff, "Thread Creation Failed");
		logMess(logBuff, 1);
		return -1;
	}

	if (serviceStatusHandle)
	{
		serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}

	char raw[512];
	char name[512];
	char value[512];

	memset(&cfig, 0, sizeof cfig);
	memset(&network, 0, sizeof network);
	GetModuleFileName(NULL, filePATH, _MAX_PATH);
	char *fileExt = strrchr(filePATH, '.');
	*fileExt = '\0';
	sprintf(leaFile, "%s.state", filePATH);
	sprintf(iniFile, "%s.ini", filePATH);
	sprintf(lnkFile, "%s.url", filePATH);
	sprintf(htmFile, "%s.htm", filePATH);
	fileExt = strrchr(filePATH, '\\');
	*fileExt++ = '\0';
	sprintf(logFile, "%s\\log\\%s%%Y%%m%%d.log", filePATH, fileExt);
	sprintf(cliFile, "%s\\log\\%%s.log", filePATH);
	strcat(filePATH, "\\");

	//printf("log=%s\n", logFile);

	cfig.dnsLogLevel = 1;
	cfig.dhcpLogLevel = 1;

	FILE *ff = fopen(iniFile, "rt");
	if (ff == NULL)
	{
		sprintf(logBuff, "Could not open %s", iniFile);
		logMess(logBuff, 1);
		return -1;
	}

	if (FILE *f = findSection("LOGGING", ff))
	{
		char tempbuff[512];
		tempbuff[0] = 0;

		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (mySplit(name, value, raw, '='))
			{
				if (!strcasecmp(name, "DNSLogLevel"))
				{
					if (!strcasecmp(value, "None"))
						cfig.dnsLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						cfig.dnsLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						cfig.dnsLogLevel = 2;
					else
						sprintf(tempbuff, "Section [LOGGING], Invalid DNSLogLevel: %s", value);
				}
				else if (!strcasecmp(name, "DHCPLogLevel"))
				{
					if (!strcasecmp(value, "None"))
						cfig.dhcpLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						cfig.dhcpLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						cfig.dhcpLogLevel = 2;
					else if (!strcasecmp(value, "Debug"))
						cfig.dhcpLogLevel = 3;
					else
						sprintf(tempbuff, "Section [LOGGING], Invalid DHCPLogLevel: %s", value);
				}
				else
					sprintf(tempbuff, "Section [LOGGING], Invalid Entry %s ignored", raw);
			}
			else
				sprintf(tempbuff, "Section [LOGGING], Invalid Entry %s ignored", raw);
		}

		if (tempbuff[0])
			logMess(tempbuff, 1);

		rewind(ff);
	}

	sprintf(logBuff, "%s Starting...", sVersion);
	logMess(logBuff, 1);

	MYWORD wVersionRequested = MAKEWORD(1, 1);
	WSAStartup(wVersionRequested, &cfig.wsaData);

	if (cfig.wsaData.wVersion != wVersionRequested)
	{
		sprintf(logBuff, "WSAStartup Error");
		logMess(logBuff, 1);
	}

	if (FILE *f = findSection("SERVICES", ff))
	{
		dhcpService = false;
		dnsService = false;

		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (!strcasecmp(raw, "DNS"))
				dnsService = true;
			else if (!strcasecmp(raw, "DHCP"))
				dhcpService = true;
			else
			{
				sprintf(logBuff, "Section [SERVICES] invalid entry %s ignored", raw);
				logMess(logBuff, 1);
			}
		}

		if (!dhcpService && !dnsService)
		{
			dhcpService = true;
			dnsService = true;
		}
		rewind(ff);
	}

	if (dnsService)
	{
		sprintf(logBuff, "Starting DNS Service");
		logDNSMess(logBuff, 1);
	}

	if (dhcpService)
	{
		sprintf(logBuff, "Starting DHCP Service");
		logDHCPMess(logBuff, 1);
	}

	if (dnsService)
	{
		if (cfig.dnsLogLevel == 3)
			sprintf(logBuff, "DNS Logging: Debug");
		else if (cfig.dnsLogLevel == 2)
			sprintf(logBuff, "DNS Logging: All");
		else if (cfig.dnsLogLevel == 1)
			sprintf(logBuff, "DNS Logging: Normal");
		else
			sprintf(logBuff, "DNS Logging: None");

		logDNSMess(logBuff, 1);
	}

	if (dhcpService)
	{
		if (cfig.dhcpLogLevel == 3)
			sprintf(logBuff, "DHCP Logging: Debug");
		else if (cfig.dhcpLogLevel == 2)
			sprintf(logBuff, "DHCP Logging: All");
		else if (cfig.dhcpLogLevel == 1)
			sprintf(logBuff, "DHCP Logging: Normal");
		else
			sprintf(logBuff, "DHCP Logging: None");

		logDHCPMess(logBuff, 1);
	}

	cfig.lease = 36000;

	if (FILE *f = findSection("TIMINGS", ff))
	{
		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (mySplit(name, value, raw, '='))
			{
				if (atol(value) || !strcasecmp(value,"0"))
				{
					if (!strcasecmp(name, "AddressTime"))
					{
						cfig.lease = atol(value);

						if (!cfig.lease)
							cfig.lease = UINT_MAX;
					}
					else if (!strcasecmp(name, "Refresh"))
						cfig.refresh = atol(value);
					else if (!strcasecmp(name, "Retry"))
						cfig.retry = atol(value);
					else if (!strcasecmp(name, "Expire"))
						cfig.expire = atol(value);
					else if (!strcasecmp(name, "Minimum"))
						cfig.minimum = atol(value);
					else if (!strcasecmp(name, "MinCacheTime"))
						cfig.minCache = atol(value);
					else if (!strcasecmp(name, "MaxCacheTime"))
						cfig.maxCache = atol(value);
					else
					{
						sprintf(logBuff, "Section [TIMINGS], Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [TIMINGS], Invalid value: %s ignored", value);
					logDNSMess(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Section [TIMINGS], Missing value, entry %s ignored", raw);
				logDNSMess(logBuff, 1);
			}
		}
		rewind(ff);
	}

	if (!cfig.refresh)
	{
		cfig.refresh = cfig.lease / 10;

		if (cfig.refresh > 3600)
			cfig.refresh = 3600;

		if (cfig.refresh < 300)
			cfig.refresh = 300;
	}

	if (!cfig.retry || cfig.retry > cfig.refresh)
	{
		cfig.retry = cfig.refresh / 5;

		if (cfig.retry > 600)
			cfig.retry = 600;

		if (cfig.retry < 60)
			cfig.retry = 60;
	}

	if (!cfig.expire)
	{
		if (UINT_MAX/24 > cfig.lease)
			cfig.expire = 24 * cfig.lease;
		else
			cfig.expire = UINT_MAX;
	}

	if (!cfig.minimum)
		cfig.minimum = cfig.retry;

	if (FILE *f = findSection("DOMAIN_NAME", ff))
	{
		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (mySplit(name, value, raw, '='))
			{
				data15 mask;
				data15 network;
				char left[64];

				cfig.authority[0] = 0;
				myLower(value);
				mask.ip = 0;
				network.ip = 0;

				for (MYBYTE octateNum = 0; octateNum < 3; octateNum++)
				{
					mySplit(left, value, value, '.');
					char *right = NULL;
					MYBYTE octate = static_cast<MYBYTE>(strtol(left, &right, 10));
					if (right <= left)
						break;
					for (int j = 2; j >= 0; j--)
					{
						network.octate[j + 1] = network.octate[j];
						mask.octate[j + 1] = mask.octate[j];
					}
					mask.octate[0] = UCHAR_MAX;
					network.octate[0] = octate;
					strcat(cfig.authority, left);
					strcat(cfig.authority, ".");
				}

				if (!strcasecmp(value, arpa + 1))
				{
					strcat(cfig.authority, arpa + 1);
					cfig.aLen = static_cast<MYBYTE>(strlen(cfig.authority));
					calcRangeLimits(network.ip, mask.ip, &cfig.rangeStart, &cfig.rangeEnd);
					cfig.authorized = 1;
				}
				else
				{
					sprintf(logBuff, "Warning: Invalid Domain Name (Part %s), ignored", cfig.authority);
					cfig.aLen = 0;
					cfig.authority[0] = 0;
					logDNSMess(logBuff, 1);
				}
			}

			if (chkQu(name))
			{
				myLower(name);
				strcpy(cfig.zone, name);
				cfig.zLen = static_cast<MYBYTE>(strlen(cfig.zone));
			}
			else
			{
				cfig.aLen = 0;
				cfig.authority[0] = 0;
				sprintf(logBuff, "Warning: Invalid Domain Name %s, ignored", raw);
				logDNSMess(logBuff, 1);
			}
		}
		rewind(ff);
	}

	getInterfaces(&network, ff);
	sprintf(cfig.servername_fqn, "%s.%s", cfig.servername, cfig.zone);

	if (FILE *f = findSection("ZONE_REPLICATION", ff))
	{
		int i = 2;
		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (i < MAX_TCP_CLIENTS)
			{
				if (dnsService && !cfig.authorized)
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Server is not an authority, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
					continue;
				}

				if (mySplit(name, value, raw, '='))
				{
					if (chkQu(name) && !isIP(name) && isIP(value))
					{
						if (!strcasecmp(name, "Primary"))
							cfig.zoneServers[0] = inet_addr(value);
						else if (!strcasecmp(name, "Secondary"))
							cfig.zoneServers[1] = inet_addr(value);
						else if (dnsService && !strcasecmp(name, "AXFRClient"))
						{
							cfig.zoneServers[i] = inet_addr(value);
							++i;
						}
						else
						{
							sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Missing value, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}
		rewind(ff);
	}

	if (!cfig.zoneServers[0] && cfig.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Primary Server");
		logDNSMess(logBuff, 1);
	}
	else if (cfig.zoneServers[0] && !cfig.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Secondary Server");
		logDNSMess(logBuff, 1);
	}
	else if (cfig.zoneServers[0] && cfig.zoneServers[1])
	{
		if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[0]) && findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[1]))
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] Primary & Secondary should be Different Boxes");
			logDNSMess(logBuff, 1);
		}
		else if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[0]))
			cfig.replication = 1;
		else if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[1]))
			cfig.replication = 2;
		else
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] No Server IP not found on this Machine");
			logDNSMess(logBuff, 1);
		}
	}

	if (cfig.replication != 2)
	{
		strcpy(cfig.nsP, cfig.servername_fqn);
		strcpy(cfig.nsA, cfig.servername_fqn);
		strcpy(cfig.nsPBare, cfig.servername);
		strcpy(cfig.nsABare, cfig.servername);
	}

	if (dhcpService)
	{
		loadDHCP(ff);

		for (int i = 0; i < cfig.rangeCount; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "DHCP Range: ");
			logPtr += sprintf(logPtr, "%s", IP2String(htonl(cfig.dhcpRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "-%s", IP2String(htonl(cfig.dhcpRanges[i].rangeEnd)));
			logPtr += sprintf(logPtr, "/%s", IP2String(cfig.dhcpRanges[i].mask));
			logDHCPMess(logBuff, 1);
		}

		if (cfig.replication)
		{
			lockIP(cfig.zoneServers[0]);
			lockIP(cfig.zoneServers[1]);
		}
	}

	if (dnsService)
	{
		if (FILE *f = findSection("DNS_ALLOWED_HOSTS", ff))
		{
			int i = 0;

			for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
			{
				if (i < MAX_DNS_RANGES)
				{
					MYDWORD rs = 0;
					MYDWORD re = 0;
					mySplit(name, value, raw, '-');

					if (isIP(name) && isIP(value))
					{
						rs = htonl(inet_addr(name));
						re = htonl(inet_addr(value));
					}
					else if (isIP(name) && !value[0])
					{
						rs = htonl(inet_addr(name));
						re = rs;
					}

					//printf("%u=%u\n", rs, re);

					if (rs && re && rs <= re)
					{
						cfig.dnsRanges[i].rangeStart = rs;
						cfig.dnsRanges[i].rangeEnd = re;
						++i;
					}
					else
					{
						sprintf(logBuff, "Section [DNS_ALLOWED_HOSTS] Invalid entry %s in ini file, ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
			rewind(ff);
		}

		if (cfig.replication != 2)
		{
			if (FILE *f = findSection("DNS_HOSTS", ff))
			{
				for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
				{
					if (mySplit(name, value, raw, '='))
					{
						if (chkQu(name) && !isIP(name))
						{
							MYDWORD ip = inet_addr(value);
							MYBYTE nameType = makeLocal(name);
							bool ipLocal = isLocal(ip);

							if (!strcasecmp(value, "0.0.0.0"))
							{
								addHostNotFound(0, name);
								continue;
							}
							else if (!ip)
							{
								sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry %s ignored", raw);
								logDNSMess(logBuff, 1);
								continue;
							}

							switch (nameType)
							{
							case DNTYPE_A_ZONE:
							case DNTYPE_A_BARE:
							case DNTYPE_A_LOCAL:
								add2Cache(0, name, ip, INT_MAX, STATIC_A_AUTH, 0);
								break;

							default:
								if (cfig.replication)
								{
									sprintf(logBuff, "Section [DNS_HOSTS] forward entry for %s not in Forward Zone, ignored", raw);
									logDNSMess(logBuff, 1);
								}
								else
									add2Cache(0, name, ip, INT_MAX, STATIC_A_NAUTH, 0);
								break;
							}

							if (ipLocal)
							{
								add2Cache(0, name, ip, INT_MAX, 0, STATIC_PTR_AUTH);
								holdIP(ip);
							}
							else if (cfig.replication)
							{
								sprintf(logBuff, "Section [DNS_HOSTS] reverse entry for %s not in Reverse Zone, ignored", raw);
								logDNSMess(logBuff, 1);
							}
							else
								add2Cache(0, name, ip, INT_MAX, 0, STATIC_PTR_NAUTH);
						}
						else
						{
							sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [DNS_HOSTS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				rewind(ff);
			}
			if (FILE *f = findSection("ALIASES", ff))
			{
				int i = 0;

				for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
				{
					if (mySplit(name, value, raw, '='))
					{
						MYBYTE nameType = makeLocal(name);
						MYBYTE aliasType = makeLocal(value);

						if (chkQu(name) && chkQu(value) && strcasecmp(value, cfig.zone))
						{
							if ((nameType == DNTYPE_A_BARE || nameType == DNTYPE_A_LOCAL || nameType == DNTYPE_A_ZONE))
							{
								data7 *cache = findEntry(0, name);

								if (!cache)
								{
									data71 lump;
									memset(&lump, 0, sizeof lump);

									if ((aliasType == DNTYPE_A_BARE || aliasType == DNTYPE_A_LOCAL || aliasType == DNTYPE_A_ZONE))
										lump.dataType = LOCAL_CNAME;
									else
										lump.dataType = EXT_CNAME;

									lump.mapname = name;
									lump.hostname = value;
									cache = createCache(&lump);

									if (cache)
									{
										cache->expiry = INT_MAX;
	//									cache->serial = cfig.serial1;
										addEntry(0, cache);
										++i;
									}
	/*
									cache = (data7*)calloc(1, sizeof(data7));

									if (cache)
									{
										if ((aliasType == DNTYPE_A_BARE || aliasType == DNTYPE_A_LOCAL || aliasType == DNTYPE_A_ZONE))
											cache->dataType = LOCAL_CNAME;
										else
											cache->dataType = EXT_CNAME;

										cache->mapname = strdup(name);
										cache->hostname = strdup(value);

										if (!cache->mapname || !cache->hostname)
										{
											sprintf(logBuff, "Section [ALIASES] entry %s memory error", raw);
											logDNSMess(logBuff, 1);
										}
										else
										{
											cache->expiry = INT_MAX;
	//										cache->serial = cfig.serial1;
											addEntry(0, cache);
											++i;
										}
									}
									else
									{
										sprintf(logBuff, "Section [ALIASES] entry %s memory error", raw);
										logDNSMess(logBuff, 1);
									}
	*/
								}
								else
								{
									sprintf(logBuff, "Section [ALIASES] duplicate entry %s ignored", raw);
									logDNSMess(logBuff, 1);
								}
							}
							else
							{
								sprintf(logBuff, "Section [ALIASES] alias %s should be bare/local name, entry ignored", name);
								logDNSMess(logBuff, 1);
							}
						}
						else
						{
							sprintf(logBuff, "Section [ALIASES] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ALIASES], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				rewind(ff);
			}

			if (FILE *f = findSection("MAIL_SERVERS", ff))
			{
				cfig.mxCount[0] = 0;

				for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
				{
					if (cfig.mxCount[0] < MAX_SERVERS)
					{
						if (mySplit(name, value, raw, '='))
						{
							if (chkQu(name) && atoi(value))
							{
								MYWORD pref = static_cast<MYWORD>(atoi(value));
								cfig.mxServers[0][cfig.mxCount[0]].pref = pref;
								cfig.mxServers[1][cfig.mxCount[0]].pref = pref;

								if (!strchr(name, '.'))
								{
									strcat(name, ".");
									strcat(name, cfig.zone);
								}

								strcpy(cfig.mxServers[0][cfig.mxCount[0]].hostname, name);
								strcpy(cfig.mxServers[1][cfig.mxCount[0]].hostname, name);
								++cfig.mxCount[0];
							}
							else
							{
								sprintf(logBuff, "Section [MAIL_SERVERS] Invalid Entry: %s ignored", raw);
								logDNSMess(logBuff, 1);
							}
						}
						else
						{
							sprintf(logBuff, "Section [MAIL_SERVERS], Missing value, entry %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					//cfig.mxCount[1] = cfig.mxCount[0];
				}
				rewind(ff);
			}
		}

		if (FILE *f = findSection("CONDITIONAL_FORWARDERS", ff))
		{
			int i = 0;

			for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
			{
				if (i < MAX_COND_FORW)
				{
					if (mySplit(name, value, raw, '='))
					{
						int j = 0;

						for (; j < MAX_COND_FORW && cfig.dnsRoutes[j].zone[0]; j++)
						{
							if (!strcasecmp(cfig.dnsRoutes[j].zone, name))
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Duplicate Entry for Child Zone %s ignored", raw);
								logDNSMess(logBuff, 1);
								break;
							}
						}

						if (j < MAX_COND_FORW && !cfig.dnsRoutes[j].zone[0])
						{
							if (name[0] && chkQu(name) && value[0])
							{
								char *value1 = strchr(value, ',');

								if (value1)
								{
									*value1++ = '\0';

									MYDWORD ip = inet_addr(myTrim(value));
									MYDWORD ip1 = inet_addr(myTrim(value1));

									if (isIP(value) && isIP(value1))
									{
										strcpy(cfig.dnsRoutes[i].zone, name);
										cfig.dnsRoutes[i].zLen = static_cast<MYWORD>(strlen(cfig.dnsRoutes[i].zone));
										cfig.dnsRoutes[i].dns[0] = ip;
										cfig.dnsRoutes[i].dns[1] = ip1;
										++i;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMess(logBuff, 1);
									}
								}
								else
								{
									MYDWORD ip = inet_addr(value);

									if (isIP(value))
									{
										strcpy(cfig.dnsRoutes[i].zone, name);
										cfig.dnsRoutes[i].zLen = static_cast<MYWORD>(strlen(cfig.dnsRoutes[i].zone));
										cfig.dnsRoutes[i].dns[0] = ip;
										++i;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMess(logBuff, 1);
									}
								}
							}
							else
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
								logDNSMess(logBuff, 1);
							}
						}
					}
					else
					{
						sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
			rewind(ff);
		}

		if (FILE *f = findSection("WILD_HOSTS", ff))
		{
			int i = 0;

			for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
			{
				if (i < MAX_WILD_HOSTS)
				{
					if (mySplit(name, value, raw, '='))
					{
						if (chkQu(name) && (isIP(value) || !strcasecmp(value, "0.0.0.0")))
						{
							MYDWORD ip = inet_addr(value);
							strcpy(cfig.wildHosts[i].wildcard, name);
							myLower(cfig.wildHosts[i].wildcard);
							cfig.wildHosts[i].ip = ip;
							++i;
						}
						else
						{
							sprintf(logBuff, "Section [WILD_HOSTS] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [WILD_HOSTS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
			rewind(ff);
		}

		if (cfig.replication == 2)
		{
			while (kRunning)
			{
				MYDWORD serial1 = getSerial(cfig.zone);
				MYDWORD serial2 = getSerial(cfig.authority);
				cfig.serial1 = getZone(0, cfig.zone);
				cfig.serial2 = getZone(0, cfig.authority);

				if (cfig.serial1 && cfig.serial2)
					break;

				sprintf(logBuff, "Failed to get Zones from Primary Server, waiting %d seconds to retry", cfig.retry);
				logDNSMess(logBuff, 1);

				ServiceSleep(cfig.retry * 1000);
			}

			if (dhcpService)
			{
				data7 *cache = NULL;
				hostMap::iterator p = dnsCache[0].begin();

				while (p != dnsCache[0].end())
				{
					cache = p->second;

					switch (cache->dataType)
					{
					case STATIC_A_AUTH:
						holdIP(cache->ip);
						break;

					case STATIC_PTR_AUTH:
						holdIP(htonl(inet_addr(cache->mapname)));
						break;
					}

					++p;
				}
			}

			if (cfig.expire > (MYDWORD)(INT_MAX - t))
				cfig.expireTime = INT_MAX;
			else
				cfig.expireTime = t + cfig.expire;

			BeginThread(checkZone, 0, NULL);
		}
		else if (cfig.replication == 1)
		{
			cfig.serial1 = t;
			cfig.serial2 = t;
			cfig.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(0, localhost, inet_addr("127.0.0.1"), INT_MAX, LOCALHOST_A, LOCALHOST_PTR);

			if (isLocal(cfig.zoneServers[0]))
				add2Cache(0, cfig.servername, cfig.zoneServers[0], INT_MAX, SERVER_A_AUTH, SERVER_PTR_AUTH);
			else
				add2Cache(0, cfig.servername, cfig.zoneServers[0], INT_MAX, SERVER_A_AUTH, SERVER_PTR_NAUTH);

			for (int i = 0; i < 2; i++)
			{
				if (getSecondary())
					break;
			}
		}
		else
		{
			cfig.serial1 = t;
			cfig.serial2 = t;
			cfig.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(0, localhost, inet_addr("127.0.0.1"), INT_MAX, LOCALHOST_A, LOCALHOST_PTR);

			bool ifspecified = false;

			if (FILE *f = findSection("LISTEN_ON", ff))
			{
				for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
				{
					ifspecified = true;
					MYDWORD ip = inet_addr(raw);

					if (ip && ip != INADDR_NONE)
					{
						if (isLocal(ip))
							add2Cache(0, cfig.servername, ip, INT_MAX, SERVER_A_AUTH, SERVER_PTR_AUTH);
						else
							add2Cache(0, cfig.servername, ip, INT_MAX, SERVER_A_AUTH, SERVER_PTR_NAUTH);
					}
				}
				rewind(ff);
			}

			for (int i = 0; !ifspecified && i < MAX_SERVERS && network.allServers[i]; i++)
			{
				if (isLocal(network.allServers[i]))
					add2Cache(0, cfig.servername, network.allServers[i], INT_MAX, SERVER_A_AUTH, SERVER_PTR_AUTH);
				else
					add2Cache(0, cfig.servername, network.allServers[i], INT_MAX, SERVER_A_AUTH, SERVER_PTR_NAUTH);
			}
		}
	}

	if (dhcpService)
	{
		if (cfig.replication)
		{
			cfig.dhcpReplConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (cfig.dhcpReplConn.sock == INVALID_SOCKET)
			{
				sprintf(logBuff, "Failed to Create DHCP Replication Socket");
				logDHCPMess(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", cfig.dhcpReplConn.sock);

				if (cfig.replication == 1)
					cfig.dhcpReplConn.server = cfig.zoneServers[0];
				else
					cfig.dhcpReplConn.server = cfig.zoneServers[1];

				cfig.dhcpReplConn.addr.sin_family = AF_INET;
				cfig.dhcpReplConn.addr.sin_addr.s_addr = cfig.dhcpReplConn.server;
				cfig.dhcpReplConn.addr.sin_port = 0;

				int nRet = bind(cfig.dhcpReplConn.sock, (sockaddr*)&cfig.dhcpReplConn.addr, sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					cfig.dhcpReplConn.ready = false;
					sprintf(logBuff, "DHCP Replication Server, Bind Failed");
					logDHCPMess(logBuff, 1);
				}
				else
				{
					cfig.dhcpReplConn.port = IPPORT_DHCPS;
					cfig.dhcpReplConn.loaded = true;
					cfig.dhcpReplConn.ready = true;

					data3 op;
					memset(&token, 0, sizeof token);
					token.vp = token.dhcpp.vend_data;
					token.messsize = sizeof(dhcp_packet);

					token.remote.sin_port = htons(IPPORT_DHCPS);
					token.remote.sin_family = AF_INET;

					if (cfig.replication == 1)
						token.remote.sin_addr.s_addr = cfig.zoneServers[1];
					else if (cfig.replication == 2)
						token.remote.sin_addr.s_addr = cfig.zoneServers[0];

					token.dhcpp.header.bp_op = BOOTP_REQUEST;
					token.dhcpp.header.bp_xid = t;
					token.dhcpp.header.bp_magic_num[0] = 99;
					token.dhcpp.header.bp_magic_num[1] = 130;
					token.dhcpp.header.bp_magic_num[2] = 83;
					token.dhcpp.header.bp_magic_num[3] = 99;

					op.opt_code = DHCP_OPTION_MESSAGETYPE;
					op.size = 1;
					op.value[0] = DHCP_MESS_INFORM;
					pvdata(&token, &op);

					if (dnsService)
					{
						op.opt_code = DHCP_OPTION_DNS;
						op.size = 4;

						if (cfig.replication == 1)
							pIP(op.value, cfig.zoneServers[0]);
						else
							pIP(op.value, cfig.zoneServers[1]);

						pvdata(&token, &op);

						if (cfig.replication == 2)
						{
							op.opt_code = DHCP_OPTION_HOSTNAME;
							op.size = static_cast<MYBYTE>(strlen(cfig.servername));
							memcpy(op.value, cfig.servername, op.size);
							pvdata(&token, &op);
						}
					}

					*token.vp++ = DHCP_OPTION_END;
					token.bytes = token.vp - (MYBYTE*)token.raw;

 					if (cfig.replication == 2)
						BeginThread(sendToken, 0, NULL);
				}
			}
		}

		if (cfig.lease >= INT_MAX)
			sprintf(logBuff, "Max Lease: Infinity");
		else
			sprintf(logBuff, "Max Lease: %u (sec)", cfig.lease);

		logDHCPMess(logBuff, 1);
	}

	ConvertFromPunycode(cfig.servername, value, _countof(value) - 1);
	sprintf(logBuff,
		cfig.replication == 1 ? "Server Name: %s = %s (Primary)" :
		cfig.replication == 2 ? "Server Name: %s = %s (Secondary)" :
		"Server Name: %s = %s", cfig.servername, value);

	logDNSMess(logBuff, 1);

	ConvertFromPunycode(cfig.zone, value, _countof(value) - 1);
	if (dnsService)
	{
		if (cfig.authorized)
			sprintf(logBuff, "Authority for Zone: %s = %s (%s)", cfig.zone, value, cfig.authority);
		else
			sprintf(logBuff, "Domain Name: %s = %s", cfig.zone, value);

		logDNSMess(logBuff, 1);

		if (cfig.lease >= INT_MAX)
			sprintf(logBuff, "Default Host Expiry: Infinity");
		else
			sprintf(logBuff, "Default Host Expiry: %u (sec)", cfig.lease);

		logDNSMess(logBuff, 1);

		if (cfig.replication)
		{
			sprintf(logBuff, "Refresh: %u (sec)", cfig.refresh);
			logDNSMess(logBuff, 1);
			sprintf(logBuff, "Retry: %u (sec)", cfig.retry);
			logDNSMess(logBuff, 1);

			if (cfig.expire == UINT_MAX)
				sprintf(logBuff, "Expire: Infinity");
			else
				sprintf(logBuff, "Expire: %u (sec)", cfig.expire);

			logDNSMess(logBuff, 1);
			sprintf(logBuff, "Min: %u (sec)", cfig.minimum);
			logDNSMess(logBuff, 1);
		}

		for (int i = 0; i < MAX_COND_FORW && cfig.dnsRoutes[i].dns[0]; i++)
		{
			if (!cfig.dnsRoutes[i].dns[1])
				sprintf(logBuff, "Conditional Forwarder: %s for %s", IP2String(cfig.dnsRoutes[i].dns[0]), cfig.dnsRoutes[i].zone);
			else
				sprintf(logBuff, "Conditional Forwarder: %s, %s for %s", IP2String(cfig.dnsRoutes[i].dns[0]), IP2String(cfig.dnsRoutes[i].dns[1]), cfig.dnsRoutes[i].zone);
			logDNSMess(logBuff, 1);
		}

		for (int i = 0; i < MAX_SERVERS && network.dns[i]; i++)
		{
			sprintf(logBuff, "Default Forwarding Server: %s", IP2String(network.dns[i]));
			logDNSMess(logBuff, 1);
		}

		//char temp[128];

		for (int i = 0; i <= MAX_DNS_RANGES && cfig.dnsRanges[i].rangeStart; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "%s", "DNS Service Permitted Hosts: ");
			logPtr += sprintf(logPtr, "%s-", IP2String(htonl(cfig.dnsRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "%s", IP2String(htonl(cfig.dnsRanges[i].rangeEnd)));
			logDNSMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Domain Name: %s = %s", cfig.zone, value);
		logDNSMess(logBuff, 1);
	}

	sprintf(logBuff, "Detecting Static Interfaces..");
	logMess(logBuff, 1);

	do
	{
		closeConn();

		getInterfaces(&network, ff);

		if (network.maxFD < cfig.dhcpReplConn.sock)
			network.maxFD = cfig.dhcpReplConn.sock;

		bool ifSpecified = false;
		bool bindfailed = false;

		if (FILE *f = findSection("LISTEN_ON", ff))
		{
			int i = 0;

			for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
			{
				if(i < MAX_SERVERS)
				{
					ifSpecified = true;
					MYDWORD addr = inet_addr(raw);

					if (isIP(raw))
					{
						for (MYBYTE m = 0; ; m++)
						{
							if (m >= MAX_SERVERS || !network.staticServers[m])
							{
								if (findServer(network.allServers, MAX_SERVERS, addr))
								{
									sprintf(logBuff, "Warning: Section [LISTEN_ON], Interface %s is not Static, ignored", raw);
									logMess(logBuff, 1);
								}
								else
								{
									bindfailed = true;
									sprintf(logBuff, "Warning: Section [LISTEN_ON], Interface %s not available, ignored", raw);
									logMess(logBuff, 1);
								}
								break;
							}
							else if (network.staticServers[m] == addr)
							{
								for (MYBYTE n = 0; n < MAX_SERVERS; n++)
								{
									if (network.listenServers[n] == addr)
										break;
									else if (!network.listenServers[n])
									{
										network.listenServers[n] = network.staticServers[m];
										network.listenMasks[n] = network.staticMasks[m];
										break;
									}
								}
								break;
							}
						}
					}
					else
					{
						sprintf(logBuff, "Warning: Section [LISTEN_ON], Invalid Interface Address %s, ignored", raw);
						logMess(logBuff, 1);
					}
				}
			}
			rewind(ff);
		}

		if (!ifSpecified)
		{
			MYBYTE k = 0;

			for (MYBYTE m = 0; m < MAX_SERVERS && network.allServers[m]; m++)
			{
				for (MYBYTE n = 0; n < MAX_SERVERS; n++)
				{
					if (network.allServers[m] == network.staticServers[n])
					{
						network.listenServers[k] = network.staticServers[n];
						network.listenMasks[k] = network.staticMasks[n];
						++k;
						break;
					}
					else if (!network.staticServers[n])
					{
						sprintf(logBuff, "Warning: Interface %s is not Static, not used", IP2String(network.allServers[m]));
						logMess(logBuff, 2);
						break;
					}
				}
			}
		}

		if (dhcpService)
		{
			int i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.dhcpConn[i].sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

				if (network.dhcpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDHCPMess(logBuff, 1);
					continue;
				}

				//printf("Socket %u\n", network.dhcpConn[i].sock);

				network.dhcpConn[i].addr.sin_family = AF_INET;
				network.dhcpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
				network.dhcpConn[i].addr.sin_port = htons(IPPORT_DHCPS);

				network.dhcpConn[i].broadCastVal = TRUE;
				network.dhcpConn[i].broadCastSize = sizeof(network.dhcpConn[i].broadCastVal);
				setsockopt(network.dhcpConn[i].sock, SOL_SOCKET, SO_BROADCAST, (char*)(&network.dhcpConn[i].broadCastVal), network.dhcpConn[i].broadCastSize);

				int nRet = bind(network.dhcpConn[i].sock,
								(sockaddr*)&network.dhcpConn[i].addr,
								sizeof(struct sockaddr_in)
							   );

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					closesocket(network.dhcpConn[i].sock);
					sprintf(logBuff, "Warning: %s UDP Port 67 already in use", IP2String(network.listenServers[j]));
					logDHCPMess(logBuff, 1);
					continue;
				}

				network.dhcpConn[i].loaded = true;
				network.dhcpConn[i].ready = true;

				if (network.maxFD < network.dhcpConn[i].sock)
					network.maxFD = network.dhcpConn[i].sock;

				network.dhcpConn[i].server = network.listenServers[j];
				network.dhcpConn[i].mask = network.listenMasks[j];
				network.dhcpConn[i].port = IPPORT_DHCPS;

				++i;
			}

			network.httpConn.port = 6789;
			network.httpConn.server = inet_addr("127.0.0.1");
			network.httpConn.loaded = true;

			if (FILE *f = findSection("HTTP_INTERFACE", ff))
			{
				for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
				{
					mySplit(name, value, raw, '=');

					if (!strcasecmp(name, "HTTPServer"))
					{
						mySplit(name, value, value, ':');

						if (isIP(name))
						{
							network.httpConn.loaded = true;
							network.httpConn.server = inet_addr(name);
						}
						else
						{
							network.httpConn.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid IP Address %s, ignored", name);
							logDHCPMess(logBuff, 1);
						}

						if (value[0])
						{
							if (MYWORD port = static_cast<MYWORD>(atoi(value)))
								network.httpConn.port = port;
							else
							{
								network.httpConn.loaded = false;
								sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid port %s, ignored", value);
								logDHCPMess(logBuff, 1);
							}
						}

						if (network.httpConn.server != inet_addr("127.0.0.1") && !findServer(network.allServers, MAX_SERVERS, network.httpConn.server))
						{
							bindfailed = true;
							network.httpConn.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], %s not available, ignored", raw);
							logDHCPMess(logBuff, 1);
						}
					}
					else if (!strcasecmp(name, "HTTPClient"))
					{
						if (isIP(value))
							addServer(cfig.httpClients, 8, inet_addr(value));
						else
						{
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], invalid client IP %s, ignored", raw);
							logDHCPMess(logBuff, 1);
						}
					}
					else if (!strcasecmp(name, "HTTPTitle"))
					{
						strncpy(htmlTitle, value, _countof(htmlTitle) - 1);
						htmlTitle[_countof(htmlTitle) - 1] = 0;
					}
					else
					{
						sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], invalid entry %s, ignored", raw);
						logDHCPMess(logBuff, 1);
					}
				}
				rewind(ff);
			}

			if (htmlTitle[0] == 0)
				sprintf(htmlTitle, "Dual Server on %s", cfig.servername);

			network.httpConn.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

			if (network.httpConn.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDHCPMess(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", network.httpConn.sock);

				network.httpConn.addr.sin_family = AF_INET;
				network.httpConn.addr.sin_addr.s_addr = network.httpConn.server;
				network.httpConn.addr.sin_port = htons(network.httpConn.port);

				int nRet = bind(network.httpConn.sock,
								(sockaddr*)&network.httpConn.addr,
								sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					sprintf(logBuff, "Http Interface %s TCP Port %u not available", IP2String(network.httpConn.server), network.httpConn.port);
					logDHCPMess(logBuff, 1);
					closesocket(network.httpConn.sock);
				}
				else
				{
					nRet = listen(network.httpConn.sock, SOMAXCONN);

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						sprintf(logBuff, "%s TCP Port %u Error on Listen", IP2String(network.httpConn.server), network.httpConn.port);
						logDHCPMess(logBuff, 1);
						closesocket(network.httpConn.sock);
					}
					else
					{
						network.httpConn.loaded = true;
						network.httpConn.ready = true;

						if (network.httpConn.sock > network.maxFD)
							network.maxFD = network.httpConn.sock;
					}
				}
			}
		}

		if (dnsService)
		{
			int i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.dnsUdpConn[i].sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

				if (network.dnsUdpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMess(logBuff, 1);
					continue;
				}

				//printf("Socket %u\n", network.dnsUdpConn[i].sock);

				network.dnsUdpConn[i].addr.sin_family = AF_INET;
				network.dnsUdpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
				network.dnsUdpConn[i].addr.sin_port = htons(IPPORT_DNS);

				int nRet = bind(network.dnsUdpConn[i].sock,
								(sockaddr*)&network.dnsUdpConn[i].addr,
								sizeof(struct sockaddr_in)
							   );

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					closesocket(network.dnsUdpConn[i].sock);
					sprintf(logBuff, "Warning: %s UDP Port 53 already in use", IP2String(network.listenServers[j]));
					logDNSMess(logBuff, 1);
					continue;
				}

				network.dnsUdpConn[i].loaded = true;
				network.dnsUdpConn[i].ready = true;

				if (network.maxFD < network.dnsUdpConn[i].sock)
					network.maxFD = network.dnsUdpConn[i].sock;

				network.dnsUdpConn[i].server = network.listenServers[j];
				network.dnsUdpConn[i].port = IPPORT_DNS;

				++i;
			}

			network.forwConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (network.forwConn.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDNSMess(logBuff, 1);
			}
			else
			{
				network.forwConn.addr.sin_family = AF_INET;
				network.forwConn.server = network.dns[0];
				network.forwConn.port = IPPORT_DNS;
				//bind(network.forwConn.sock, (sockaddr*)&network.forwConn.addr, sizeof(struct sockaddr_in));

				network.forwConn.loaded = true;
				network.forwConn.ready = true;

				if (network.maxFD < network.forwConn.sock)
					network.maxFD = network.forwConn.sock;
			}

			i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.dnsTcpConn[i].sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP);

				if (network.dnsTcpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMess(logBuff, 1);
				}
				else
				{
					//printf("Socket %u\n", network.dnsTcpConn[i].sock);
					network.dnsTcpConn[i].addr.sin_family = AF_INET;
					network.dnsTcpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
					network.dnsTcpConn[i].addr.sin_port = htons(IPPORT_DNS);

					int nRet = bind(network.dnsTcpConn[i].sock,
									(sockaddr*)&network.dnsTcpConn[i].addr,
									sizeof(struct sockaddr_in));

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						closesocket(network.dnsTcpConn[i].sock);
						sprintf(logBuff, "Warning: %s TCP Port 53 already in use", IP2String(network.listenServers[j]));
						logDNSMess(logBuff, 1);
					}
					else
					{
						nRet = listen(network.dnsTcpConn[i].sock, SOMAXCONN);

						if (nRet == SOCKET_ERROR)
						{
							closesocket(network.dnsTcpConn[i].sock);
							sprintf(logBuff, "TCP Port 53 Error on Listen");
							logDNSMess(logBuff, 1);
						}
						else
						{
							network.dnsTcpConn[i].server = network.listenServers[j];
							network.dnsTcpConn[i].port = IPPORT_DNS;

							network.dnsTcpConn[i].loaded = true;
							network.dnsTcpConn[i].ready = true;

							if (network.maxFD < network.dnsTcpConn[i].sock)
								network.maxFD = network.dnsTcpConn[i].sock;

							++i;
						}
					}
				}
			}
		}

		++network.maxFD;

		if (dhcpService)
		{
			for (MYBYTE m = 0; m < MAX_SERVERS && network.allServers[m]; m++)
				lockIP(network.allServers[m]);

			for (MYBYTE m = 0; m < MAX_SERVERS && network.dns[m]; m++)
				lockIP(network.dns[m]);
		}

		if (bindfailed)
			++cfig.failureCount;
		else
			cfig.failureCount = 0;

		//printf("%i %i %i\n", network.dhcpConn[0].ready, network.dnsUdpConn[0].ready, network.dnsTcpConn[0].ready);

		if ((dhcpService && !network.dhcpConn[0].ready) || (dnsService && !(network.dnsUdpConn[0].ready && network.dnsTcpConn[0].ready)))
		{
			sprintf(logBuff, "No Static Interface ready, Waiting...");
			logMess(logBuff, 1);
			continue;
		}

		if (dhcpService && network.httpConn.ready)
		{
			sprintf(logBuff, "Lease Status URL: http://%s:%u", IP2String(network.httpConn.server), network.httpConn.port);
			logDHCPMess(logBuff, 1);
			if (FILE *f = fopen(htmFile, "wt"))
			{
				fprintf(f, "<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://%s:%u\"</head></html>", IP2String(network.httpConn.server), network.httpConn.port);
				fclose(f);
			}
		}
		else
		{
			if (FILE *f = fopen(htmFile, "wt"))
			{
				fprintf(f, "<html><body><h2>DHCP/HTTP Service is not running</h2></body></html>");
				fclose(f);
			}
		}

		for (int i = 0; i < MAX_SERVERS && network.staticServers[i]; i++)
		{
			for (MYBYTE j = 0; j < MAX_SERVERS; j++)
			{
				if (network.dhcpConn[j].server == network.staticServers[i] || network.dnsUdpConn[j].server == network.staticServers[i])
				{
					sprintf(logBuff, "Listening On: %s", IP2String(network.staticServers[i]));
					logMess(logBuff, 1);
					break;
				}
			}
		}

		network.ready = true;

	} while (detectChange());

	while (threadCount != 0)
		Sleep(100);

	fclose(ff);

	sprintf(logBuff, "Closing Network Connections...");
	logMess(logBuff, 1);
	closeConn();

	if (cfig.dhcpReplConn.ready)
		closesocket(cfig.dhcpReplConn.sock);

	freeHostMapData(dnsCache[0].begin(), dnsCache[0].end());
	freeHostMapData(dnsCache[1].begin(), dnsCache[1].end());
	freeDhcpMapData(dhcpCache.begin(), dhcpCache.end());
	freeDhcpRanges(&cfig.dhcpRanges[0], &cfig.dhcpRanges[cfig.rangeCount]);
	free(cfig.options);

	sprintf(logBuff, "Dual Server Stopped !\n");
	logMess(logBuff, 1);
	WSACleanup();

	if (serviceStatusHandle)
	{
		serviceStatus.dwControlsAccepted = 0;
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}

	return 0;
}

bool detectChange()
{
	network.ready = true;

	MYDWORD eventWait = INFINITE;

	if (cfig.failureCount)
		eventWait = 10000 << cfig.failureCount;

	OVERLAPPED overlap;
	MYDWORD ret;
	HANDLE hand = NULL;
	overlap.hEvent = WSACreateEvent();

	ret = NotifyAddrChange(&hand, &overlap);

	if (ret != NO_ERROR)
	{
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING)
		{
			//printf("NotifyAddrChange error...%d\n", error);
			return true;
		}
	}

	HANDLE events[] = { overlap.hEvent, stopServiceEvent };
	DWORD dwWait = WaitForMultipleObjects(2, events, FALSE, eventWait);
	WSACloseEvent(overlap.hEvent);

	if (dwWait != WAIT_OBJECT_0)
		return false;

	network.ready = false;

	while (network.busy)
		ServiceSleep(1000);

	char logBuff[256];
	if (cfig.failureCount)
	{
		sprintf(logBuff, "Retrying failed Listening Interfaces..");
		logMess(logBuff, 1);
	}
	else
	{
		sprintf(logBuff, "Network changed, re-detecting Static Interfaces..");
		logMess(logBuff, 1);
	}

	return true;
}

void getInterfaces(data1 *network, FILE *ff)
{
	char logBuff[256];

	memset(network, 0, sizeof(data1));

	SOCKET sd = WSASocket(PF_INET, SOCK_DGRAM, 0, 0, 0, 0);

	if (sd == INVALID_SOCKET)
		return;

	INTERFACE_INFO InterfaceList[MAX_SERVERS];
	unsigned long nBytesReturned;

	if (WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, &InterfaceList,
	             sizeof(InterfaceList), &nBytesReturned, 0, 0) == SOCKET_ERROR)
		return;

	int nNumInterfaces = nBytesReturned / sizeof(INTERFACE_INFO);

	for (int i = 0; i < nNumInterfaces; ++i)
	{
		sockaddr_in *pAddress = (sockaddr_in*)&(InterfaceList[i].iiAddress);
		u_long nFlags = InterfaceList[i].iiFlags;
		//		if (!((nFlags & IFF_POINTTOPOINT)))
		if (!((nFlags & IFF_POINTTOPOINT) || (nFlags & IFF_LOOPBACK)))
		{
			//printf("%s\n", IP2String(tempbuff, pAddress->sin_addr.S_un.S_addr));
			addServer(network->allServers, MAX_SERVERS, pAddress->sin_addr.s_addr);
		}
	}

	closesocket(sd);

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter;

	pAdapterInfo = (IP_ADAPTER_INFO*) calloc(1, sizeof(IP_ADAPTER_INFO));
	DWORD ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)calloc(1, ulOutBufLen);
	}

	if ((GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			if (!pAdapter->DhcpEnabled)
			{
				IP_ADDR_STRING *sList = &pAdapter->IpAddressList;
				while (sList)
				{
					MYDWORD iaddr = inet_addr(sList->IpAddress.String);

					if (iaddr)
					{
						for (MYBYTE k = 0; k < MAX_SERVERS; k++)
						{
							if (network->staticServers[k] == iaddr)
								break;
							else if (!network->staticServers[k])
							{
								network->staticServers[k] = iaddr;
								network->staticMasks[k] = inet_addr(sList->IpMask.String);
								break;
							}
						}
					}
					sList = sList->Next;
				}

//				IP_ADDR_STRING *rList = &pAdapter->GatewayList;
//				while (rList)
//				{
//					MYDWORD trouter = inet_addr(rList->IpAddress.String);
//					addServer(cfig.routers, trouter);
//					rList = rList->Next;
//				}
			}
			pAdapter = pAdapter->Next;
		}
		free(pAdapterInfo);
	}

	MYDWORD dservers[MAX_SERVERS];

	for (int i = 0; i < MAX_SERVERS; i++)
	{
		network->dns[i] = 0;
		dservers[i] = 0;
	}

	if (FILE *f = findSection("FORWARDING_SERVERS", ff))
	{
		char raw[512];
		int i = 0;

		for (FILE *e = f; (e = readSection(raw, e, f)) != NULL; )
		{
			if (i < MAX_SERVERS)
			{
				if (isIP(raw))
				{
					MYDWORD addr = inet_addr(raw);
					if (addServer(dservers, MAX_SERVERS, addr))
						++i;
				}
				else
				{
					sprintf(logBuff, "Section [FORWARDING_SERVERS] Invalid Entry: %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}
		rewind(ff);
	}

	FIXED_INFO *FixedInfo;
	IP_ADDR_STRING *pIPAddr;

	FixedInfo = (FIXED_INFO*)GlobalAlloc(GPTR, sizeof(FIXED_INFO));
	ulOutBufLen = sizeof(FIXED_INFO);

	if (ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &ulOutBufLen))
	{
		GlobalFree(FixedInfo);
		FixedInfo = (FIXED_INFO*)GlobalAlloc(GPTR, ulOutBufLen);
	}

	if (!GetNetworkParams(FixedInfo, &ulOutBufLen))
	{
		if (!cfig.servername[0])
		{
			WCHAR servername[MAX_COMPUTERNAME_LENGTH + 1];
			DWORD len = _countof(servername);
			if (GetComputerNameExW(ComputerNameDnsHostname, servername, &len))
			{
				ConvertToPunycode(servername, cfig.servername, sizeof cfig.servername - 1);
			}
			if (!cfig.servername[0])
			{
				strcpy(cfig.servername, FixedInfo->HostName);
			}
		}

		//printf("d=%u=%s", strlen(FixedInfo->DomainName), FixedInfo->DomainName);

		if (!cfig.zone[0])
		{
			strcpy(cfig.zone, FixedInfo->DomainName);
			cfig.zLen = static_cast<MYBYTE>(strlen(cfig.zone));
		}

		if (!cfig.zone[0] || cfig.zone[0] == NBSP)
		{
			strcpy(cfig.zone, "workgroup");
			cfig.zLen = static_cast<MYBYTE>(strlen(cfig.zone));
		}

		if (!dservers[0])
		{
			pIPAddr = &FixedInfo->DnsServerList;
			while (pIPAddr)
			{
				MYDWORD addr = inet_addr(pIPAddr->IpAddress.String);

				addServer(dservers, MAX_SERVERS, addr);
				pIPAddr = pIPAddr->Next;
			}
		}
		GlobalFree(FixedInfo);
	}

	for (int i = 0; i < MAX_SERVERS && dservers[i]; i++)
	{
		if (dnsService)
		{
			if (findServer(network->allServers, MAX_SERVERS, dservers[i]))
				continue;

			addServer(network->dns, MAX_SERVERS, dservers[i]);
		}
		else
			addServer(network->dns, MAX_SERVERS, dservers[i]);
	}
	return;
}

void updateStateFile(data7 *dhcpEntry)
{
	data8 dhcpData;
	memset(&dhcpData, 0, sizeof dhcpData);
	dhcpData.bp_hlen = 16;
	getHexValue(dhcpData.bp_chaddr, dhcpEntry->mapname, &dhcpData.bp_hlen);
	dhcpData.ip = dhcpEntry->ip;
	dhcpData.expiry = dhcpEntry->expiry;
	dhcpData.local = dhcpEntry->local;

	if (dhcpEntry->hostname)
		strcpy(dhcpData.hostname, dhcpEntry->hostname);

	if (dhcpEntry->dhcpInd)
	{
		dhcpData.dhcpInd = dhcpEntry->dhcpInd;
		if (FILE *f = fopen(leaFile, "rb+"))
		{
			if (fseek(f, (dhcpData.dhcpInd - 1) * sizeof(data8), SEEK_SET) >= 0)
				fwrite(&dhcpData, sizeof(data8), 1, f);
			fclose(f);
		}
	}
	else
	{
		++cfig.dhcpInd;
		dhcpEntry->dhcpInd = cfig.dhcpInd;
		dhcpData.dhcpInd = cfig.dhcpInd;
		if (FILE *f = fopen(leaFile, "ab"))
		{
			fwrite(&dhcpData, sizeof(data8), 1, f);
			fclose(f);
		}
	}
}

char *hostname2utf8(data9 *req, char *utf8)
{
	MYWORD codepage = cfig.codepage;

	if (data7 *dhcpEntry = findDHCPEntry(req->chaddr))
		if (MYWORD clientcp = dhcpEntry->codepage)
			codepage = clientcp;

	WCHAR utf16[512];
	char *hostname = req->hostname;
	int cch = MultiByteToWideChar(codepage, 0, hostname, -1, utf16, 512);
	if (cch >= 0 && cch < _countof(utf16))
	{
		cch = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, 512, NULL, NULL);
		if (cch >= 0 && cch < 512)
			hostname = utf8;
	}
	return hostname;
}

bool gdmess(data9 *req, MYBYTE sockInd)
{
	char logBuff[256];
	//debug("gdmess");
	memset(req, 0, sizeof(data9));
	req->sockInd = sockInd;
	req->sockLen = sizeof(req->remote);

	req->bytes = recvfrom(network.dhcpConn[req->sockInd].sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	//printf("IP=%s bytes=%u\n", IP2String(tempbuff,req->remote.sin_addr.s_addr), req->bytes);

	if (req->bytes <= 0 || req->dhcpp.header.bp_op != BOOTP_REQUEST)
		return false;

	hex2String(req->chaddr, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);

	MYBYTE *raw = req->dhcpp.vend_data;
	MYBYTE *rawEnd = raw + (req->bytes - sizeof(dhcp_header));

	for (; raw < rawEnd && *raw != DHCP_OPTION_END;)
	{
		data3 *const op = reinterpret_cast<data3*>(raw);
		//printf("OpCode=%u,MessType=%u\n", op->opt_code, op->value[0]);

		switch (op->opt_code)
		{
		case DHCP_OPTION_PAD:
			++raw;
			continue;

		case DHCP_OPTION_PARAMREQLIST:
			for (int ix = 0; ix < op->size; ix++)
				req->paramreqlist[op->value[ix]] = 1;
			break;

		case DHCP_OPTION_MESSAGETYPE:
			req->req_type = op->value[0];
			break;

		case DHCP_OPTION_SERVERID:
			req->server = fIP(op->value);
			break;

		case DHCP_OPTION_IPADDRLEASE:
			req->lease = fULong(op->value);
			break;

		case DHCP_OPTION_MAXDHCPMSGSIZE:
			req->messsize = fUShort(op->value);
			break;

		case DHCP_OPTION_REQUESTEDIPADDR:
			req->reqIP = fIP(op->value);
			break;

		case DHCP_OPTION_CLIENTFQDN:
			// TODO: Are there really clients which are really capable of
			// advertising their fully qualified domain name as unicode?
			break;

		case DHCP_OPTION_HOSTNAME:
			// Don't assume the received string to be zero-terminated
			if (op->size)
			{
				memcpy(req->hostname, op->value, op->size);
				if (!strcasecmp(req->hostname, "(none)") || !strcasecmp(req->hostname, cfig.servername))
					*req->hostname = '\0';
				if (char *ptr = strchr(req->hostname, '.'))
					*ptr = 0;
			}
			break;

		case DHCP_OPTION_VENDORCLASSID:
			memcpy(&req->vendClass, op, op->size + 2);
			break;

		case DHCP_OPTION_USERCLASS:
			memcpy(&req->userClass, op, op->size + 2);
			break;

		case DHCP_OPTION_RELAYAGENTINFO:
			memcpy(&req->agentOption, op, op->size + 2);
			break;

		case DHCP_OPTION_CLIENTID:
			memcpy(&req->clientId, op, op->size + 2);
			break;

		case DHCP_OPTION_SUBNETSELECTION:
			memcpy(&req->subnet, op, op->size + 2);
			req->subnetIP = fULong(op->value);
			break;

		case DHCP_OPTION_DNS:
			req->dns = fULong(op->value);
			break;

		case DHCP_OPTION_REBINDINGTIME:
			req->rebind = fULong(op->value);
			break;
		}
		raw += 2;
		raw += op->size;
	}

	if (!req->subnetIP)
	{
		if (req->dhcpp.header.bp_giaddr)
			req->subnetIP = req->dhcpp.header.bp_giaddr;
		else
			req->subnetIP = network.dhcpConn[req->sockInd].server;
	}

	if (!req->messsize)
	{
		if (req->req_type == DHCP_MESS_NONE)
			req->messsize = static_cast<MYWORD>(req->bytes);
		else
			req->messsize = sizeof(dhcp_packet);
	}

	if ((req->req_type == 1 || req->req_type == 3) && cfig.dhcpLogLevel == 3)
	{
		logDebug(req);
	}

	if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		if (req->req_type == DHCP_MESS_NONE)
		{
			if (req->dhcpp.header.bp_giaddr)
			{
				sprintf(logBuff,
					"BOOTPREQUEST for %s (%s) from RelayAgent %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_giaddr));
			}
			else
			{
				sprintf(logBuff,
					"BOOTPREQUEST for %s (%s) from interface %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(network.dhcpConn[req->sockInd].server));
			}
			logDHCPMess(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_DISCOVER)
		{
			if (req->dhcpp.header.bp_giaddr)
			{
				sprintf(logBuff,
					"DHCPDISCOVER for %s (%s) from RelayAgent %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_giaddr));
			}
			else
			{
				sprintf(logBuff,
					"DHCPDISCOVER for %s (%s) from interface %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(network.dhcpConn[req->sockInd].server));
			}
			logDHCPMess(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_REQUEST)
		{
			if (req->dhcpp.header.bp_giaddr)
			{
				sprintf(logBuff,
					"DHCPREQUEST for %s (%s) from RelayAgent %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(req->dhcpp.header.bp_giaddr));
			}
			else
			{
				sprintf(logBuff,
					"DHCPREQUEST for %s (%s) from interface %s received",
					req->chaddr, hostname2utf8(req),
					IP2String(network.dhcpConn[req->sockInd].server));
			}
			logDHCPMess(logBuff, 2);
		}
	}

	req->vp = req->dhcpp.vend_data;
	memset(req->vp, 0, sizeof(dhcp_packet) - sizeof(dhcp_header));
	//printf("end bytes=%u\n", req->bytes);
	return true;
}

void debug(const char *mess)
{
	logMess(mess, 1);
}

void logDebug(const data9 *req)
{
	char localBuff[1024];
	char path[_MAX_PATH];
	genHostName(localBuff, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);
	sprintf(path, cliFile, localBuff);
	if (FILE *f = fopen(path, "at"))
	{
		tm *ttm = localtime(&t);
		strftime(path, sizeof path, "%d-%m-%y %X", ttm);

		char *s = localBuff;
		s += sprintf(s, path);
		s += sprintf(s, " SourceMac=%s", req->chaddr);
		s += sprintf(s, " ClientIP=%s", IP2String(req->dhcpp.header.bp_ciaddr));
		s += sprintf(s, " SourceIP=%s", IP2String(req->remote.sin_addr.s_addr));
		s += sprintf(s, " RelayAgent=%s", IP2String(req->dhcpp.header.bp_giaddr));
		fprintf(f, "%s\n", localBuff);

		const MYBYTE *raw = req->dhcpp.vend_data;
		const MYBYTE *rawEnd = raw + (req->bytes - sizeof(dhcp_header));

		for (; raw < rawEnd && *raw != DHCP_OPTION_END;)
		{
			data3 *op = (data3*)raw;

			BYTE opType = 2;
			char opName[40] = "Private";

			for (MYBYTE i = 0; i < _countof(opData); i++)
			{
				if (op->opt_code == opData[i].opTag)
				{
					strcpy(opName, opData[i].opName);
					opType = opData[i].opType;
					break;
				}
			}

			s = localBuff;
			s += sprintf(s, "\t%d\t%s\t", op->opt_code, opName);
			//printf("OpCode=%u,OpLen=%u,OpType=%u\n", op->opt_code, op->size, opType);

			switch (opType)
			{
			case 1:
				memcpy(s, op->value, op->size);
				s[op->size] = 0;
				break;
			case 3:
				for (BYTE x = 4; x <= op->size; x += 4)
				{
					s += sprintf(s, "%s,", IP2String(fIP(op->value)));
				}
				break;
			case 4:
				sprintf(s, "%u", fULong(op->value));
				break;
			case 5:
				sprintf(s, "%u", fUShort(op->value));
				break;
			case 6:
			case 7:
				sprintf(s, "%u", op->value[0]);
				break;
			default:
				if (op->size == 1)
					sprintf(s, "%u", op->value[0]);
				else
					hex2String(s, op->value, op->size);
				break;
			}

			fprintf(f, "%s\n", localBuff);
			raw += 2;
			raw += op->size;
		}
		fclose(f);
	}
}

void logMessVerbatim(const char *mess)
{
	WCHAR tempBuff[512];
	int cch = MultiByteToWideChar(CP_UTF8, 0, mess, -1, tempBuff, _countof(tempBuff));
	if (cch >= 0)
	{
		if (cch >= _countof(tempBuff))
			cch = _countof(tempBuff) - 1;
		tempBuff[cch++] = L'\n';
		DWORD dwcch;
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), tempBuff, cch, &dwcch, NULL);
	}
}

void logMessArchived(const char *mess)
{
	tm *ttm = localtime(&t);
	char path[_MAX_PATH];
	strftime(path, sizeof path, logFile, ttm);

	if (strcmp(cfig.logFileName, path))
	{
		if (cfig.logFileName[0])
		{
			if (FILE *f = fopen(cfig.logFileName, "at"))
			{
				fprintf(f, "Logging Continued on file %s\n", path);
				fclose(f);
			}

			strcpy(cfig.logFileName, path);

			if (FILE *f = fopen(cfig.logFileName, "at"))
			{
				fprintf(f, "%s\n\n", sVersion);
				fclose(f);
			}
		}

		strcpy(cfig.logFileName, path);
		WritePrivateProfileString("InternetShortcut", "URL", path, lnkFile);
		WritePrivateProfileString("InternetShortcut", "IconIndex", "0", lnkFile);
		WritePrivateProfileString("InternetShortcut", "IconFile", path, lnkFile);
	}

	if (FILE *f = fopen(cfig.logFileName, "at"))
	{
		strftime(path, sizeof path, "%d-%b-%y %X", ttm);
		fprintf(f, "[%s] %s\n", path, mess);
		fclose(f);
	}
	else
	{
		cfig.dnsLogLevel = 0;
		cfig.dhcpLogLevel = 0;
	}
}

void logMess(const char *mess, MYBYTE logLevel)
{
	bool archived = logLevel <= cfig.dnsLogLevel || logLevel <= cfig.dhcpLogLevel;
	if (archived || verbatim)
	{
		WaitForSingleObject(lEvent, INFINITE);
		if (archived)
			logMessArchived(mess);
		if (verbatim)
			logMessVerbatim(mess);
		SetEvent(lEvent);
	}
}

void logDHCPMess(const char *mess, MYBYTE logLevel)
{
	if (logLevel <= cfig.dhcpLogLevel || verbatim)
		logMess(mess, logLevel);
}

void logDNSMess(const char *mess, MYBYTE logLevel)
{
	if (logLevel <= cfig.dnsLogLevel || verbatim)
		logMess(mess, logLevel);
}

void logDNSMess(data5 *req, const char *logBuff, MYBYTE logLevel)
{
	if (logLevel <= cfig.dnsLogLevel || verbatim)
	{
		char mess[512];
		sprintf(mess, "Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		logMess(mess, logLevel);
	}
}

void logTCPMess(data5 *req, const char *logBuff, MYBYTE logLevel)
{
	if (logLevel <= cfig.dnsLogLevel || verbatim)
	{
		char mess[512];
		sprintf(mess, "TCP Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		logMess(mess, logLevel);
	}
}

data7 *createCache(data71 *lump)
{
	size_t dataSize = sizeof(data7) + strlen(lump->mapname) + 1;

	switch (lump->dataType)
	{
	case DHCP_ENTRY:
		dataSize += lump->optionSize;
		if (data7 *cache = (data7*)calloc(1, dataSize))
		{
			MYBYTE *dp = cache->data();
			cache->mapname = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			dp += strlen(cache->mapname) + 1;

			if (lump->optionSize >= 5)
			{
				cache->options = dp;
				memcpy(cache->options, lump->options, lump->optionSize);
			}

			if (lump->hostname && lump->hostname[0])
				cache->hostname = strdup(lump->hostname);

			return cache;
		}
		break;

	case QUEUE:
		dataSize += strlen(lump->query) + 1;
		dataSize += sizeof(SOCKADDR_IN);
		if (data7 *cache = (data7*)calloc(1, dataSize))
		{
			cache->dataType = lump->dataType;
			MYBYTE *dp = cache->data();
			cache->mapname = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			dp += strlen(cache->mapname) + 1;
			cache->query = (char*)dp;
			strcpy(cache->query, lump->query);
			dp += strlen(cache->query) + 1;
			cache->addr = (SOCKADDR_IN*)dp;
			memcpy(cache->addr, lump->addr, sizeof(SOCKADDR_IN));
			return cache;
		}
		break;

	case LOCAL_PTR_AUTH:
	case LOCAL_PTR_NAUTH:
	case LOCALHOST_PTR:
	case SERVER_PTR_AUTH:
	case SERVER_PTR_NAUTH:
	case STATIC_PTR_AUTH:
	case STATIC_PTR_NAUTH:
	case LOCAL_CNAME:
	case EXT_CNAME:
		dataSize += strlen(lump->hostname) + 1;
		if (data7 *cache = (data7*)calloc(1, dataSize))
		{
			cache->dataType = lump->dataType;
			MYBYTE *dp = cache->data();
			cache->mapname = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			dp += strlen(cache->mapname) + 1;
			cache->hostname = (char*)dp;
			strcpy(cache->hostname, lump->hostname);
			return cache;
		}
		break;

	case CACHED:
		dataSize += lump->bytes;
		if (data7 *cache = (data7*)calloc(1, dataSize))
		{
			cache->dataType = lump->dataType;
			MYBYTE *dp = cache->data();
			cache->mapname = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			dp += strlen(cache->mapname) + 1;
			cache->response = dp;
			cache->bytes = lump->bytes;
			memcpy(cache->response, lump->response, cache->bytes);
			return cache;
		}
		break;

	default:
		if (data7 *cache = (data7*)calloc(1, dataSize))
		{
			cache->dataType = lump->dataType;
			cache->mapname = (char*)cache->data();
			strcpy(cache->mapname, lump->mapname);
			return cache;
		}
		break;
	}
	return NULL;
}
