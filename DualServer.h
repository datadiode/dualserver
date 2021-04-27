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
//This file defines all structures and constants
//for both DHCP and DNS Servers

extern const char sVersion[];

#define MYBYTE unsigned char
#define MYWORD unsigned short
#define MYDWORD unsigned int

#ifdef _MSC_VER
#	define strdup _strdup
#	define strcasecmp _stricmp
#	pragma comment(lib, "ws2_32.lib")
#	pragma comment(lib, "iphlpapi.lib")
#endif

#include "EASTL/string.h"
#include "EASTL/map.h"

using namespace eastl;

uintptr_t BeginThread(void (__cdecl *)(void *), unsigned, void *);
void EndThread();

#define MAX_SERVERS			125
#define MAX_DHCP_RANGES		125
#define MAX_DNS_RANGES		32
#define MAX_RANGE_SETS		125
#define MAX_RANGE_FILTERS	32
#define MAX_COND_FORW		125
#define MAX_TCP_CLIENTS		16
#define MAX_WILD_HOSTS		125

#define RCODE_NOERROR		0
#define RCODE_FORMATERROR	1
#define RCODE_SERVERFAIL	2
#define RCODE_NAMEERROR		3
#define RCODE_NOTIMPL		4
#define RCODE_REFUSED		5
#define RCODE_YXDOMAIN		6
#define RCODE_YXRRSET		7
#define RCODE_NXRRSET		8
#define RCODE_NOTAUTH		9
#define RCODE_NOTZONE		10

#define OPCODE_STANDARD_QUERY	0
#define OPCODE_INVERSE_QUERY	1
#define OPCODE_SRVR_STAT_REQ	2
#define OPCODE_NOTIFY			4
#define OPCODE_DYNAMIC_UPDATE	5

#define DNS_TYPE_A		1
#define DNS_TYPE_NS		2
#define DNS_TYPE_MD		3
#define DNS_TYPE_MF		4
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_MB		7
#define DNS_TYPE_MG		8
#define DNS_TYPE_MR		9
#define DNS_TYPE_NULL	10
#define DNS_TYPE_WKS	11
#define DNS_TYPE_PTR	12
#define DNS_TYPE_HINFO	13
#define DNS_TYPE_MINFO	14
#define DNS_TYPE_MX		15
#define DNS_TYPE_TXT	16
#define DNS_TYPE_AAAA	28
#define DNS_TYPE_IXFR	251
#define DNS_TYPE_AXFR	252
#define DNS_TYPE_MAILB	253
#define DNS_TYPE_MAILA	254
#define DNS_TYPE_ANY	255

#define DNS_CLASS_IN	1
#define DNS_CLASS_CS	2
#define DNS_CLASS_CH	3
#define DNS_CLASS_HS	4
#define DNS_CLASS_NONE	254
#define DNS_CLASS_ANY	255

#define IPPORT_DNS 53

struct dnsHeader
{
	unsigned xid: 16;	//query identification number
	/* byte boundry */
	unsigned rd: 1;		//recursion desired
	unsigned tc: 1;		//truncated message
	unsigned aa: 1;		//authoritive answer
	unsigned opcode: 4;	//option code
	unsigned qr: 1;		//response flag
	/* byte boundry */
	unsigned rcode: 4;	//response code
	unsigned cd: 1;		//checking disabled by resolver
	unsigned at: 1;		//authentic data from named
	unsigned unused: 1;	//unused
	unsigned ra: 1;		//recursion available
	/* byte boundry */
	unsigned qdcount: 16;	//number of question entries
	unsigned ancount: 16;	//number of answer entries
	unsigned nscount: 16;	//number of authority entries
	unsigned adcount: 16;	//number of additional entries
	char *data()
	{
		return reinterpret_cast<char *>(this + 1);
	}
};

struct data6
{
	char zone[256];
	MYWORD zLen;
	MYDWORD dns[2];
	MYBYTE currentDNS;
	MYBYTE lastDNS;
};

struct data16
{
	char wildcard[256];
	MYDWORD ip;
};

struct data7 //cache
{
	char *mapname;
	time_t expiry;
	MYWORD codepage;
	union
	{
		struct
		{
			MYBYTE reserved;
			MYBYTE dataType;
			MYBYTE sockInd;
			MYBYTE dnsIndex;
		};
		struct
		{
			unsigned fixed: 1;
			unsigned local: 1;
			unsigned display: 1;
			unsigned reserved1: 5;
			char rangeInd;
			MYWORD dhcpInd;
		};
	};
	union
	{
		int bytes;
		MYDWORD ip;
	};
	union
	{
		SOCKADDR_IN *addr;
		MYBYTE *options;
	};
	union
	{
		MYBYTE *response;
		char *hostname;
		char *query;
	};
	MYBYTE *data()
	{
		return reinterpret_cast<MYBYTE *>(this + 1);
	}
};

struct data71 //Lump
{
	char *mapname;
	MYBYTE *response;
	char *hostname;
	char *query;
	SOCKADDR_IN *addr;
	MYBYTE *options;
	MYWORD optionSize;
	int bytes;
	MYBYTE dataType;
};

typedef map<string, data7*> dhcpMap;
typedef multimap<string, data7*> hostMap;
typedef multimap<time_t, data7*> expiryMap;

struct data5 //dns request
{
	dnsHeader *dnsp;
	char *dp;
	char raw[2048];
	char temp[2048];
	char query[256];
	char cname[256];
	char mapname[256];
	hostMap::iterator iterBegin;
	SOCKET sock;
	SOCKADDR_IN addr;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	linger ling;
	int bytes;
	MYWORD qLen;
	MYWORD qtype;
	MYWORD qclass;
	MYBYTE dnType;
	MYBYTE sockInd;
	MYBYTE dnsIndex;
	MYBYTE respType;

	int send(SOCKET sock, int flags = 0) const
	{
		return ::send(sock, raw, bytes, flags);
	}
	int sendto(SOCKET sock, const SOCKADDR_IN &sa, int flags = 0) const
	{
		return ::sendto(sock, raw, bytes, flags,
			reinterpret_cast<const sockaddr *>(&sa), sizeof sa);
	}
	int recvfrom(SOCKET sock, int flags = 0)
	{
		memset(this, 0, sizeof *this);
		sockLen = sizeof remote;
		return bytes = ::recvfrom(sock, raw, sizeof raw, flags,
			reinterpret_cast<sockaddr *>(&remote), &sockLen);
	}
};

enum
{
	NONE,
	DHCP_ENTRY,
	LOCAL_A,
	LOCAL_PTR_AUTH,
	LOCAL_PTR_NAUTH,
	LOCALHOST_A,
	LOCALHOST_PTR,
	SERVER_A_AUTH,
	SERVER_PTR_AUTH,
	SERVER_A_NAUTH,
	SERVER_PTR_NAUTH,
	LOCAL_CNAME,
	EXT_CNAME,
	STATIC_A_AUTH,
	STATIC_PTR_AUTH,
	STATIC_A_NAUTH,
	STATIC_PTR_NAUTH,
	NS,
	SOA,
	AXFR,
	CACHED,
	NON_CACHED,
	QUEUE,
	DNS_CHECK,
	DNTYPE_IP,
	DNTYPE_HOSTNAME,
	DNTYPE_A_EXT,
	DNTYPE_A_BARE,
	DNTYPE_A_LOCAL,
	DNTYPE_A_ZONE,
	DNTYPE_P_EXT,
	DNTYPE_P_LOCAL,
	DNTYPE_P_ZONE,
	DNTYPE_A_SUBZONE,
	DNTYPE_P_SUBZONE,
	DNTYPE_CHILDZONE
};

struct data12 //dns range
{
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
};

struct data11 //mx
{
	char hostname[256];
	MYWORD pref;
};

struct ConnType
{
	SOCKET sock;
	SOCKADDR_IN addr;
	SOCKADDR_IN remote;
	MYDWORD server;
	MYWORD port;
	bool loaded;
	bool ready;
};

#define BOOTP_REQUEST	1
#define BOOTP_REPLY		2

#define DHCP_MESS_NONE		0
#define DHCP_MESS_DISCOVER	1
#define DHCP_MESS_OFFER		2
#define DHCP_MESS_REQUEST	3
#define DHCP_MESS_DECLINE	4
#define DHCP_MESS_ACK		5
#define DHCP_MESS_NAK		6
#define DHCP_MESS_RELEASE	7
#define DHCP_MESS_INFORM	8


// DHCP OPTIONS
#define DHCP_OPTION_PAD						0
#define DHCP_OPTION_NETMASK					1
#define DHCP_OPTION_TIMEOFFSET				2
#define DHCP_OPTION_ROUTER					3
#define DHCP_OPTION_TIMESERVER				4
#define DHCP_OPTION_NAMESERVER				5
#define DHCP_OPTION_DNS						6
#define DHCP_OPTION_LOGSERVER				7
#define DHCP_OPTION_COOKIESERVER			8
#define DHCP_OPTION_LPRSERVER				9
#define DHCP_OPTION_IMPRESSSERVER			10
#define DHCP_OPTION_RESLOCSERVER			11
#define DHCP_OPTION_HOSTNAME				12
#define DHCP_OPTION_BOOTFILESIZE			13
#define DHCP_OPTION_MERITDUMP				14
#define DHCP_OPTION_DOMAINNAME				15
#define DHCP_OPTION_SWAPSERVER				16
#define DHCP_OPTION_ROOTPATH				17
#define DHCP_OPTION_EXTSPATH				18
#define DHCP_OPTION_IPFORWARD				19
#define DHCP_OPTION_NONLOCALSR				20
#define DHCP_OPTION_POLICYFILTER			21
#define DHCP_OPTION_MAXREASSEMBLE			22
#define DHCP_OPTION_IPTTL					23
#define DHCP_OPTION_PATHMTUAGING			24
#define DHCP_OPTION_PATHMTUPLATEAU			25
#define DHCP_OPTION_INTERFACEMTU			26
#define DHCP_OPTION_SUBNETSLOCAL			27
#define DHCP_OPTION_BCASTADDRESS			28
#define DHCP_OPTION_MASKDISCOVERY			29
#define DHCP_OPTION_MASKSUPPLIER			30
#define DHCP_OPTION_ROUTERDISCOVERY			31
#define DHCP_OPTION_ROUTERSOLIC				32
#define DHCP_OPTION_STATICROUTE				33
#define DHCP_OPTION_TRAILERENCAPS			34
#define DHCP_OPTION_ARPTIMEOUT				35
#define DHCP_OPTION_ETHERNETENCAPS			36
#define DHCP_OPTION_TCPTTL					37
#define DHCP_OPTION_TCPKEEPALIVEINT			38
#define DHCP_OPTION_TCPKEEPALIVEGRBG		39
#define DHCP_OPTION_NISDOMAIN				40
#define DHCP_OPTION_NISSERVERS				41
#define DHCP_OPTION_NTPSERVERS				42
#define DHCP_OPTION_VENDORSPECIFIC			43
#define DHCP_OPTION_NETBIOSNAMESERV			44
#define DHCP_OPTION_NETBIOSDGDIST			45
#define DHCP_OPTION_NETBIOSNODETYPE			46
#define DHCP_OPTION_NETBIOSSCOPE			47
#define DHCP_OPTION_X11FONTS				48
#define DHCP_OPTION_X11DISPLAYMNGR			49
#define DHCP_OPTION_REQUESTEDIPADDR			50
#define DHCP_OPTION_IPADDRLEASE				51
#define DHCP_OPTION_OVERLOAD				52
#define DHCP_OPTION_MESSAGETYPE				53
#define DHCP_OPTION_SERVERID				54
#define DHCP_OPTION_PARAMREQLIST			55
#define DHCP_OPTION_MESSAGE					56
#define DHCP_OPTION_MAXDHCPMSGSIZE			57
#define DHCP_OPTION_RENEWALTIME				58
#define DHCP_OPTION_REBINDINGTIME			59
#define DHCP_OPTION_VENDORCLASSID			60
#define DHCP_OPTION_CLIENTID				61
#define DHCP_OPTION_NETWARE_IPDOMAIN		62
#define DHCP_OPTION_NETWARE_IPOPTION		63
#define DHCP_OPTION_NISPLUSDOMAIN			64
#define DHCP_OPTION_NISPLUSSERVERS			65
#define DHCP_OPTION_TFTPSERVER				66
#define DHCP_OPTION_BOOTFILE				67
#define DHCP_OPTION_MOBILEIPHOME			68
#define DHCP_OPTION_SMTPSERVER				69
#define DHCP_OPTION_POP3SERVER				70
#define DHCP_OPTION_NNTPSERVER				71
#define DHCP_OPTION_WWWSERVER				72
#define DHCP_OPTION_FINGERSERVER			73
#define DHCP_OPTION_IRCSERVER				74
#define DHCP_OPTION_STSERVER				75
#define DHCP_OPTION_STDASERVER				76
#define DHCP_OPTION_USERCLASS				77
#define DHCP_OPTION_SLPDIRAGENT				78
#define DHCP_OPTION_SLPDIRSCOPE				79
#define DHCP_OPTION_CLIENTFQDN				81
#define DHCP_OPTION_RELAYAGENTINFO			82
#define DHCP_OPTION_I_SNS					83
#define DHCP_OPTION_NDSSERVERS				85
#define DHCP_OPTION_NDSTREENAME				86
#define DHCP_OPTION_NDSCONTEXT				87
#define DHCP_OPTION_AUTHENTICATION			90
#define DHCP_OPTION_CLIENTSYSTEM			93
#define DHCP_OPTION_CLIENTNDI				94
#define DHCP_OPTION_LDAP					95
#define DHCP_OPTION_UUID_GUID				97
#define DHCP_OPTION_USER_AUTH				98
#define DHCP_OPTION_P_CODE					100
#define DHCP_OPTION_T_CODE					101
#define DHCP_OPTION_NETINFOADDRESS			112
#define DHCP_OPTION_NETINFOTAG				113
#define DHCP_OPTION_URL						114
#define DHCP_OPTION_AUTO_CONFIG				116
#define DHCP_OPTION_NAMESERVICESEARCH		117
#define DHCP_OPTION_SUBNETSELECTION			118
#define DHCP_OPTION_DOMAINSEARCH			119
#define DHCP_OPTION_SIPSERVERSDHCP			120
#define DHCP_OPTION_CLASSLESSSTATICROUTE	121
#define DHCP_OPTION_CCC						122
#define DHCP_OPTION_GEOCONF					123
#define DHCP_OPTION_V_IVENDORCLASS			124
#define DHCP_OPTION_V_IVENDOR_SPECIFIC		125
#define DHCP_OPTION_TFPTSERVERIPADDRESS		128
#define DHCP_OPTION_CALLSERVERIPADDRESS		129
#define DHCP_OPTION_DISCRIMINATIONSTRING	130
#define DHCP_OPTION_REMOTESTATISTICSSERVER	131
#define DHCP_OPTION_802_1PVLANID			132
#define DHCP_OPTION_802_1QL2PRIORITY		133
#define DHCP_OPTION_DIFFSERVCODEPOINT		134
#define DHCP_OPTION_HTTPPROXYFORPHONE_SPEC	135
#define DHCP_OPTION_SERIAL					252
#define DHCP_OPTION_BP_FILE					253
#define DHCP_OPTION_NEXTSERVER				254
#define DHCP_OPTION_END						255

#define IPPORT_DHCPS	67
#define IPPORT_DHCPC	68

struct data3
{
	MYBYTE opt_code;
	MYBYTE size;
	MYBYTE value[256];
};

struct dhcp_header
{
	static const MYWORD messsize = 1024;
	MYBYTE bp_op;
	MYBYTE bp_htype;
	MYBYTE bp_hlen;
	MYBYTE bp_hops;
	MYDWORD bp_xid;
	struct
	{
		unsigned bp_secs:16;
		unsigned bp_spare:7;
		unsigned bp_broadcast:1;
		unsigned bp_spare1:8;
	};
	MYDWORD bp_ciaddr;
	MYDWORD bp_yiaddr;
	MYDWORD bp_siaddr;
	MYDWORD bp_giaddr;
	MYBYTE bp_chaddr[16];
	char bp_sname[64];
	MYBYTE bp_file[128];
	MYBYTE bp_magic_num[4];

	MYBYTE *vend_data()
	{
		return reinterpret_cast<MYBYTE *>(this + 1);
	}
};

struct data13 //dhcp range
{
	MYBYTE rangeSetInd;
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
	MYDWORD mask;
	MYBYTE *options;
	time_t *expiry;
	data7 **dhcpEntry;
};

struct data14 //rangeSet
{
	MYBYTE active;
	MYBYTE *macStart[MAX_RANGE_FILTERS];
	MYBYTE *macEnd[MAX_RANGE_FILTERS];
	MYBYTE macSize[MAX_RANGE_FILTERS];
	MYBYTE *vendClass[MAX_RANGE_FILTERS];
	MYBYTE vendClassSize[MAX_RANGE_FILTERS];
	MYBYTE *userClass[MAX_RANGE_FILTERS];
	MYBYTE userClassSize[MAX_RANGE_FILTERS];
	MYDWORD subnetIP[MAX_RANGE_FILTERS];
	MYDWORD targetIP;
};

struct data17
{
	MYBYTE macArray[MAX_RANGE_SETS];
	MYBYTE vendArray[MAX_RANGE_SETS];
	MYBYTE userArray[MAX_RANGE_SETS];
	MYBYTE subnetArray[MAX_RANGE_SETS];
	bool macFound;
	bool vendFound;
	bool userFound;
	bool subnetFound;
};

struct data20
{
	MYBYTE options[dhcp_header::messsize];
	MYWORD optionSize;
	MYWORD codepage;
	MYDWORD ip;
	MYDWORD mask;
	MYBYTE rangeSetInd;
};

struct data9 //dhcpRequst
{
	MYDWORD lease;
	union
	{
		char raw[dhcp_header::messsize];
		dhcp_header dhcpp;
	};
	char hostname[256];
	char chaddr[64];
	MYDWORD server;
	MYDWORD reqIP;
	int bytes;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	MYWORD messsize;
	MYBYTE *vp;
	data7 *dhcpEntry;
	data3 agentOption;
	data3 clientId;
	data3 subnet;
	data3 vendClass;
	data3 userClass;
	MYDWORD subnetIP;
	MYDWORD targetIP;
	MYDWORD rebind;
	MYDWORD dns;
	MYBYTE paramreqlist[256];
	MYBYTE opAdded[256];
	MYBYTE req_type;
	MYBYTE resp_type;
	MYBYTE sockInd;

	int sendto(SOCKET sock, const SOCKADDR_IN &sa, int flags = 0) const
	{
		return ::sendto(sock, raw, bytes, flags,
			reinterpret_cast<const sockaddr *>(&sa), sizeof sa);
	}
	int recvfrom(SOCKET sock, int flags = 0)
	{
		memset(this, 0, sizeof *this);
		sockLen = sizeof remote;
		return bytes = ::recvfrom(sock, raw, sizeof raw, flags,
			reinterpret_cast<sockaddr *>(&remote), &sockLen);
	}
};

struct DhcpConnType
{
	SOCKET sock;
	SOCKADDR_IN addr;
	MYDWORD server;
	MYWORD port;
	MYDWORD mask;
	int broadCastVal;
	int broadCastSize;
	int reUseVal;
	int reUseSize;
	int donotRouteVal;
	int donotRouteSize;
	bool loaded;
	bool ready;
};

struct data4
{
	char opName[40];
	MYBYTE opTag;
	MYBYTE opType;
	bool permitted;
};

struct data15
{
	union
	{
		//MYDWORD ip;
		unsigned ip:32;
		MYBYTE octate[4];
	};
};

struct data8 //client
{
	MYWORD dhcpInd;
	MYBYTE bp_hlen;
	MYBYTE local;
	MYDWORD source;
	MYDWORD ip;
	time_t expiry;
	MYBYTE bp_chaddr[16];
	char hostname[64];
};

struct data1
{
	DhcpConnType dhcpConn[MAX_SERVERS];
	ConnType dnsUdpConn[MAX_SERVERS];
	ConnType forwConn;
	ConnType dnsTcpConn[MAX_SERVERS];
	ConnType httpConn;
	ConnType telnetConn;
	MYDWORD allServers[MAX_SERVERS];
	MYDWORD listenServers[MAX_SERVERS];
	MYDWORD listenMasks[MAX_SERVERS];
	MYDWORD staticServers[MAX_SERVERS];
	MYDWORD staticMasks[MAX_SERVERS];
	MYDWORD dns[MAX_SERVERS];
	char encoding[MAX_SERVERS]; // (u)tf-8 or (p)unycode
	SOCKET maxFD;
	MYBYTE currentDNS;
	bool ready;
	bool busy;
	bool bindfailed;
};

struct data2
{
	WSADATA wsaData;
	char zone[256];
	MYBYTE zLen;
	char authoritySmall[256];
	char authority[256];
	MYBYTE aLen;
	CHAR nsA[256];
	CHAR nsP[256];
	CHAR nsABare[256];
	CHAR nsPBare[256];
	char servername[128];
	char servername_fqn[256];
	data11 mxServers[2][5];
	MYBYTE mxCount[2];
	ConnType dhcpReplConn;
	MYWORD codepage;
	MYDWORD mask;
	MYDWORD lease;
	MYDWORD serial1;
	MYDWORD serial2;
	MYDWORD refresh;
	MYDWORD retry;
	MYDWORD expire;
	MYDWORD minimum;
	long minCache;
	long maxCache;
	MYDWORD dhcpSize;
	time_t expireTime;
	MYDWORD httpClients[8];
	MYDWORD telnetClients[8];
	MYDWORD zoneServers[MAX_TCP_CLIENTS];
	data6 dnsRoutes[MAX_COND_FORW];
	data16 wildHosts[MAX_WILD_HOSTS];
	data12 dnsRanges[MAX_DNS_RANGES];
	data13 dhcpRanges[MAX_DHCP_RANGES];
	data14 rangeSet[MAX_RANGE_SETS];
	MYBYTE hasFilter;
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
	MYBYTE *options;
	MYWORD dhcpInd;
	char logFileName[_MAX_PATH];
	MYDWORD failureCount;
	time_t dhcpRepl;
	time_t dnsRepl;
	MYBYTE rangeCount;
	MYBYTE qc;
	MYBYTE dhcpLogLevel;
	MYBYTE dnsLogLevel;
	MYBYTE authorized;
	MYBYTE replication;
};

template<typename type, size_t size>
class array
{
public:
	type data[size];
};

//Global Variables
extern time_t t;
extern dhcpMap dhcpCache;
extern volatile bool kRunning;
extern struct data2 cfig;

//Function Prototypes
bool chkQu(const char*);
bool checkMask(MYDWORD);
bool checkRange(data17*, char);
bool detectChange();
size_t parseInt(const char *, unsigned long &);
bool isIP(char*);
bool getSecondary();
bool wildcmp(char*, char*);
bool isLocal(MYDWORD);
FILE *findSection(const char*, FILE*);
MYBYTE makeLocal(char*);
MYBYTE pIP(void*, MYDWORD);
MYBYTE pULong(void*, MYDWORD);
MYBYTE pUShort(void*, MYWORD);
char getRangeInd(MYDWORD);
int utf8bom(const char *);
char* myTrim(char*, int = 0);
//char* getServerName(char*, MYDWORD);
const char* getHexValue(MYBYTE*, const char*, MYBYTE*);
char* getResult(data5*, char* = array<char, 512>().data);
char* genHostName(char*, const MYBYTE*, MYBYTE);
char* hex2String(char*, const MYBYTE*, MYBYTE);
const char *AnsiToPunycode(const char *hostname, unsigned codepage, char* = array<char, 512>().data);
char* IP2String(MYDWORD, char* = array<char, 256>().data);
char* IP62String(MYBYTE*, char* = array<char, 256>().data);
char* myLower(char* string, bool = true);
FILE* readSection(char*, FILE*, FILE* = NULL);
char* strquery(data5*, char* = array<char, 512>().data);
data7* findDHCPEntry(char*);
data7* findEntry(MYBYTE, char*);
data7* findEntry(MYBYTE, char*, MYBYTE);
data7 *createCache(const data71 *lump);
MYDWORD alad(data9*);
MYDWORD calcMask(MYDWORD, MYDWORD);
MYDWORD chad(data9*);
MYDWORD getClassNetwork(MYDWORD);
MYDWORD getZone(MYBYTE, char*);
MYDWORD getSerial(const char*);
MYDWORD resad(data9*);
int sdmess(data9*);
int sendRepl(data9 *req);
MYDWORD* findServer(MYDWORD*, MYBYTE, MYDWORD);
MYDWORD* addServer(MYDWORD*, MYBYTE, MYDWORD);
int getIndex(char, MYDWORD);
void addNSAuth(data5*);
void addDHCPRange(char*);
void addMacRange(MYBYTE, char*);
void addVendClass(MYBYTE, char*, MYBYTE);
void addUserClass(MYBYTE, char*, MYBYTE);
void addEntry(MYBYTE, data7*);
void addOptions(data9*);
void addRRNone(data5*);
void addRRExt(data5*);
void addRRA(data5*);
void addRRPtr(data5*);
void addRRServerA(data5*);
void addRRAny(data5*, bool);
void addRRWildA(data5*, MYDWORD);
void addRRLocalhostA(data5*);
void addRRLocalhostPtr(data5*);
void addRRMX(data5*);
void addRRNS(data5*);
void addRRSOA(data5*, MYDWORD);
void addRRSOAuth(data5*, MYDWORD);
void addRRAd(data5*);
void addRRAOne(data5*);
void addRRPtrOne(data5*);
void addRRSTAOne(data5*);
void addRRCNOne(data5*);
void addRRMXOne(data5*, MYBYTE);
void addRRMXOne(data5*, MYBYTE);
void add2Cache(MYBYTE, char*, MYDWORD, time_t, MYBYTE, MYBYTE, MYWORD = CP_UTF8);
void calcRangeLimits(MYDWORD, MYDWORD, MYDWORD*, MYDWORD*);
void checkSize(MYBYTE);
void checkDNS(MYBYTE);
void closeConn();
void delDnsEntry(MYBYTE, data7*);
void getInterfaces(FILE*);
void logDebug(data9*);
bool lockOptions(FILE*, const char*);
bool loadOptions(FILE*, const char*, data20*);
void logThread(const char *);
void logMess(const char*, MYBYTE);
void logDHCPMess(const char*, MYBYTE);
void logDNSMess(const char*, MYBYTE);
void logDNSMess(data5*, const char*, MYBYTE);
void logTCPMess(data5*, const char*, MYBYTE);
bool mySplit(char*, char*, const char*, char);
void sendToken();
void procTCP(data5*);
void pvdata(data9*, data3*);
void recvRepl(data9*);
void debug(const char*);
void checkZone(void*);
int runProg();
void showError(MYDWORD);
void lockIP(MYDWORD);
void holdIP(MYDWORD);
void setTempLease(data7*);
void setLeaseExpiry(data7*);
void setLeaseExpiry(data7*, MYDWORD);
void updateDNS(data9*);
void updateStateFile(data7*);
int fdnmess(data5*);
MYWORD fQu(char*, dnsHeader*, char*);
bool frdnmess(data5*);
MYWORD fUShort(void*);
char *hostname2utf8(data9*, char* = array<char, 512>().data);
bool gdmess(data9*, MYBYTE);
int gdnmess(data5*, MYBYTE);
MYWORD listSections(char*, int, char*);
int recvTcpDnsMess(char*, SOCKET, int);
MYWORD qLen(const char*);
MYWORD pQu(char*, const char*);
MYWORD scanloc(data5*);
int sdnmess(data5*);
int sendTCPmess(data5 *req);

