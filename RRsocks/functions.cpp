#include "stdafx.h"

int initWsa()
{
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {
		debug("init wsa error", 0);
		return -1;
	}
	return 0;
}

/*
	print debug message
	@param debugInfo message
	@param level debug level
*/
void debug(char *debugInfo, int level)
{
	if (level <= DEBUG_LEVEL)
	{
		printf("DEBUG_%d |-| %s\n", level, debugInfo);
	}
}

SOCKET initSocket()
{//初始化服务器socket，绑定，监听
	if (initWsa() != 0)
	{
		debug("init wsa error!", 1);
		return -1;
	}
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		debug("init socket error!", 1);
		return -1;
	}
	sockaddr_in server_addr;
	memset((void *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(RR_PORT);
	server_addr.sin_addr.S_un.S_addr = INADDR_ANY;
	if (bind(s, (LPSOCKADDR)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
	{
		debug("bind socket error!", 1);
		printf("%d\n", WSAGetLastError());
		closesocket(s);
		return -1;
	}
	if (listen(s, SOMAXCONN) < 0)
	{
		debug("listen error!", 1);
		closesocket(s);
		return -1;
	}
	return s;
}

int get_server_addr(char *msg, LPSOCKADDR_IN lpServerAddr)
{
	addrinfo *addrinfoptr = NULL;
	addrinfo hints;
	// Setup the hints address info structure
	// which is passed to the getaddrinfo() function
	memset((void *)&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	char domain_name[255] = { 0 };
	char szPort[10] = { 0 };
	int port = 0;
	int domain_len = 0;
	//return value
	int iRetval = 0;
	switch (msg[3])
	{
	case 0x01:
		// addrtype: IPV4
		lpServerAddr->sin_family = AF_INET;
		lpServerAddr->sin_addr.S_un.S_addr = *(int *)&msg[4];
		lpServerAddr->sin_port = *(short *)&msg[8];

		//debug 
		printf("__IP__ %d.%d.%d.%d\n", msg[4], msg[5], msg[6], msg[7]);
		break;
	case 0x03:
		// addrtype: domain name
		domain_len = msg[4];
		for (int i = 0; i < domain_len; ++i)
		{
			domain_name[i] = msg[i + 5];
		}
		port = *(short *)&msg[domain_len + 5];
		_itoa_s(port, szPort, 10);
		iRetval = getaddrinfo(domain_name, szPort, &hints, &addrinfoptr);
		if (iRetval)
		{
			debug("getaddrinfo returned error, domain not found?", 1);
			return -1;
		}
		lpServerAddr->sin_addr = ((LPSOCKADDR_IN)(addrinfoptr->ai_addr))->sin_addr;
		lpServerAddr->sin_family = AF_INET;
		lpServerAddr->sin_port = port;
		break;
	case 0x04:
		// addrtype: IPV6
		// TODO: support ipv6
		return -1;
	default:
		return -1;
	}
	return 0;
}