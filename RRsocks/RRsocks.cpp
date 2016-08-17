// RRsocks.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

unsigned __stdcall packetHandler(LPVOID lpParameter);
int identify(int len, unsigned char *msg, SOCKET s);
int request(int len, unsigned char *msg, SOCKET s);
unsigned __stdcall forwardThread(LPVOID lpParameter);
//void test_aes();
//void phex(const unsigned char *buffer);
static unsigned char key[16] = { 'T', 'h', 'i', 's', 'i', 's', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'k', '3', 'y' };
static unsigned char iv[16] = { 'T', 'h', 'i', 's', 'i', 's', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'v', '.' };

int main()
{
	SOCKET s = initSocket();
	if (s == -1)
	{
		debug("init socket error!", 0);
		WSACleanup();
		return -1;
	}
	sockaddr_in remoteAddr;
	int addrLen = sizeof(remoteAddr);
	
	//调试信息保存在字符串中，用于debug
	char debugInfoBuffer[256] = { 0 };
	debug("service started.", 0);
	for (;;)
	{
		SOCKET *s_tmp_ptr = (SOCKET *)malloc(sizeof(s));
		if (s_tmp_ptr == NULL)
		{
			continue;
		}
		memset(debugInfoBuffer, 0, sizeof(debugInfoBuffer));
		*s_tmp_ptr = accept(s, (LPSOCKADDR)&remoteAddr, &addrLen);
		if (*s_tmp_ptr == INVALID_SOCKET)
		{
			debug("accept connection error.", 1);
			continue;
		}
		else
		{
			char remoteAddrStr[20] = { 0 };
			inet_ntop(AF_INET, (PVOID)&(remoteAddr.sin_addr), remoteAddrStr, 20);
			sprintf_s(debugInfoBuffer, "accept success %s:%d", remoteAddrStr, ntohs(remoteAddr.sin_port));
			debug(debugInfoBuffer,2);
		}
		
		// create a process for one connection.
		_beginthreadex(NULL, 0, packetHandler, (LPVOID)s_tmp_ptr, 0, NULL);
	} 
	
	closesocket(s);
	WSACleanup();
	return 0; 
}

unsigned __stdcall packetHandler(LPVOID lpParameter)
{
	SOCKET s = *((SOCKET *)lpParameter);
	free((SOCKET *)lpParameter);
	char buffer[4096] = { 0 };
	char buffer_decrypted[4096] = { 0 };
	int len = 0;
	// handshark, negotiation the identifier method
	len = recv(s, buffer, sizeof(buffer), 0);
	
	//decrypt data
	//len = (len / 16) * 16 + 16;
	//AES128_CBC_encrypt_buffer((uint8_t *)buffer_decrypted, (uint8_t *)buffer, len, (uint8_t *)key, (uint8_t *)iv);
	//AES128_CBC_decrypt_buffer((uint8_t *)buffer, (uint8_t *)buffer_decrypted, len, (uint8_t *)key, (uint8_t *)iv);

	if (identify(len, (unsigned char *)buffer, s) < 0)
	{
		return 0;
	}
	// request detail, connect to the remote server
	memset(buffer, 0, sizeof(buffer));
	len = recv(s, buffer, sizeof(buffer), 0);
	
	request(len, (unsigned char *)buffer, s);
	
	debug("forward finished, connection closed.", 1);
	return 0;
}

int identify(int len, unsigned char *msg, SOCKET s)
{
	char debugInfoBuffer[256] = { 0 };
	// get remote addr info for debuging
	SOCKADDR_IN remote_addr;
	ZeroMemory(&remote_addr, sizeof(remote_addr));
	int namelen = sizeof(remote_addr);
	char szAddrStr[20] = { 0 };
	if (getpeername(s, (LPSOCKADDR)&remote_addr, &namelen) < 0)
	{
		strcpy_s(szAddrStr, "unknown");
	}
	else
	{
		inet_ntop(AF_INET, (PVOID)&remote_addr.sin_addr, szAddrStr, sizeof(szAddrStr));
	}
	
	if (len <= 0)
	{
		sprintf_s(debugInfoBuffer, "identify error CONNECTION_CLOSED %s:%d", szAddrStr, ntohs(remote_addr.sin_port));
		debug(debugInfoBuffer, 2);
		closesocket(s);
		return -1;
	}
	// verify the socks version
	char retMsg[2] = { 0 };
	if (msg[0] != 0x05)
	{
		retMsg[0] = (char)0x05;
		retMsg[1] = (char)0xFF;
		send(s, retMsg, 2, 0);
		sprintf_s(debugInfoBuffer, "identify error SOCKS_VERSION_NOT_SUPPORTED %s:%d data: [%X %X]", szAddrStr, ntohs(remote_addr.sin_port), *(int*)(msg), *(((int*)msg) + 1));
		debug(debugInfoBuffer, 1);
		closesocket(s);
		return -1;
	}
	// check supported identifier method
	int nmethods = msg[1];
	int isIdentified = 0;
	// traversal，try every identify method until identified
	for (int i = 0; i < nmethods; ++i)
	{
		switch (msg[i + 2])
		{
		case 0:
			isIdentified = 1;
			retMsg[0] = 0x05;
			retMsg[1] = 0x00;
			send(s, retMsg, 2, 0);
			break;
		case 1:
			break;
		case 2:
			break;
		default:
			break;
		}
	}
	// identify failed
	if (!isIdentified)
	{
		sprintf_s(debugInfoBuffer, "identify error METHOD_NOT_ALLOWED %s:%d", szAddrStr, ntohs(remote_addr.sin_port));
		debug(debugInfoBuffer, 0);
		retMsg[0] = (char)0x05;
		retMsg[1] = (char)0xFF;
		send(s, retMsg, 2, 0);
		closesocket(s);
		return -1;
	}
	
	sprintf_s(debugInfoBuffer, "identify success. %s:%d", szAddrStr, ntohs(remote_addr.sin_port));
	debug(debugInfoBuffer, 1);
	return 0;
}

int request(int len, unsigned char *msg, SOCKET s)
{
	char retMsg[255] = { 0 };
	if (len <= 0)
	{
		// connection closed
		debug("connection closed accidentally in request function.", 1);
		closesocket(s);
		return -1;
	}
	if (msg[0] != 0x05 || msg[2] != 0x00) {
		// version not supported
		debug("version not supported when identifing.", 1);
		retMsg[0] = 0x05;
		retMsg[1] = 0x07;
		retMsg[2] = 0x00;
		send(s, retMsg, 10, 0);
		closesocket(s);
		return -1;
	}
	
	HANDLE hRecvThread, hSendThread;
	SOCKET socks_connection_send[2] = { 0 };
	SOCKET socks_connection_recv[2] = { 0 };

	//get local connection info;
	sockaddr_in local_addr;
	int namelen = sizeof(local_addr);
	memset((void *)&local_addr, 0, sizeof(local_addr));
	getsockname(s, (LPSOCKADDR)&local_addr, &namelen);

	SOCKET socket_to_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in server_addr;
	ZeroMemory(&server_addr, sizeof(server_addr));
	if (get_server_addr((char *)msg, &server_addr) < 0)
	{
		// address type not supported
		debug("get server address error, addr type may not supported.", 1);
		retMsg[0] = 0x05;
		retMsg[1] = 0x08;
		retMsg[2] = 0x00;
		send(s, retMsg, 10, 0);
		closesocket(s);
		return -1;
	}
	char szServerAddr[20] = { 0 };
	inet_ntop(AF_INET, (PVOID)&(server_addr.sin_addr), szServerAddr, sizeof(szServerAddr));

	switch (msg[1])
	{
	case 0x01:
		// CONNECT
		// connect to remote server
		
		if (connect(socket_to_server, (LPSOCKADDR)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
		{
			// TODO: specify error reason
			debug("connect to server error!", 1);
			retMsg[0] = 0x05;
			// connection refused
			retMsg[1] = 0x05;
			retMsg[2] = 0x00;
			send(s, retMsg, 3, 0);
			closesocket(s);
		}
		// connect server success
		printf("connected to %s:%d\n", szServerAddr, ntohs(server_addr.sin_port));
		// return connection succeed
		retMsg[0] = 0x05;
		retMsg[1] = retMsg[2] = 0x00;
		retMsg[3] = 0x01;
		*(unsigned int *)(retMsg + 4) = local_addr.sin_addr.S_un.S_addr;
		*((short *)(retMsg + 8)) = local_addr.sin_port;
		send(s, retMsg, 10, 0);

		//forward data
		socks_connection_send[0] = s;
		socks_connection_send[1] = socket_to_server;
		hSendThread = (HANDLE)_beginthreadex(NULL, 0, forwardThread, (LPVOID)socks_connection_send, 0, NULL);
		debug("send thread started.", 2);
		socks_connection_recv[0] = socket_to_server;
		socks_connection_recv[1] = s;
		hRecvThread = (HANDLE)_beginthreadex(NULL, 0, forwardThread, (LPVOID)socks_connection_recv, 0, NULL);
		debug("recv thread started.", 2);
		WaitForSingleObject(hSendThread, INFINITE);
		WaitForSingleObject(hRecvThread, INFINITE);

		break;
	case 0x02:
		// BIND
		// TODO: implement bind command
		break;
	case 0x03:
		// UDP ASSOCIATE
		// TODO: implement UDP ASSOCIATE 
		break;
	default:
		// command not supported
		retMsg[0] = 0x05;
		retMsg[1] = 0x07;
		retMsg[2] = 0x00;
		send(s, retMsg, 10, 0);
		closesocket(s);
		return -1;
		break;
	}
	return 0;
}

unsigned __stdcall forwardThread(LPVOID lpParameter)
{
	SOCKET *socks_connection = (SOCKET *)lpParameter;
	SOCKET socket_to_recv_data = socks_connection[0];
	SOCKET socket_to_send_data = socks_connection[1];

	// for printing debug info
	char debug_buffer[255] = { 0 };
	char recv_ip_str[30] = { 0 };
	unsigned short recv_port = 0;
	char send_ip_str[30] = { 0 };
	unsigned short send_port = 0;
	SOCKADDR_IN connection_addr;
	int namelen = sizeof(connection_addr);
	// get recv data socket peer
	ZeroMemory((LPVOID)&connection_addr, namelen);
	getpeername(socket_to_recv_data, (LPSOCKADDR)&connection_addr, &namelen);
	inet_ntop(AF_INET, (PVOID)&connection_addr.sin_addr, recv_ip_str, sizeof(recv_ip_str));
	recv_port = ntohs(connection_addr.sin_port);
	// get send data socket peer
	ZeroMemory((LPVOID)&connection_addr, namelen);
	getpeername(socket_to_send_data, (LPSOCKADDR)&connection_addr, &namelen);
	inet_ntop(AF_INET, (PVOID)&connection_addr.sin_addr, send_ip_str, sizeof(send_ip_str));
	send_port = ntohs(connection_addr.sin_port);

	char buffer[4096] = { 0 };
	int len = 0;
	while ((len = recv(socket_to_recv_data, buffer, sizeof(buffer), 0)) > 0)
	{
		if (send(socket_to_send_data, buffer, len, 0) <= 0)
		{
			// connection closed
			debug("send error, closing the socket.", 2);
			break;
		}
		sprintf_s(debug_buffer, "%s:%d ---> %s:%d", recv_ip_str, recv_port, send_ip_str, send_port);
		debug(debug_buffer, 3);
		memset(buffer, 0, sizeof(buffer));
	}
	
	// close socket
	closesocket(socket_to_recv_data);
	closesocket(socket_to_send_data);
	return 0;
}

//void test_aes()
//{
//	char buffer[1024] = { 0 };
//	char output[1024] = { 0 };
//	char result[1024] = { 0 };
//	char iv[16] = { 'T', 'h', 'i', 's', 'i', 's', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'v', '.' };
//	char key[16] = { 'T', 'h', 'i', 's', 'i', 's', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'k', '3', 'y' };
//	for (int i = 0; i < 20; ++i) {
//		buffer[i] = '0' + i;
//	}
//	printf("%s\n", buffer);
//	phex((unsigned char *)buffer);
//	AES128_CBC_encrypt_buffer((uint8_t *)output, (uint8_t *)buffer, 16, (uint8_t *)key, (uint8_t *)iv);
//	phex((unsigned char *)output);
//	AES128_CBC_decrypt_buffer((uint8_t *)result, (uint8_t *)output, 16, (uint8_t *)key, (uint8_t *)iv);
//	phex((unsigned char *)result);
//	printf("%s\n", result);
//}

//void phex(const unsigned char *buffer)
//{
//	for (int i = 0; i < 32; ++i) {
//		if (i && i % 4 == 0) {
//			if (i % 8 == 0) {
//				printf("\n");
//			}
//			else
//			{
//				printf("    ");
//			}
//
//		}
//		printf("%.2X ", buffer[i]);
//	}
//	printf("\n\n");
//}