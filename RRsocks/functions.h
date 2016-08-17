#pragma once
#include "stdafx.h"

int initWsa();
void debug(char *debugInfo, int level);
SOCKET initSocket();
int get_server_addr(char *msg, LPSOCKADDR_IN lpServerAddr);
