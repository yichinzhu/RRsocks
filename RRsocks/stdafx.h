// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <process.h>

#include "functions.h"
#include "aes.h"
//引入静态链接库
#pragma comment(lib, "ws2_32.lib")

//调试模式
#define DEBUG_LEVEL 5

//服务器端口，默认为4349
#define RR_PORT 2333


//main中函数声明
