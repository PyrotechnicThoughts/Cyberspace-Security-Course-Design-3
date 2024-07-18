#ifndef SERVER_H
#define SERVER_H

#include "utils.h"
#include "diffie.h"
#include "aes.h"

#include <pthread.h>   // 提供POSIX线程（即pthreads）库
#include <arpa/inet.h> // 提供Internet操作的定义（如 struct sockaddr_in）
#include <stdlib.h>    // stdlib.h 提供常用的库函数（如 atoi 和 exit）
#include <unistd.h>    // 提供POSIX操作系统API（如 getopt）
#include <stdio.h>
#include <sys/types.h>
#include <bits/getopt_core.h>

#define BACKLOG 100
#define BUFFER_SIZE 4096

#define THIS_IS_SERVER

void *handle_client(void *arg);

#endif