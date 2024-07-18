#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "diffie.h"

typedef unsigned int uint32_t;

ssize_t recvn(int sockfd, void *buf, ssize_t len);
ssize_t recvvl(int sockfd, void **buf);
int recv_mpz_t(int sockfd, mpz_t value);
ssize_t decrypt_recvvl(int sockfd, unsigned char *buf, aes256_gcm *ag, const char* key_path);

ssize_t sendn(int sockfd, const void *buf, size_t len);
ssize_t sendvl(int sockfd, const void *buf, size_t len);
int send_mpz_t(int sockfd, mpz_t value);
ssize_t encrypt_sendvl(int sockfd, const void *buf, size_t len, aes256_gcm *ag, const char* key_path);

#endif
