#ifndef DIFFIE_H
#define DIFFIE_H

#include <gmp.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"
#include "utils.h"

#define SERVER_TAG 0 // 标识调用者是服务器
#define CLIENT_TAG 1 // 标识调用者是客户端


void generate_large_prime(mpz_t prime, gmp_randstate_t state, int bit_length);
void find_generator(mpz_t generator, const mpz_t p);

typedef struct diffie_hellman
{
    mpz_t p;
    mpz_t g;
    mpz_t secret;
    mpz_t g_secret_mod_p;
    mpz_t peer_g_secret_mod_p;
    mpz_t symmetric_key;
}diffie_hellman;

void diffie_hellman_init(diffie_hellman *dh);
void diffie_hellman_clear(diffie_hellman *dh);

int generate_symmertic_key(int sockfd, int tag, aes256_gcm *ag, const char *key_path);

#endif