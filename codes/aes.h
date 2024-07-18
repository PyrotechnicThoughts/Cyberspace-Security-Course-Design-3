#ifndef AES_H
#define AES_H

#include <gmp.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define N_LEFT 5
#define AES_256_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define CIPHERTEXT_LENTH 4096
#define PLAINTEXT_LENGTH 4096

// #define PRIVATE_KEY_PATH "./private.pem"
// #define PUBLIC_KEY_PATH "./public.pem"
#define PRIVATE_KEY_PATH ""
#define PUBLIC_KEY_PATH ""

typedef struct aes256_gcm
{
    int nleft; // 剩余可用次数
    mpz_t symmetric_key;
    unsigned char key[AES_256_KEY_SIZE]; // 实际的对称密钥
    unsigned char iv[GCM_IV_SIZE];       // 初始向量
} aes256_gcm;

void aes256_gcm_init(aes256_gcm *data);
void aes256_gcm_clear(aes256_gcm *data);

void generate_iv(unsigned char *iv, int iv_len);

int decrypt_aes_256_gcm(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *key,
                        const unsigned char *iv,
                        unsigned char *plaintext);
int encrypt_aes_256_gcm(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key,
                        const unsigned char *iv,
                        unsigned char *ciphertext);

void hash_128(const char *input, unsigned char output[16]);
int rsa_sign(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *priv_key_path);
int rsa_verify(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *pub_key_path);

#endif