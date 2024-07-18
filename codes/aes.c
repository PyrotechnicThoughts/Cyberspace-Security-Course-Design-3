#include "aes.h"

void aes256_gcm_init(aes256_gcm *data)
{
    data->nleft = N_LEFT;
    mpz_init(data->symmetric_key);
}

void aes256_gcm_clear(aes256_gcm *data)
{
    data->nleft = -1;
    mpz_clear(data->symmetric_key);
}

// Function to generate a random IV
void generate_iv(unsigned char *iv, int iv_len)
{
    if (RAND_bytes(iv, iv_len) != 1)
    {
        perror("Error generating IV");
    }
}

int decrypt_aes_256_gcm(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *key,
                        const unsigned char *iv,
                        unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    // int ret;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error creating new context\n");
        return -1;
    }

    // Initialize the decryption operation
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        printf("Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL))
    {
        printf("Error setting IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        printf("Error setting key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide ciphertext to be decrypted
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        printf("Error updating with ciphertext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    // ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // // Check for successful decryption and verify authentication tag
    // if (ret > 0)
    // {
    //     plaintext_len += len;
    // }
    // else
    // {
    //     printf("Error finalizing decryption or authentication failure\n");
    //     EVP_CIPHER_CTX_free(ctx);
    //     return -1;
    // }

    // // Set expected tag value (if authenticated encryption)
    // if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ciphertext + ciphertext_len - 16)))
    // {
    //     printf("Error setting tag\n");
    //     EVP_CIPHER_CTX_free(ctx);
    //     return -1;
    // }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt_aes_256_gcm(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key,
                        const unsigned char *iv,
                        unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        printf("Error creating new context\n");
        return -1;
    }

    // Initialize the encryption operation
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        printf("Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL))
    {
        printf("Error setting IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        printf("Error setting key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide plaintext to be encrypted
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        printf("Error encrypting plaintext\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        printf("Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Get the authentication tag
    // if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + ciphertext_len))
    // {
    //     printf("Error getting authentication tag\n");
    //     EVP_CIPHER_CTX_free(ctx);
    //     return -1;
    // }
    // ciphertext_len += 16;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void hash_128(const char *input, unsigned char output[16])
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, output, NULL);

    EVP_MD_CTX_free(mdctx);
}

int rsa_sign(const unsigned char *msg, size_t msg_len, unsigned char **sig, size_t *sig_len, const char *priv_key_path)
{
    FILE *fp = fopen(priv_key_path, "r");
    if (!fp)
    {
        fprintf(stderr, "Unable to open private key file %s\n", priv_key_path);
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey)
    {
        fprintf(stderr, "Unable to read private key\n");
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mdctx, NULL, EVP_md5(), NULL, pkey) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_DigestSignUpdate(mdctx, msg, msg_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, sig_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignFinal (get length) failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    *sig = (unsigned char *)malloc(*sig_len);
    if (EVP_DigestSignFinal(mdctx, *sig, sig_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestSignFinal (get signature) failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        free(*sig);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return 1;
}

int rsa_verify(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const char *pub_key_path)
{
    FILE *fp = fopen(pub_key_path, "r");
    if (!fp)
    {
        fprintf(stderr, "Unable to open public key file %s\n", pub_key_path);
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey)
    {
        fprintf(stderr, "Unable to read public key\n");
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_md5(), NULL, pkey) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_DigestVerifyUpdate(mdctx, msg, msg_len) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    int result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    if (result != 1)
    {
        fprintf(stderr, "EVP_DigestVerifyFinal failed\n");
        ERR_print_errors_fp(stderr);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return result == 1;
}
