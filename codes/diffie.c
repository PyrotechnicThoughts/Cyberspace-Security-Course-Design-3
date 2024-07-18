#include "diffie.h"

// 使用欧几里德算法计算最大公约数
void gcd(mpz_t result, const mpz_t a, const mpz_t b)
{
    mpz_t temp_a, temp_b, temp;
    mpz_init_set(temp_a, a);
    mpz_init_set(temp_b, b);
    mpz_init(temp);

    while (mpz_cmp_ui(temp_b, 0) != 0)
    {
        mpz_set(temp, temp_b);
        mpz_mod(temp_b, temp_a, temp_b);
        mpz_set(temp_a, temp);
    }

    mpz_set(result, temp_a);

    mpz_clear(temp);
    mpz_clear(temp_a);
    mpz_clear(temp_b);
}

// 判断两个数是否互质
int are_coprime(const mpz_t a, const mpz_t b)
{
    mpz_t gcd_result;
    mpz_init(gcd_result);

    // 计算最大公约数
    gcd(gcd_result, a, b);

    // 如果最大公约数为1，则两个数互质
    int coprime = (mpz_cmp_ui(gcd_result, 1) == 0);

    mpz_clear(gcd_result);

    return coprime;
}

// 计算素数p的欧拉函数 φ(p) = p - 1
void euler_totient(mpz_t result, const mpz_t p)
{
    mpz_sub_ui(result, p, 1);
}

// 计算 (base^exp) % mod 的函数
void mod_exp(mpz_t result, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
    mpz_t exp_copy;
    mpz_init_set(exp_copy, exp); // 创建并初始化 exp 的副本
    mpz_t base_copy;
    mpz_init_set(base_copy, base);
    mpz_set_ui(result, 1);

    if (mpz_cmp_ui(exp_copy, 0) == 0)
    {
        mpz_set_ui(result, 1);
    }
    else
    {
        while (mpz_cmp_ui(exp_copy, 0) > 0)
        {
            if (mpz_odd_p(exp_copy))
            {
                mpz_mul(result, result, base_copy);
                mpz_mod(result, result, mod);
            }
            mpz_powm_ui(base_copy, base_copy, 2, mod); // base_copy = (base_copy * base_copy) % mod;
            mpz_fdiv_q_ui(exp_copy, exp_copy, 2);      // exp_copy = exp_copy / 2;
        }
    }

    mpz_clear(exp_copy);
    mpz_clear(base_copy);
}

// 判断一个数是否为素数
int is_prime(const mpz_t n)
{
    if (mpz_cmp_ui(n, 2) < 0)
        return 0; // 小于2的数不是素数

    mpz_t i, sqrt_n;
    mpz_inits(i, sqrt_n, NULL);

    mpz_set_ui(i, 2);
    mpz_sqrt(sqrt_n, n); // 计算n的平方根

    while (mpz_cmp(i, sqrt_n) <= 0)
    {
        if (mpz_divisible_p(n, i))
        {
            mpz_clears(i, sqrt_n, NULL);
            return 0; // n可以被i整除，不是素数
        }
        mpz_add_ui(i, i, 1);
    }

    mpz_clears(i, sqrt_n, NULL);
    return 1; // 没有找到可以整除n的数，是素数
}

// 生成一个随机的大素数
void generate_large_prime(mpz_t prime, gmp_randstate_t state, int bit_length)
{
    // printf("Generate large prime...\n");
    do
    {
        mpz_urandomb(prime, state, bit_length);
        mpz_setbit(prime, bit_length - 1); // 确保最高位是1，使得生成的数具有指定位数
    } while (!mpz_probab_prime_p(prime, 25)); // 进行25次Miller-Rabin测试
}

// 查找一个给定素数p的生成元g
void find_generator(mpz_t generator, const mpz_t p)
{
    mpz_t phi, exp;
    mpz_init(phi);
    mpz_init(exp);
    euler_totient(phi, p);

    mpz_t g, result;
    mpz_init_set_ui(g, 2);
    mpz_init(result);

    while (1)
    {
        int is_generator = 1;
        mpz_t i;
        mpz_init_set_ui(i, 2);

        while (mpz_cmp(i, p) < 0)
        {
            // gmp_printf("p:%Zd, g:%Zd, i:%Zd\n", p, g, i);
            if (mpz_divisible_p(phi, i) && is_prime(i))
            {
                mpz_tdiv_q_ui(exp, phi, mpz_get_ui(i));

                mod_exp(result, g, exp, p);
                if (mpz_cmp_ui(result, 1) == 0)
                {
                    is_generator = 0;
                    break;
                }
            }

            mpz_add_ui(i, i, 1);
        }
        if (is_generator)
            break;

        mpz_add_ui(g, g, 1);

        mpz_clear(i);
    }
    mpz_set(generator, g);

    mpz_clear(g);
    mpz_clear(result);

    mpz_clear(phi);
    mpz_clear(exp);
}
void diffie_hellman_init(diffie_hellman *dh)
{
    mpz_inits(dh->p, dh->g, dh->secret, dh->g_secret_mod_p, dh->peer_g_secret_mod_p, dh->symmetric_key, NULL);
}

void diffie_hellman_clear(diffie_hellman *dh)
{
    mpz_clears(dh->p, dh->g, dh->secret, dh->g_secret_mod_p, dh->peer_g_secret_mod_p, dh->symmetric_key, NULL);
}

void initialize_random_state(gmp_randstate_t state)
{
    // 获取当前时间（秒数）
    unsigned long seed = time(NULL);

    // 获取进程ID
    seed ^= getpid();

    // 获取随机数
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp != NULL)
    {
        unsigned long urandom_seed;
        fread(&urandom_seed, sizeof(urandom_seed), 1, fp);
        seed ^= urandom_seed;
        fclose(fp);
    }

    // 初始化随机数生成器状态
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
}

int generate_symmertic_key(int sockfd, int tag, aes256_gcm *ag, const char *key_path)
{
    diffie_hellman dh;
    diffie_hellman_init(&dh);

    gmp_randstate_t state;
    initialize_random_state(state);

    mpz_urandomb(dh.secret, state, 8);

    ag->nleft = N_LEFT;

    if (tag == SERVER_TAG)
    {
        struct sockaddr_in peer_addr;
        socklen_t client_addr_len = sizeof(peer_addr);
        if (getpeername(sockfd, (struct sockaddr *)&peer_addr, &client_addr_len) == -1)
        {
            perror("Getpeername failed");
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);
        int peer_port = ntohs(peer_addr.sin_port);

        gmp_printf("%s:%d [secret] %Zd\n", peer_ip, peer_port, dh.secret);

        // 接收 p
        // printf("Receive p... ");
        if (recv_mpz_t(sockfd, dh.p) == -1)
        {
            perror("Receive p failed");
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }
        gmp_printf("%s:%d [p] %Zd\n", peer_ip, peer_port, dh.p);

        // 接收 g
        // printf("Receive g... ");
        if (recv_mpz_t(sockfd, dh.g) == -1)
        {
            printf("Receive g failed\n");
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }
        gmp_printf("%s:%d [g] %Zd\n", peer_ip, peer_port, dh.g);

        // 接收 peer_g_secret_mod_p
        // printf("Receive peer_g_secret_mod_p... ");
        if (recv_mpz_t(sockfd, dh.peer_g_secret_mod_p) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }
        gmp_printf("%s:%d [peer_g_secret_mod_p] %Zd\n", peer_ip, peer_port, dh.peer_g_secret_mod_p);

        mod_exp(dh.g_secret_mod_p, dh.g, dh.secret, dh.p);
        gmp_printf("%s:%d [g_secret_mod_p] %Zd\n", peer_ip, peer_port, dh.g_secret_mod_p);

        // 发送 g_secret_mod_p
        // printf("Send peer_g_secret_mod_p... %s:%d\n", peer_ip, peer_port);
        if (send_mpz_t(sockfd, dh.g_secret_mod_p) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }

        // 发送签名部分
        // 将 mpz_t 转换为字符串，基数为10表示十进制
        char *str_value = mpz_get_str(NULL, 10, dh.g_secret_mod_p);
        if (str_value == NULL)
        {
            return -1;
        }
        unsigned char hash[16];
        unsigned char *signature = NULL;
        size_t signature_len = 0;

        hash_128(str_value, hash);
        printf("%s:%d Input: %s\n", peer_ip, peer_port, str_value);
        printf("%s:%d 128-bit Hash: ", peer_ip, peer_port);
        for (int i = 0; i < 16; ++i)
        {
            printf("%02x ", hash[i]);
        }
        printf("\n");

        if (rsa_sign(hash, 16, &signature, &signature_len, key_path))
        {
            printf("%s:%d RSA Signature: ", peer_ip, peer_port);
            for (size_t i = 0; i < signature_len; ++i)
            {
                printf("%02x", signature[i]);
            }
            printf("\n");

            // 如果签名成功则发送
            sendvl(sockfd, signature, signature_len);

            free(signature);
        }
        else
        {
            sendvl(sockfd, hash, 16);
        }

        mod_exp(dh.symmetric_key, dh.peer_g_secret_mod_p, dh.secret, dh.p);
        mpz_set(ag->symmetric_key, dh.symmetric_key);
        gmp_printf("%s:%d [symmetric_key] %Zd\n", peer_ip, peer_port, dh.symmetric_key);

        size_t countp;
        mpz_export(ag->key, &countp, 1, 1, 0, 0, ag->symmetric_key);
        if (countp < AES_256_KEY_SIZE)
        {
            memmove(ag->key + (AES_256_KEY_SIZE - countp), ag->key, countp);
            memset(ag->key, 0, AES_256_KEY_SIZE - countp);
        }

        printf("%s:%d [key]:", peer_ip, peer_port);
        for (int i = 0; i < AES_256_KEY_SIZE; ++i)
        {
            printf("%02x ", ag->key[i]);
        }
        printf("\n");

        diffie_hellman_clear(&dh);
        gmp_randclear(state);
        return 0;
    }
    else if (tag == CLIENT_TAG)
    {
        gmp_printf("[secret]: %Zd\n", dh.secret);

        generate_large_prime(dh.p, state, 8);
        // mpz_set_ui(dh.p, 41);
        gmp_printf("[p]: %Zd\n", dh.p);

        find_generator(dh.g, dh.p);
        gmp_printf("[g]: %Zd\n", dh.g);

        mod_exp(dh.g_secret_mod_p, dh.g, dh.secret, dh.p);
        gmp_printf("[g_secret_mod_p]: %Zd\n", dh.g_secret_mod_p);

        // 发送 p
        // printf("Send p...\n");
        if (send_mpz_t(sockfd, dh.p) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }

        // 发送 g
        // printf("Send g...\n");
        if (send_mpz_t(sockfd, dh.g) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }

        // 发送 g_secret_mod_p
        // printf("Send g_secret_mod_p...\n");
        if (send_mpz_t(sockfd, dh.g_secret_mod_p) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }

        // 接收 peer_g_secret_mod_p
        // printf("Receive peer_g_secret_mod_p...\n");
        if (recv_mpz_t(sockfd, dh.peer_g_secret_mod_p) == -1)
        {
            diffie_hellman_clear(&dh);
            gmp_randclear(state);
            return -1;
        }
        gmp_printf("[peer_g_secret_mod_p]: %Zd\n", dh.peer_g_secret_mod_p);

        if (strcmp(key_path, "") != 0)
        {
            // 接收签名
            unsigned char *signature = NULL;
            size_t signature_len = 0;
            unsigned char hash[16];

            signature_len = recvvl(sockfd, (void **)&signature);
            signature[signature_len] = '\0';

            // 将 mpz_t 转换为字符串，基数为10表示十进制
            char *str_value = mpz_get_str(NULL, 10, dh.peer_g_secret_mod_p);
            if (str_value == NULL)
            {
                return -1;
            }

            hash_128(str_value, hash);
            printf("Input: %s\n", str_value);
            printf("128-bit Hash: ");
            for (int i = 0; i < 16; ++i)
            {
                printf("%02x ", hash[i]);
            }
            printf("\n");

            printf("RSA Signature: ");
            for (size_t i = 0; i < signature_len; ++i)
            {
                printf("%02x", signature[i]);
            }
            printf("\n");

            if (rsa_verify(hash, sizeof(hash), signature, signature_len, "public.pem"))
            {
                printf("RSA Signature verification succeeded\n");
            }
            else
            {
                fprintf(stderr, "RSA Signature verification failed\n");
                return -1;
            }

            free(signature);
        }
        else
        {
            unsigned char *hash = NULL;
            int res = recvvl(sockfd, (void **)&hash);
            hash[res] = '\0';
            free(hash);
        }

        mod_exp(dh.symmetric_key, dh.peer_g_secret_mod_p, dh.secret, dh.p);
        mpz_set(ag->symmetric_key, dh.symmetric_key);
        gmp_printf("[symmetric_key]: %Zd\n", dh.symmetric_key);

        size_t countp;
        mpz_export(ag->key, &countp, 1, 1, 0, 0, ag->symmetric_key);
        if (countp < AES_256_KEY_SIZE)
        {
            memmove(ag->key + (AES_256_KEY_SIZE - countp), ag->key, countp);
            memset(ag->key, 0, AES_256_KEY_SIZE - countp);
        }
        printf("[key]:");
        for (int i = 0; i < AES_256_KEY_SIZE; ++i)
        {
            printf("%02x ", ag->key[i]);
        }
        printf("\n");

        diffie_hellman_clear(&dh);
        gmp_randclear(state);
        return 0;
    }
    else
    {
        printf("Incorrect tag.\n");

        diffie_hellman_clear(&dh);
        gmp_randclear(state);
        return -1;
    }
}