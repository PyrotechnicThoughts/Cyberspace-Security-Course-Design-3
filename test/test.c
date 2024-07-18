#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>

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

int main()
{
    // 初始化GMP库
    mpz_t p, g;
    mpz_init(p);
    mpz_init(g);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成一个大素数
    generate_large_prime(p, state, 8); // 生成至少512位的素数
    gmp_printf("Generated prime p: %Zd\n", p);

    // 查找与p相关的生成元g
    find_generator(g, p);
    gmp_printf("Found generator g: %Zd\n", g);

    mpz_set_ui(p, 41);
    find_generator(g, p);
    gmp_printf("Found generator g: %Zd\n", g);

    // 清理资源
    mpz_clear(p);
    mpz_clear(g);
    gmp_randclear(state);

    return 0;
}
