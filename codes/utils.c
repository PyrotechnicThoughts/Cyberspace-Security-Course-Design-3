#include "utils.h"

#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>

ssize_t recvn(int sockfd, void *buf, ssize_t len)
{
    ssize_t nleft = len; // 剩余未接受的
    ssize_t nread;
    char *ptr = buf;

    while (nleft > 0)
    {
        /* code */
        if ((nread = recv(sockfd, ptr, nleft, 0)) < 0)
        {
            if (errno == EINTR)
            {
                nread = 0;
            }
            else
            {
                return -1;
            }
        }
        else if (nread == 0)
        {
            break; // EOF
        }

        nleft -= nread;
        ptr += nread;
    }

    return (len - nleft); // 实际接受的字节数
}

ssize_t recvvl(int sockfd, void **buf)
{
    uint32_t len;
    ssize_t nread;

    // 先接收长度信息
    nread = recvn(sockfd, &len, sizeof(len));
    if (nread <= 0)
    {
        return nread; // 读取错误或连接关闭
    }

    len = ntohl(len); // 将网络字节序转换为主机字节序

    *buf = malloc(len);
    if (*buf == NULL)
    {
        return -1; // 内存分配失败
    }

    // 接收实际数据
    nread = recvn(sockfd, *buf, len);
    if (nread <= 0)
    {
        free(*buf);
        return nread; // 读取错误或连接关闭
    }

    return len; // 返回实际接收的字节数
}

int recv_mpz_t(int sockfd, mpz_t value)
{
    char *buf;
    ssize_t len = recvvl(sockfd, (void **)&buf);
    if (len <= 0)
    {
        perror("len <= 0");
        return -1; // 接收失败或连接关闭
    }
    // printf("mpz len:%ld\n", len);

    buf[len] = '\0';
    // printf("mpz str:%s\n", (char *)buf);

    // 将接收的字符串转换为 mpz_t
    if (mpz_set_str(value, (char *)buf, 10) != 0)
    {
        perror("mpz_set_str failed");
        free(buf);
        return -1; // 转换失败
    }

    free(buf);
    return 0;
}

ssize_t decrypt_recvvl(int sockfd, unsigned char *buf, aes256_gcm *ag, const char* key_path)
{
    if (ag->nleft <= 0)
    {
        int is_secure = generate_symmertic_key(sockfd, SERVER_TAG, ag, key_path);
        if (is_secure < 0)
        {
            perror("generate_symmertic_key failed");
        }
    }
    else
    {
        ag->nleft -= 1;
    }

    // 获取并打印客户端地址和端口信息
    struct sockaddr_in peer_addr;
    socklen_t client_addr_len = sizeof(peer_addr);
    if (getpeername(sockfd, (struct sockaddr *)&peer_addr, &client_addr_len) == -1)
    {
        perror("Getpeername failed");
        return -1;
    }

    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);
    int peer_port = ntohs(peer_addr.sin_port);

    int res = 0;
    unsigned char *iv;
    if ((res = recvvl(sockfd, (void **)&iv)) > 0)
    {
        printf("%s:%d IV:", peer_ip, peer_port);
        for (int i = 0; i < GCM_IV_SIZE; i++)
        {
            printf("%02x ", iv[i]);
        }
        printf("\n");
    }
    else
    {
        perror("Recv IV failed");
        return res;
    }

    memcpy(ag->iv, iv, GCM_IV_SIZE);
    free(iv);

    unsigned char *ciphertext;
    int ciphertext_len;
    if ((ciphertext_len = recvvl(sockfd, (void **)&ciphertext)) > 0)
    {
        ciphertext[ciphertext_len] = '\0';

        printf("%s:%d Ciphertext:", peer_ip, peer_port);
        for (int i = 0; i < ciphertext_len; i++)
        {
            printf("%02x ", ciphertext[i]);
        }
        printf("\n");
    }
    else
    {
        perror("Recv failed");
        return ciphertext_len;
    }

    // unsigned char plaintext[PLAINTEXT_LENGTH];
    int plaintext_len;
    plaintext_len = decrypt_aes_256_gcm(ciphertext, ciphertext_len, ag->key, ag->iv, buf);
    buf[plaintext_len] = '\0';

    free(ciphertext);
    return plaintext_len;
}

ssize_t sendn(int sockfd, const void *buf, size_t len)
{
    size_t nleft = len;
    ssize_t nwritten;
    const char *ptr = buf;

    while (nleft > 0)
    {
        if ((nwritten = send(sockfd, ptr, nleft, 0)) <= 0)
        {
            if (nwritten < 0 && errno == EINTR)
            {
                nwritten = 0; // 重启send
            }
            else
            {
                return -1; // 出错
            }
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return len;
}

ssize_t sendvl(int sockfd, const void *buf, size_t len)
{
    uint32_t len_net = htonl(len);

    // 先发送长度信息
    if (sendn(sockfd, &len_net, sizeof(len_net)) != sizeof(len_net))
    {
        return -1;
    }

    // 再发送实际数据
    if (sendn(sockfd, buf, len) != len)
    {
        return -1;
    }

    return len;
}

int send_mpz_t(int sockfd, mpz_t value)
{
    // 将 mpz_t 转换为字符串，基数为10表示十进制
    char *str_value = mpz_get_str(NULL, 10, value);
    if (str_value == NULL)
    {
        return -1;
    }
    // printf("mpz str:%s\n", str_value);

    size_t len = strlen(str_value);
    ssize_t result = sendvl(sockfd, str_value, len);

    // 释放字符串内存
    free(str_value);

    return result;
}

ssize_t encrypt_sendvl(int sockfd, const void *buf, size_t len, aes256_gcm *ag, const char* key_path)
{

    if (ag->nleft <= 0)
    {
        int is_secure = generate_symmertic_key(sockfd, CLIENT_TAG, ag, key_path);
        if (is_secure < 0)
        {
            perror("generate_symmertic_key failed");
        }
    }
    else
    {
        ag->nleft -= 1;
    }

    unsigned char ciphertext[CIPHERTEXT_LENTH];
    int ciphertext_len;

    generate_iv(ag->iv, GCM_IV_SIZE);

    printf("IV:");
    for (int i = 0; i < GCM_IV_SIZE; i++)
    {
        printf("%02x ", ag->iv[i]);
    }
    printf("\n");

    ciphertext_len = encrypt_aes_256_gcm((unsigned char *)buf, len, ag->key, ag->iv, ciphertext);

    if (ciphertext_len < 0)
    {
        perror("Encryption failed");
        return -1;
    }

    printf("Ciphertext:");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    if (sendvl(sockfd, ag->iv, GCM_IV_SIZE) < 0)
    {
        perror("Send IV failed");
        return -1;
    }

    if (sendvl(sockfd, ciphertext, ciphertext_len) < 0)
    {
        perror("Send ciphertext failed");
        return -1;
    }

    return len;
}