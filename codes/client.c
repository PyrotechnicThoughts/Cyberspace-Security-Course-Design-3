#include "client.h"

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int sockfd;
    struct sockaddr_in serv_addr;

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    // 将IP地址转换为二进制形式
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 连接服务器
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Connection failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    aes256_gcm ag;
    aes256_gcm_init(&ag);

    int is_secure = generate_symmertic_key(sockfd, CLIENT_TAG, &ag, PUBLIC_KEY_PATH);
    if (is_secure < 0)
    {
        perror("generate_symmertic_key failed");
        return -1;
    }

    char buffer[BUFFER_SIZE];
    while (1)
    {
        printf("Enter message: ");
        fgets(buffer, sizeof(buffer), stdin);
        size_t len = strlen(buffer);

        if (buffer[len - 1] == '\n')
        {
            buffer[len - 1] = '\0';
            len--;
        }

        if (len == 0)
        {
            continue; // 空消息，不发送
        }

        // 发送变长消息
        // if (sendvl(sockfd, buffer, len) < 0)
        // {
        //     perror("Send failed");
        //     break;
        // }

        if (encrypt_sendvl(sockfd, buffer, len, &ag, PUBLIC_KEY_PATH) < 0)
        {
            perror("Send failed");
            break;
        }

        printf("nleft:%d\n", ag.nleft);
    }

    aes256_gcm_clear(&ag);

    close(sockfd);
    return 0;
}
