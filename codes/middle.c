#include "middle.h"

int main(int argc, char *argv[])
{
    /***
     *
     */

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int server_sockfd;
    struct sockaddr_in serv_addr;

    // 创建套接字
    if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    // 连接服务器
    if (connect(server_sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("Connection failed");
        close(server_sockfd);
        exit(EXIT_FAILURE);
    }

    aes256_gcm server_ag;
    aes256_gcm_init(&server_ag);

    int is_secure = generate_symmertic_key(server_sockfd, CLIENT_TAG, &server_ag, PUBLIC_KEY_PATH);
    if (is_secure < 0)
    {
        perror("generate_symmertic_key failed");
    }

    /***
     * 面向客户端进行监听
     */

    int client_sockfd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 创建套接字文件描述符
    if ((client_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Create socket failed.");
        exit(EXIT_FAILURE);
    }

    // 设置地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(server_port);

    // 绑定套接字到地址和端口
    if (bind(client_sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        close(client_sockfd);
        exit(EXIT_FAILURE);
    }

    // 获取绑定后的地址信息
    if (getsockname(client_sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen) == -1)
    {
        perror("Getsockname failed");
        close(client_sockfd);
        exit(EXIT_FAILURE);
    }

    // 将地址转换为字符串形式
    char *ip_address = inet_ntoa(address.sin_addr);

    // 监听端口
    if (listen(client_sockfd, BACKLOG) < 0)
    {
        perror("Listen failed");
        close(client_sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Server listening on %s:%d\n", ip_address, server_port);

    while (1)
    {
        int client_fd;
        unsigned char buffer[PLAINTEXT_LENGTH];
        ssize_t read_size;

        // 接受客户端连接
        if ((client_fd = accept(client_sockfd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("Accept failed");
            continue;
        }

        // 打印客户端连接信息
        printf("New connection accepted from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // 获取并打印客户端地址和端口信息
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        if (getpeername(client_fd, (struct sockaddr *)&client_addr, &client_addr_len) == -1)
        {
            perror("Getpeername failed");
            close(client_fd);
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);

        aes256_gcm client_ag;
        aes256_gcm_init(&client_ag);

        int is_secure = generate_symmertic_key(client_fd, SERVER_TAG, &client_ag, "");
        if (is_secure < 0)
        {
            perror("generate_symmertic_key failed");
        }

        // 接收和处理客户端消息
        while ((read_size = decrypt_recvvl(client_fd, buffer, &client_ag, "")) > 0)
        {
            buffer[read_size] = '\0';
            printf("%s:%d %s\n", client_ip, client_port, buffer);
            printf("%s:%d client nleft:%d\n", client_ip, client_port, client_ag.nleft);

            // 发送给服务器
            if (encrypt_sendvl(server_sockfd, buffer, read_size, &server_ag, "") < 0)
            {
                perror("Send failed");
                break;
            }
            printf("server nleft:%d\n", server_ag.nleft);
        }

        if (read_size == 0)
        {
            printf("%s:%d disconnected\n", client_ip, client_port);
        }
        else if (read_size == -1)
        {
            perror("handle client, recv failed");
        }

        aes256_gcm_clear(&client_ag);

        close(client_fd);
    }

    // char buffer[BUFFER_SIZE];
    // while (1)
    // {
    //     printf("Enter message: ");
    //     fgets(buffer, sizeof(buffer), stdin);
    //     size_t len = strlen(buffer);

    //     if (buffer[len - 1] == '\n')
    //     {
    //         buffer[len - 1] = '\0';
    //         len--;
    //     }

    //     if (len == 0)
    //     {
    //         continue; // 空消息，不发送
    //     }

    //     // 发送变长消息
    //     // if (sendvl(server_sockfd, buffer, len) < 0)
    //     // {
    //     //     perror("Send failed");
    //     //     break;
    //     // }

    //     if (encrypt_sendvl(server_sockfd, buffer, len, &server_ag, "") < 0)
    //     {
    //         perror("Send failed");
    //         break;
    //     }

    //     printf("nleft:%d\n", server_ag.nleft);
    // }

    aes256_gcm_clear(&server_ag);
    close(server_sockfd);
    close(client_sockfd);
    return 0;
}