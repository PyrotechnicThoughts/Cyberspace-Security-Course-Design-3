#include "server.h"

int main(int argc, char *argv[])
{
    int opt;
    int port = 0;

    while ((opt = getopt(argc, argv, "p:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            port = atoi(optarg);
            break;
        }
    }

    if (port == 0)
    {
        port = 8080;
    }

    int server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 创建套接字文件描述符
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Create socket failed.");
        exit(EXIT_FAILURE);
    }

    // 设置地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // 绑定套接字到地址和端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 获取绑定后的地址信息
    if (getsockname(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen) == -1)
    {
        perror("Getsockname failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 将地址转换为字符串形式
    char *ip_address = inet_ntoa(address.sin_addr);

    // 监听端口
    if (listen(server_fd, BACKLOG) < 0)
    {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on %s:%d\n", ip_address, port);

    while (1)
    {
        int client_fd;

        // 接受客户端连接
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("Accept failed");
            continue;
        }

        // 打印客户端连接信息
        printf("New connection accepted from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // 创建线程处理客户端
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)&client_fd) != 0)
        {
            perror("Pthread_create failed");
            close(client_fd);
        }
        else
        {
            pthread_detach(thread_id); // 让线程在完成后自动释放资源
        }
    }

    close(server_fd);

    return 0;
}

void *handle_client(void *arg)
{
    int client_socket = *(int *)arg;
    unsigned char buffer[PLAINTEXT_LENGTH];
    ssize_t read_size;

    // 获取并打印客户端地址和端口信息
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    if (getpeername(client_socket, (struct sockaddr *)&client_addr, &client_addr_len) == -1)
    {
        perror("Getpeername failed");
        close(client_socket);
        return NULL;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    aes256_gcm ag;
    aes256_gcm_init(&ag);

    int is_secure = generate_symmertic_key(client_socket, SERVER_TAG, &ag, PRIVATE_KEY_PATH);
    if (is_secure < 0)
    {
        perror("generate_symmertic_key failed");
    }

    // 接收和处理客户端消息
    while ((read_size = decrypt_recvvl(client_socket, buffer, &ag, PRIVATE_KEY_PATH)) > 0)
    {
        // printf("read size:%d\n", read_size);
        buffer[read_size] = '\0';
        printf("%s:%d %s\n", client_ip, client_port, buffer);
        printf("%s:%d nleft:%d\n", client_ip, client_port, ag.nleft);

        // 发送回客户端
        // send(client_socket, buffer, read_size, 0);
        // free(buffer); // 释放接收缓冲区
    }

    if (read_size == 0)
    {
        printf("%s:%d disconnected\n", client_ip, client_port);
    }
    else if (read_size == -1)
    {
        perror("handle client, recv failed");
    }

    aes256_gcm_clear(&ag);

    close(client_socket);
    return NULL;
}
