#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>

#include "crypto-server.h"
#include "crypto-lib.h"
#include "protocol.h"

#define SEND_BUFFER_SIZE 4096
#define RECV_BUFFER_SIZE 4096

static int server_loop(int server_socket, const char* addr, int port);
static int service_client_loop(int client_socket);
static int build_response(crypto_msg_t *request,
                          crypto_msg_t *response,
                          crypto_key_t *client_key,
                          crypto_key_t *server_key);


void start_server(const char* addr, int port) {

    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        return;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() failed");
        close(sockfd);
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (strcmp(addr, "0.0.0.0") == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
            perror("inet_pton() failed");
            close(sockfd);
            return;
        }
    }

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        close(sockfd);
        return;
    }

    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen() failed");
        close(sockfd);
        return;
    }

    printf("Server listening on %s:%d\n", addr, port);

    server_loop(sockfd, addr, port);

    close(sockfd);
}


static int server_loop(int server_socket, const char* addr, int port) {

    while (1) {

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_socket = accept(server_socket,
                                   (struct sockaddr*)&client_addr,
                                   &addr_len);

        if (client_socket < 0) {
            perror("accept() failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,
                  &client_addr.sin_addr,
                  client_ip,
                  INET_ADDRSTRLEN);

        printf("Client connected from %s\n", client_ip);

        int rc = service_client_loop(client_socket);

        close(client_socket);
        printf("Client disconnected\n");

        if (rc == RC_CLIENT_REQ_SERVER_EXIT) {
            printf("Server shutdown requested\n");
            break;
        }
    }

    return 0;
}


static int service_client_loop(int client_socket) {

    uint8_t *recv_buffer = malloc(RECV_BUFFER_SIZE);
    uint8_t *send_buffer = malloc(SEND_BUFFER_SIZE);

    if (!recv_buffer || !send_buffer) {
        perror("malloc failed");
        return RC_CLIENT_EXITED;
    }

    crypto_key_t server_key = NULL_CRYPTO_KEY;
    crypto_key_t client_key = NULL_CRYPTO_KEY;

    while (1) {

        int received = recv(client_socket,
                            recv_buffer,
                            sizeof(crypto_pdu_t),
                            0);

        if (received == 0) {
            free(recv_buffer);
            free(send_buffer);
            return RC_CLIENT_EXITED;
        }

        if (received < 0) {
            perror("recv() failed");
            free(recv_buffer);
            free(send_buffer);
            return RC_CLIENT_EXITED;
        }

        crypto_msg_t *request = (crypto_msg_t*)recv_buffer;
        uint16_t payload_len = request->header.payload_len;

        if (payload_len > 0) {
            int total = 0;
            while (total < payload_len) {
                int r = recv(client_socket,
                             recv_buffer + sizeof(crypto_pdu_t) + total,
                             payload_len - total,
                             0);
                if (r <= 0) {
                    free(recv_buffer);
                    free(send_buffer);
                    return RC_CLIENT_EXITED;
                }
                total += r;
            }
        }

        print_msg_info(request, server_key, SERVER_MODE);

        if (request->header.msg_type == MSG_CMD_SERVER_STOP) {
            free(recv_buffer);
            free(send_buffer);
            return RC_CLIENT_REQ_SERVER_EXIT;
        }

        if (request->header.msg_type == MSG_CMD_CLIENT_STOP) {
            free(recv_buffer);
            free(send_buffer);
            return RC_CLIENT_EXITED;
        }

        crypto_msg_t *response = (crypto_msg_t*)send_buffer;

        int resp_size = build_response(request,
                                       response,
                                       &client_key,
                                       &server_key);

        if (resp_size > 0) {

            print_msg_info(response, server_key, SERVER_MODE);

            if (send(client_socket, send_buffer, resp_size, 0) <= 0) {
                free(recv_buffer);
                free(send_buffer);
                return RC_CLIENT_EXITED;
            }
        }
    }
}


static int build_response(crypto_msg_t *request,
                          crypto_msg_t *response,
                          crypto_key_t *client_key,
                          crypto_key_t *server_key) {

    response->header.direction = DIR_RESPONSE;
    response->header.msg_type = request->header.msg_type;
    response->header.payload_len = 0;

    switch (request->header.msg_type) {

        case MSG_KEY_EXCHANGE: {

            if (gen_key_pair(server_key, client_key) != RC_OK)
                return -1;

            memcpy(response->payload,
                   client_key,
                   sizeof(crypto_key_t));

            response->header.payload_len = sizeof(crypto_key_t);
            break;
        }

        case MSG_DATA: {

            char buffer[MAX_MSG_DATA_SIZE];
            snprintf(buffer,
                     sizeof(buffer),
                     "echo %.*s",
                     request->header.payload_len,
                     request->payload);

            int len = strlen(buffer);

            memcpy(response->payload, buffer, len);
            response->header.payload_len = len;
            break;
        }

        case MSG_ENCRYPTED_DATA: {

            if (*server_key == NULL_CRYPTO_KEY)
                return -1;

            uint8_t decrypted[MAX_MSG_DATA_SIZE];
            int dec_len = decrypt_string(*server_key,
                                         decrypted,
                                         request->payload,
                                         request->header.payload_len);

            if (dec_len < 0)
                return -1;

            decrypted[dec_len] = '\0';

            char echo_buffer[MAX_MSG_DATA_SIZE];
            snprintf(echo_buffer,
                     sizeof(echo_buffer),
                     "echo %s",
                     decrypted);

            uint8_t encrypted[MAX_MSG_DATA_SIZE];
            int enc_len = encrypt_string(*server_key,
                                         encrypted,
                                         (uint8_t*)echo_buffer,
                                         strlen(echo_buffer));

            if (enc_len < 0)
                return -1;

            memcpy(response->payload, encrypted, enc_len);
            response->header.payload_len = enc_len;
            break;
        }

        default:
            return -1;
    }

    return sizeof(crypto_pdu_t) + response->header.payload_len;
}
