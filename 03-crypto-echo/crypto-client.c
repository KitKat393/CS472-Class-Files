#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include "crypto-client.h"
#include "crypto-lib.h"
#include "protocol.h"

#define SEND_BUFFER_SIZE 4096
#define RECV_BUFFER_SIZE 4096


static int client_loop(int socket_fd);
static int build_packet(const msg_cmd_t *cmd,
                        crypto_msg_t *pdu,
                        crypto_key_t session_key);


/* =============================================================================
 * STUDENT TODO: IMPLEMENT THIS FUNCTION
 * =============================================================================
 * This is the main client function. You need to:
 * 1. Create a TCP socket
 * 2. Connect to the server
 * 3. Call your communication loop
 * 4. Clean up and close the socket
 * 
 * Parameters:
 *   addr - Server IP address (e.g., "127.0.0.1")
 *   port - Server port number (e.g., 1234)
 */
void start_client(const char* addr, int port) {

    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr, &server_addr.sin_addr) <= 0) {
        perror("inet_pton() failed");
        close(sockfd);
        return;
    }

    if (connect(sockfd,
                (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("connect() failed");
        close(sockfd);
        return;
    }

    printf("[INFO] Connected to %s:%d\n", addr, port);

    client_loop(sockfd);

    close(sockfd);
    printf("[INFO] Disconnected from server\n");
}


static int client_loop(int socket_fd)
{
    uint8_t *send_buffer = malloc(SEND_BUFFER_SIZE);
    uint8_t *recv_buffer = malloc(RECV_BUFFER_SIZE);
    char input_buffer[MAX_MSG_DATA_SIZE];

    if (!send_buffer || !recv_buffer) {
        perror("malloc failed");
        return -1;
    }

    crypto_key_t session_key = NULL_CRYPTO_KEY;
    msg_cmd_t command;

    while (1) {

        int cmd_status = get_command(input_buffer,
                                     sizeof(input_buffer),
                                     &command);

        if (cmd_status == CMD_NO_EXEC)
            continue;

        crypto_msg_t *pdu = (crypto_msg_t*)send_buffer;

        int pdu_size = build_packet(&command, pdu, session_key);
        if (pdu_size < 0) {
            printf("[ERROR] Failed to build packet\n");
            continue;
        }

        print_msg_info(pdu, session_key, CLIENT_MODE);

        int sent = send(socket_fd, send_buffer, pdu_size, 0);
        if (sent <= 0) {
            perror("send() failed");
            break;
        }

        if (command.cmd_id == MSG_CMD_CLIENT_STOP)
            break;

        int received = recv(socket_fd,
                            recv_buffer,
                            sizeof(crypto_pdu_t),
                            0);

        if (received == 0) {
            printf("[INFO] Server closed connection\n");
            break;
        }

        if (received < 0) {
            perror("recv() failed");
            break;
        }

        crypto_msg_t *response = (crypto_msg_t*)recv_buffer;
        uint16_t payload_len = response->header.payload_len;

        if (payload_len > 0) {
            int total = 0;
            while (total < payload_len) {
                int r = recv(socket_fd,
                             recv_buffer + sizeof(crypto_pdu_t) + total,
                             payload_len - total,
                             0);
                if (r <= 0) {
                    perror("recv() payload failed");
                    goto cleanup;
                }
                total += r;
            }
        }

        print_msg_info(response, session_key, CLIENT_MODE);

        switch (response->header.msg_type) {

            case MSG_KEY_EXCHANGE:
                if (payload_len == sizeof(crypto_key_t)) {
                    memcpy(&session_key,
                           response->payload,
                           sizeof(crypto_key_t));
                    printf("[INFO] Session key received\n");
                }
                break;

            case MSG_DATA:
                if (payload_len > 0) {
                    printf("[SERVER]: %.*s\n",
                           payload_len,
                           response->payload);
                }
                break;

            case MSG_ENCRYPTED_DATA:
                if (session_key == NULL_CRYPTO_KEY)
                    break;

                if (payload_len > 0) {
                    uint8_t decrypted[MAX_MSG_DATA_SIZE];
                    int dec_len = decrypt_string(session_key,
                                                 decrypted,
                                                 response->payload,
                                                 payload_len);
                    if (dec_len >= 0) {
                        decrypted[dec_len] = '\0';
                        printf("[SERVER - DECRYPTED]: %s\n", decrypted);
                    }
                }
                break;

            case MSG_CMD_SERVER_STOP:
                goto cleanup;

            default:
                break;
        }
    }

cleanup:
    free(send_buffer);
    free(recv_buffer);
    return 0;
}


static int build_packet(const msg_cmd_t *cmd,
                        crypto_msg_t *pdu,
                        crypto_key_t session_key)
{
    if (!cmd || !pdu)
        return -1;

    pdu->header.msg_type = cmd->cmd_id;
    pdu->header.direction = DIR_REQUEST;
    pdu->header.payload_len = 0;

    int payload_len = 0;

    switch (cmd->cmd_id) {

        case MSG_DATA:
            if (cmd->cmd_line) {
                payload_len = strlen(cmd->cmd_line);
                memcpy(pdu->payload,
                       cmd->cmd_line,
                       payload_len);
            }
            break;

        case MSG_ENCRYPTED_DATA:
            if (session_key == NULL_CRYPTO_KEY)
                return -1;

            if (cmd->cmd_line) {
                int enc_len = encrypt_string(session_key,
                                             pdu->payload,
                                             (uint8_t*)cmd->cmd_line,
                                             strlen(cmd->cmd_line));
                if (enc_len < 0)
                    return -1;
                payload_len = enc_len;
            }
            break;

        case MSG_KEY_EXCHANGE:
        case MSG_CMD_CLIENT_STOP:
        case MSG_CMD_SERVER_STOP:
            payload_len = 0;
            break;

        default:
            return -1;
    }

    pdu->header.payload_len = payload_len;

    return sizeof(crypto_pdu_t) + payload_len;
}


int get_command(char *cmd_buff, size_t cmd_buff_sz, msg_cmd_t *msg_cmd)
{
    if ((cmd_buff == NULL) || (cmd_buff_sz == 0)) return CMD_NO_EXEC;

    printf("> ");
    fflush(stdout);
    
    // Get input from user
    if (fgets(cmd_buff, cmd_buff_sz, stdin) == NULL) {
        printf("[WARNING] Error reading input command.\n\n");
        return CMD_NO_EXEC;
    }
    
    // Remove trailing newline
    cmd_buff[strcspn(cmd_buff, "\n")] = '\0';

    // Interpret the command based on first character
    switch (cmd_buff[0]) {
        case '!':
            // Encrypted message - everything after '!' is the message
            msg_cmd->cmd_id = MSG_ENCRYPTED_DATA;
            msg_cmd->cmd_line = cmd_buff + 1; // Skip the '!' character
            return CMD_EXECUTE;
            
        case '#':
            // Key exchange request - no message data
            msg_cmd->cmd_id = MSG_KEY_EXCHANGE;
            msg_cmd->cmd_line = NULL;
            return CMD_EXECUTE;
            
        case '$':
            // Digital signature (not implemented in this assignment)
            msg_cmd->cmd_id = MSG_DIG_SIGNATURE;
            msg_cmd->cmd_line = NULL;
            printf("[INFO] Digital signature command not implemented yet.\n\n");
            return CMD_NO_EXEC;
            
        case '-':
            // Client exit command
            msg_cmd->cmd_id = MSG_CMD_CLIENT_STOP;
            msg_cmd->cmd_line = NULL;
            return CMD_EXECUTE;
            
        case '=':
            // Server shutdown command
            msg_cmd->cmd_id = MSG_CMD_SERVER_STOP;
            msg_cmd->cmd_line = NULL;
            return CMD_EXECUTE;
            
        case '?':
            // Help - display available commands
            msg_cmd->cmd_id = MSG_HELP_CMD;
            msg_cmd->cmd_line = NULL;
            printf("Available commands:\n");
            printf("  <message>  : Send plain text message\n");
            printf("  !<message> : Send encrypted message (requires key exchange first)\n");
            printf("  #          : Request key exchange from server\n");
            printf("  ?          : Show this help message\n");
            printf("  -          : Exit the client\n");
            printf("  =          : Exit the client and request server shutdown\n\n");
            return CMD_NO_EXEC;
            
        default:
            // Regular text message
            msg_cmd->cmd_id = MSG_DATA;
            msg_cmd->cmd_line = cmd_buff;
            return CMD_EXECUTE;
    }
    
    return CMD_NO_EXEC;
}
