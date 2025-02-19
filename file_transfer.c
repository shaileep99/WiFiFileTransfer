#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include "encryption.h"
#include "decryption.h"

#define MAX_PATH 1024
#define MAX_BUFFER 4096
#define PORT 2126
#define RECEIVE_DIR "received_files"
#define MAX_RETRIES 3
#define AES_KEY_SIZE 32 // AES-256 key size
#define AES_BLOCK_SIZE 16

/**
 * @brief Configuration structure for file transfer.
 * 
 * This structure contains essential configuration details for the file transfer process,
 * including the shared directory path, port, server socket, and a mutex for logging.
 */
typedef struct {
    char shared_directory[MAX_PATH];
    int port;
    int server_socket;
    pthread_mutex_t log_mutex;
} FileTransferConfig;

/**
 * @brief Logs a message with a timestamp and severity level.
 * 
 * @param level The severity level of the log (e.g., INFO, ERROR).
 * @param message The log message to record.
 */
void log_message(const char* level, const char* message) {
    time_t now;
    time(&now);
    char* date = ctime(&now);
    date[strlen(date) - 1] = '\0';  // Remove newline
    fprintf(stderr, "%s - %s - %s\n", date, level, message);
}

/**
 * @brief Wrapper function for error handling with logging.
 * 
 * Logs an error message and prints a system error message using `perror`.
 * 
 * @param message The error message to log.
 */
void handle_error(const char* message) {
    perror(message);
    log_message("ERROR", message);
}

/**
 * @brief Creates the directory for receiving files.
 * 
 * Checks if the directory exists and creates it if it does not.
 * 
 * @param config Pointer to the file transfer configuration structure.
 * @return 1 if the directory is created or exists, 0 on failure.
 */
int create_receive_directory(FileTransferConfig* config) {
    struct stat st = {0};
    if (stat(config->shared_directory, &st) == -1) {
        if (mkdir(config->shared_directory, 0700) == -1) {
            handle_error("Error creating receive directory");
            return 0;
        }
        log_message("INFO", "Created receiving directory");
    }
    return 1;
}

/**
 * @brief Gets the local IP address of the machine.
 * 
 * Establishes a UDP connection to an external server to determine the local IP address.
 * 
 * @param ip_buffer Buffer to store the local IP address.
 * @param buffer_size Size of the buffer.
 * @return 1 on success, 0 on failure.
 */
int get_local_ip(char* ip_buffer, size_t buffer_size) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        handle_error("Socket creation error");
        return 0;
    }

    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_server);
    serv.sin_port = htons(dns_port);

    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) < 0) {
        handle_error("Connection error");
        close(sock);
        return 0;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr*)&name, &namelen) < 0) {
        handle_error("getsockname error");
        close(sock);
        return 0;
    }

    inet_ntop(AF_INET, &name.sin_addr, ip_buffer, buffer_size);
    close(sock);
    return 1;
}


/**
 * @brief Sends a file over a socket using AES-256 encryption.
 * 
 * Encrypts the file contents and transfers it to the target IP and port.
 * 
 * @param target_ip The IP address of the target machine.
 * @param file_path The path of the file to send.
 * @param port The target port to connect to.
 * @return 1 on success, 0 on failure.
 */
int send_file_socket(const char* target_ip, const char* file_path, int port) {
    int local_file = open(file_path, O_RDONLY);
    if (local_file < 0) {
        handle_error("Cannot open local file");
        return 0;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        handle_error("Socket creation error");
        close(local_file);
        return 0;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) {
        handle_error("Invalid address / Address not supported");
        close(local_file);
        close(sock);
        return 0;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Connection failed");
        close(local_file);
        close(sock);
        return 0;
    }

    const char* filename = strrchr(file_path, '/');
    filename = filename ? filename + 1 : file_path;
    if (send(sock, filename, strlen(filename) + 1, 0) < 0) {
        handle_error("Failed to send filename");
        close(local_file);
        close(sock);
        return 0;
    }

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        handle_error("Failed to generate AES key and IV");
        close(local_file);
        close(sock);
        return 0;
    }

    if (send(sock, key, sizeof(key), 0) < 0 || send(sock, iv, sizeof(iv), 0) < 0) {
        handle_error("Failed to send encryption key or IV");
        close(local_file);
        close(sock);
        return 0;
    }

    char buffer[MAX_BUFFER];
    unsigned char encrypted_buffer[MAX_BUFFER + AES_BLOCK_SIZE];
    ssize_t bytes_read, encrypted_bytes, total_sent = 0;

    while ((bytes_read = read(local_file, buffer, sizeof(buffer))) > 0) {
        encrypted_bytes = encrypt_buffer((unsigned char*)buffer, bytes_read, key, iv, encrypted_buffer);
        if (encrypted_bytes < 0) {
            handle_error("Encryption failed");
            close(local_file);
            close(sock);
            return 0;
        }

        if (send(sock, encrypted_buffer, encrypted_bytes, 0) < 0) {
            handle_error("Send failed");
            close(local_file);
            close(sock);
            return 0;
        }

        total_sent += encrypted_bytes;
    }

    close(local_file);
    close(sock);

    printf("File '%s' encrypted and sent successfully.\n", filename);
    return 1;
}



void list_received_files(const char* directory) {
    DIR* dir;
    struct dirent* entry;
    struct stat file_stat;
    char full_path[MAX_PATH];

    printf("Files in %s:\n", directory);
    dir = opendir(directory);
    if (dir == NULL) {
        handle_error("Could not open directory");
        return;
    }

    int file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {  // Regular file
            snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);
            if (stat(full_path, &file_stat) == 0) {
                printf("%d. %s (%.1f KB)\n", 
                    ++file_count, 
                    entry->d_name, 
                    file_stat.st_size / 1024.0);
            }
        }
    }

    if (file_count == 0) {
        printf("No files received yet.\n");
    }

    closedir(dir);
}


void* file_receive_thread(void* arg) {
    FileTransferConfig* config = (FileTransferConfig*)arg;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[MAX_BUFFER];
    char filepath[MAX_PATH];

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        handle_error("Failed to create socket");
        return NULL;
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        handle_error("Failed to set socket options");
        close(server_sock);
        return NULL;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Bind failed");
        close(server_sock);
        return NULL;
    }

    if (listen(server_sock, 3) < 0) {
        handle_error("Listen failed");
        close(server_sock);
        return NULL;
    }

    log_message("INFO", "File receive thread started");

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            handle_error("Accept failed");
            continue;
        }

        // Receive filename
        ssize_t filename_len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (filename_len <= 0) {
            close(client_sock);
            continue;
        }
        buffer[filename_len] = '\0';

        snprintf(filepath, sizeof(filepath), "%s/%s", config->shared_directory, buffer);

        // Receive AES key and IV
        unsigned char key[AES_KEY_SIZE];
        unsigned char iv[AES_BLOCK_SIZE];
        if (recv(client_sock, key, sizeof(key), 0) <= 0 || recv(client_sock, iv, sizeof(iv), 0) <= 0) {
            handle_error("Failed to receive encryption key or IV");
            close(client_sock);
            continue;
        }

        FILE* received_file = fopen(filepath, "wb");
        if (received_file == NULL) {
            handle_error("Cannot create file");
            close(client_sock);
            continue;
        }

        // Receive and decrypt file data
        ssize_t bytes_received;
        unsigned char decrypted_buffer[MAX_BUFFER];
        while ((bytes_received = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
            int decrypted_bytes = decrypt_buffer((unsigned char*)buffer, bytes_received, key, iv, decrypted_buffer);
            fwrite(decrypted_buffer, 1, decrypted_bytes, received_file);
        }

        fclose(received_file);
        close(client_sock);

        log_message("INFO", "File received and decrypted successfully");
        printf("File '%s' received and decrypted successfully.\n", received_file);

    }

    close(server_sock);
    return NULL;
}
// Clear input buffer
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

// Command-line interface
void handle_cli(FileTransferConfig* config) {
    char target_ip[INET_ADDRSTRLEN];
    char file_path[MAX_PATH];
    char local_ip[INET_ADDRSTRLEN];
    int choice;

    get_local_ip(local_ip, sizeof(local_ip));

    printf("\n========= Simple File Transfer =========\n");
    printf("Your IP: %s\n", local_ip);
    printf("Port: %d\n", config->port);
    printf("Receiving files in: %s\n", config->shared_directory);
    printf("=======================================\n");

    while (1) {
        printf("\nMenu:\n");
        printf("1. Send file\n");
        printf("2. Show received files\n");
        printf("3. Show my IP\n");
        printf("4. Exit\n");

        printf("\nEnter choice (1-4): ");
        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("Invalid input. Please enter a number.\n");
            continue;
        }
        getchar();  // Consume newline

        switch (choice) {
            case 1: {
                printf("Enter target IP: ");
                if (fgets(target_ip, sizeof(target_ip), stdin) == NULL) {
                    printf("Input error. Please try again.\n");
                    continue;
                }
                target_ip[strcspn(target_ip, "\n")] = 0;

                printf("Enter file path to send: ");
                clear_input_buffer();
                if (fgets(file_path, sizeof(file_path), stdin) == NULL) {
                    printf("Input error. Please try again.\n");
                    continue;
                }
                file_path[strcspn(file_path, "\n")] = 0;

                if (access(file_path, F_OK) == -1) {
                    printf("File does not exist. Please check the path.\n");
                    continue;
                }

                if (!send_file_socket(target_ip, file_path, config->port)) {
                    printf("File transfer failed.\n");
                }
                break;
            }
            case 2:
                list_received_files(config->shared_directory);
                break;

            case 3:
                printf("\nYour IP: %s\n", local_ip);
                break;

            case 4:
                printf("\nStopping...\n");
                return;

            default:
                printf("Invalid choice. Please enter a number between 1 and 4.\n");
        }
    }
}

// Main function
int main() {
    FileTransferConfig config = {0};
    strcpy(config.shared_directory, RECEIVE_DIR);
    config.port = PORT;

    if (!create_receive_directory(&config)) {
        return 1;
    }

    pthread_t receive_thread;
    if (pthread_create(&receive_thread, NULL, file_receive_thread, &config) != 0) {
        handle_error("Failed to create receive thread");
        return 1;
    }

    handle_cli(&config);

    pthread_cancel(receive_thread);
    pthread_join(receive_thread, NULL);

    return 0;
}