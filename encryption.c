#include "encryption.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Encrypts a buffer using AES-256-CBC.
 * 
 * This function encrypts the input plaintext buffer using the AES-256-CBC encryption algorithm.
 * The encryption process requires a 256-bit (32 bytes) key and a 128-bit (16 bytes) initialization vector (IV).
 * 
 * @param plaintext The buffer containing the data to be encrypted.
 * @param plaintext_len The length of the plaintext buffer in bytes.
 * @param key The encryption key (32 bytes for AES-256).
 * @param iv The initialization vector (16 bytes for AES-CBC).
 * @param ciphertext The buffer where the encrypted data will be stored.
 * @return The length of the encrypted ciphertext on success, or -1 if an error occurs.
 */
int encrypt_buffer(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    // Create and initialize a cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    // Initialize the encryption operation with AES-256-CBC, using the key and IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        perror("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, ciphertext_len = 0;

    // Encrypt the plaintext in chunks
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption to handle any remaining data
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        perror("EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
    return ciphertext_len;
}
