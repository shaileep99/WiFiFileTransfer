#include "decryption.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Decrypts a buffer using AES-256-CBC.
 * 
 * This function decrypts a given ciphertext buffer using the AES-256-CBC encryption algorithm.
 * It uses the provided key and initialization vector (IV) to perform decryption.
 * 
 * @param ciphertext The buffer containing the encrypted data.
 * @param ciphertext_len The length of the ciphertext buffer.
 * @param key The decryption key (must be 256 bits / 32 bytes for AES-256).
 * @param iv The initialization vector (must be 128 bits / 16 bytes for AES-CBC).
 * @param plaintext The buffer where the decrypted data will be stored.
 * @return The length of the decrypted plaintext on success, or an error message via `handle_error` if decryption fails.
 */

int decrypt_buffer(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {
    // Create and initialize a cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_error("EVP_CIPHER_CTX_new failed");

    // Initialize the decryption operation with AES-256-CBC, using the key and IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_error("EVP_DecryptInit_ex failed");

    int len = 0, plaintext_len = 0;

    // Decrypt the ciphertext in chunks
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handle_error("EVP_DecryptUpdate failed");
    plaintext_len = len;

    // Finalize the decryption to handle any remaining padding
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handle_error("EVP_DecryptFinal_ex failed");
    plaintext_len += len;

    // Free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
