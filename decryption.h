#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <openssl/evp.h>
/*
 * @file decryption.h
 * @brief Header file for AES-256-CBC decryption functionality.
 * 
 * This file declares the function used for decrypting encrypted data using
 * the AES-256-CBC encryption algorithm. It serves as the interface for decryption
 * logic implemented in the `decryption.c` file.
 */

/**
 * @brief Decrypts a buffer using AES-256-CBC.
 * 
 * This function decrypts the input ciphertext buffer using the AES-256-CBC
 * encryption algorithm. It requires a 256-bit (32 bytes) key and a 128-bit (16 bytes)
 * initialization vector (IV) for decryption.
 * 
 * @param ciphertext The buffer containing the encrypted data.
 * @param ciphertext_len The length of the ciphertext buffer in bytes.
 * @param key The decryption key (32 bytes for AES-256).
 * @param iv The initialization vector (16 bytes for AES-CBC).
 * @param plaintext The buffer where the decrypted plaintext will be stored.
 * @return The length of the decrypted plaintext on success. If decryption fails, 
 *         it logs an error and returns an appropriate error code.
 */
int decrypt_buffer(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

#endif
