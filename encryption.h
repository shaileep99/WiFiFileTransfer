#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
/**
 * @file encryption.h
 * @brief Header file for AES-256-CBC encryption functionality.
 * 
 * This file declares the function used for encrypting data using the
 * AES-256-CBC encryption algorithm. It serves as the interface for the
 * encryption logic implemented in `encryption.c`.
 */

/**
 * @brief Encrypts a buffer using AES-256-CBC.
 * 
 * This function encrypts the input plaintext buffer using the AES-256-CBC
 * encryption algorithm. It requires a 256-bit (32 bytes) encryption key
 * and a 128-bit (16 bytes) initialization vector (IV).
 * 
 * @param plaintext The buffer containing the data to be encrypted.
 * @param plaintext_len The length of the plaintext buffer in bytes.
 * @param key The encryption key (32 bytes for AES-256).
 * @param iv The initialization vector (16 bytes for AES-CBC).
 * @param ciphertext The buffer where the encrypted data will be stored.
 * @return The length of the encrypted ciphertext on success, or -1 if an error occurs.
 */
int encrypt_buffer(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);

#endif