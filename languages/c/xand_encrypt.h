#ifndef XAND_ENCRYPT_H
#define XAND_ENCRYPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum sizes for our encrypted data
#define XAND_MAX_DATA_SIZE 4096
#define XAND_KEY_SIZE 32
#define XAND_NONCE_SIZE 16
#define XAND_PADDING_SIZE 16
#define XAND_IV_SIZE 16

// Structure to hold our encrypted data
typedef struct {
    char encrypted[XAND_MAX_DATA_SIZE];
    char iv[XAND_IV_SIZE];
    char nonce[XAND_NONCE_SIZE];
    uint64_t timestamp;
    size_t padding_length;
    size_t encrypted_length;
} xand_encrypted_data_t;

// Structure to hold our encryption context
typedef struct {
    char password[256];
    uint8_t key_size;
    uint8_t nonce_size;
    uint8_t padding_size;
} xand_encrypt_t;

/**
 * Initialize the encryption system with a password
 * This sets up everything we need to start encrypting and decrypting
 */
int xand_init(xand_encrypt_t* ctx, const char* password);

/**
 * Encrypt some data using our triple-layer approach
 * This is the main function you'll call to protect your data
 */
int xand_encrypt(xand_encrypt_t* ctx, const char* data, size_t data_len, xand_encrypted_data_t* result);

/**
 * Decrypt data that was encrypted with xand_encrypt
 * This reverses all three layers to get your original data back
 */
int xand_decrypt(xand_encrypt_t* ctx, const xand_encrypted_data_t* encrypted_data, char* result, size_t* result_len);

/**
 * Generate a key pair for asymmetric operations
 * This creates a public and private key for advanced use cases
 */
int xand_generate_key_pair(char* private_key, char* public_key);

/**
 * Convert encrypted data to a JSON string for easy storage
 * This makes it simple to save encrypted data to files or databases
 */
int xand_to_json(const xand_encrypted_data_t* data, char* json_buffer, size_t buffer_size);

/**
 * Parse JSON string back into encrypted data structure
 * This lets you load encrypted data from files or databases
 */
int xand_from_json(const char* json_string, xand_encrypted_data_t* data);

/**
 * Clean up any resources used by the encryption context
 * Call this when you're done with encryption to be tidy
 */
void xand_cleanup(xand_encrypt_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // XAND_ENCRYPT_H 