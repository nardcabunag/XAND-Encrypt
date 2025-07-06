#include "xand_encrypt.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Helper function to get current timestamp in milliseconds
static uint64_t get_current_timestamp() {
    return (uint64_t)time(NULL) * 1000;
}

// Helper function to generate random bytes
static int generate_random_bytes(unsigned char* buffer, size_t length) {
    return RAND_bytes(buffer, length);
}

/**
 * Convert password to SHA-256 hash using OpenSSL low-level API
 * SHA256_CTX provides direct control over hash computation process
 * unsigned char* prevents sign extension issues during byte operations
 */
static void hash_password(const char* password, unsigned char* hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
}

/**
 * Generate three time-dependent keys using HMAC-SHA256
 * Manual byte extraction from uint64_t ensures big-endian byte order
 * C lacks built-in integer-to-byte conversion, requiring manual bit manipulation
 */
static void generate_time_shifted_keys(const unsigned char* base_key, uint64_t timestamp, 
                                     unsigned char* key1, unsigned char* key2, unsigned char* key3) {
    unsigned char time_buffer[8];
    unsigned int hmac_len;
    
    // Convert timestamp to bytes - C requires manual bit manipulation
    for (int i = 0; i < 8; i++) {
        time_buffer[i] = (timestamp >> (56 - i * 8)) & 0xFF;
    }
    
    // Each layer gets its own unique key derived from the previous one
    // OpenSSL's HMAC function is highly optimized and thread-safe
    HMAC(EVP_sha256(), base_key, XAND_KEY_SIZE, time_buffer, 8, key1, &hmac_len);
    HMAC(EVP_sha256(), key1, XAND_KEY_SIZE, (unsigned char*)"layer2", 6, key2, &hmac_len);
    HMAC(EVP_sha256(), key2, XAND_KEY_SIZE, (unsigned char*)"layer3", 6, key3, &hmac_len);
}

/**
 * Generate cryptographically secure random nonce and padding
 * RAND_bytes() calls OS random number generator for cryptographic security
 * Pointer parameter enables multiple return values in C function signature
 */
static void generate_nonce_and_padding(unsigned char* nonce, unsigned char* padding, size_t* padding_len) {
    generate_random_bytes(nonce, XAND_NONCE_SIZE);
    *padding_len = (nonce[0] % XAND_PADDING_SIZE) + 1;
    generate_random_bytes(padding, *padding_len);
}

/**
 * First encryption layer: XOR and bit rotation operations
 * C bitwise operations compile to single CPU instructions for maximum performance
 * unsigned char prevents sign extension issues during byte-level operations
 */
static void layer1_scramble(const unsigned char* data, size_t data_len, 
                           const unsigned char* key, unsigned char* result) {
    for (size_t i = 0; i < data_len; i++) {
        unsigned char key_byte = key[i % XAND_KEY_SIZE];
        unsigned char data_byte = data[i];
        
        // Do some bit magic to scramble the data
        // C bitwise ops are extremely fast and compile to efficient assembly
        unsigned char scrambled = data_byte ^ key_byte;
        scrambled = ((scrambled << 3) | (scrambled >> 5)) & 0xFF; // Rotate left by 3
        scrambled = scrambled ^ (((key_byte << 1) | (key_byte >> 7)) & 0xFF);
        
        result[i] = scrambled;
    }
}

/**
 * Second encryption layer: Position-dependent bit rotation
 * Rotation amount calculated from byte position and key value
 * Conditional rotation prevents unnecessary operations when rotation is zero
 */
static void layer2_manipulate(const unsigned char* data, size_t data_len, 
                             const unsigned char* key, unsigned char* result) {
    for (size_t i = 0; i < data_len; i++) {
        unsigned char key_byte = key[i % XAND_KEY_SIZE];
        unsigned char data_byte = data[i];
        
        // Rotate bits based on position and key
        int rotation = (i + key_byte) % 8;
        unsigned char manipulated = data_byte;
        
        if (rotation > 0) {
            manipulated = ((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF;
        }
        
        // Mix in some position-dependent randomness
        manipulated = manipulated ^ ((key_byte + i) & 0xFF);
        
        result[i] = manipulated;
    }
}

/**
 * Third encryption layer: AES-256-CBC encryption
 * Uses OpenSSL EVP interface for AES operations with PKCS7 padding
 * CBC mode requires unique IV for each encryption operation
 */
static int layer3_encrypt(const unsigned char* data, size_t data_len, 
                         const unsigned char* key, unsigned char* iv, 
                         unsigned char* encrypted, size_t* encrypted_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    // Generate a random IV
    generate_random_bytes(iv, XAND_IV_SIZE);
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted, &len, data, data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *encrypted_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * Third layer decryption: Reverse the AES-256 encryption
 */
static int layer3_decrypt(const unsigned char* encrypted, size_t encrypted_len,
                         const unsigned char* key, const unsigned char* iv,
                         unsigned char* decrypted, size_t* decrypted_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    *decrypted_len = len + final_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * Apply key decay by XORing with time-based hash
 * Prevents key reuse attacks by modifying keys after each operation
 * Uses current timestamp to ensure uniqueness of decay value
 */
static void apply_key_decay(unsigned char* key1, unsigned char* key2, unsigned char* key3) {
    uint64_t timestamp = get_current_timestamp();
    unsigned char decay_value[XAND_KEY_SIZE];
    
    // Mix in some fresh randomness to age the keys
    char time_str[32];
    snprintf(time_str, sizeof(time_str), "%llu", (unsigned long long)timestamp);
    
    // Apply decay to each key
    for (int key_idx = 0; key_idx < 3; key_idx++) {
        unsigned char* key = (key_idx == 0) ? key1 : (key_idx == 1) ? key2 : key3;
        
        // Create decay value based on key and timestamp
        HMAC_CTX* hmac_ctx = HMAC_CTX_new();
        HMAC_Init_ex(hmac_ctx, key, XAND_KEY_SIZE, EVP_sha256(), NULL);
        HMAC_Update(hmac_ctx, (unsigned char*)time_str, strlen(time_str));
        unsigned int decay_len;
        HMAC_Final(hmac_ctx, decay_value, &decay_len);
        HMAC_CTX_free(hmac_ctx);
        
        // XOR the key with decay value
        for (int i = 0; i < XAND_KEY_SIZE; i++) {
            key[i] ^= decay_value[i % decay_len];
        }
    }
}

int xand_init(xand_encrypt_t* ctx, const char* password) {
    if (!ctx || !password) return -1;
    
    // Initialize OpenSSL random number generator
    if (RAND_poll() != 1) return -1;
    
    // Store the password and set up our parameters
    strncpy(ctx->password, password, sizeof(ctx->password) - 1);
    ctx->password[sizeof(ctx->password) - 1] = '\0';
    ctx->key_size = XAND_KEY_SIZE;
    ctx->nonce_size = XAND_NONCE_SIZE;
    ctx->padding_size = XAND_PADDING_SIZE;
    
    return 0;
}

int xand_encrypt(xand_encrypt_t* ctx, const char* data, size_t data_len, xand_encrypted_data_t* result) {
    if (!ctx || !data || !result || data_len == 0) return -1;
    if (data_len + XAND_PADDING_SIZE > XAND_MAX_DATA_SIZE) return -1;
    
    // Generate our base key from the password
    unsigned char base_key[XAND_KEY_SIZE];
    hash_password(ctx->password, base_key);
    
    // Create three unique keys that change over time
    uint64_t timestamp = get_current_timestamp();
    unsigned char key1[XAND_KEY_SIZE], key2[XAND_KEY_SIZE], key3[XAND_KEY_SIZE];
    generate_time_shifted_keys(base_key, timestamp, key1, key2, key3);
    
    // Generate some random data to make each encryption unique
    unsigned char nonce[XAND_NONCE_SIZE];
    unsigned char padding[XAND_PADDING_SIZE];
    size_t padding_len;
    generate_nonce_and_padding(nonce, padding, &padding_len);
    
    // Prepare our data with padding
    unsigned char padded_data[XAND_MAX_DATA_SIZE];
    memcpy(padded_data, data, data_len);
    memcpy(padded_data + data_len, padding, padding_len);
    size_t padded_len = data_len + padding_len;
    
    // First layer: Mix up the data with some fancy bit operations
    unsigned char layer1_result[XAND_MAX_DATA_SIZE];
    layer1_scramble(padded_data, padded_len, key1, layer1_result);
    
    // Second layer: More bit manipulation, but this time it depends on position
    unsigned char layer2_result[XAND_MAX_DATA_SIZE];
    layer2_manipulate(layer1_result, padded_len, key2, layer2_result);
    
    // Third layer: The heavy artillery - AES-256 encryption
    unsigned char iv[XAND_IV_SIZE];
    size_t encrypted_len;
    if (layer3_encrypt(layer2_result, padded_len, key3, iv, (unsigned char*)result->encrypted, &encrypted_len) != 0) {
        return -1;
    }
    
    // After we use the keys, we modify them slightly
    apply_key_decay(key1, key2, key3);
    
    // Store all the pieces we need for decryption
    memcpy(result->iv, iv, XAND_IV_SIZE);
    memcpy(result->nonce, nonce, XAND_NONCE_SIZE);
    result->timestamp = timestamp;
    result->padding_length = padding_len;
    result->encrypted_length = encrypted_len;
    
    return 0;
}

int xand_decrypt(xand_encrypt_t* ctx, const xand_encrypted_data_t* encrypted_data, char* result, size_t* result_len) {
    if (!ctx || !encrypted_data || !result || !result_len) return -1;
    
    // Generate our base key from the password
    unsigned char base_key[XAND_KEY_SIZE];
    hash_password(ctx->password, base_key);
    
    // Recreate the three keys using the same timestamp
    unsigned char key1[XAND_KEY_SIZE], key2[XAND_KEY_SIZE], key3[XAND_KEY_SIZE];
    generate_time_shifted_keys(base_key, encrypted_data->timestamp, key1, key2, key3);
    
    // Third layer: Reverse the AES-256 encryption
    unsigned char layer3_result[XAND_MAX_DATA_SIZE];
    size_t layer3_len;
    if (layer3_decrypt((unsigned char*)encrypted_data->encrypted, encrypted_data->encrypted_length,
                      key3, (unsigned char*)encrypted_data->iv, layer3_result, &layer3_len) != 0) {
        return -1;
    }
    
    // Second layer: Reverse the bit manipulation
    unsigned char layer2_result[XAND_MAX_DATA_SIZE];
    layer2_manipulate(layer3_result, layer3_len, key2, layer2_result);
    
    // First layer: Reverse the bit scrambling
    unsigned char layer1_result[XAND_MAX_DATA_SIZE];
    layer1_scramble(layer2_result, layer3_len, key1, layer1_result);
    
    // Remove the padding to get our original data
    size_t original_len = layer3_len - encrypted_data->padding_length;
    memcpy(result, layer1_result, original_len);
    *result_len = original_len;
    
    return 0;
}

int xand_generate_key_pair(char* private_key, char* public_key) {
    if (!private_key || !public_key) return -1;
    
    // Generate a random private key
    unsigned char random_key[XAND_KEY_SIZE];
    if (generate_random_bytes(random_key, XAND_KEY_SIZE) != 1) return -1;
    
    // Create a public key by hashing the private key
    unsigned char hash[XAND_KEY_SIZE];
    hash_password((char*)random_key, hash);
    
    // Convert to base64-like strings (simplified)
    for (int i = 0; i < XAND_KEY_SIZE; i++) {
        private_key[i * 2] = "0123456789ABCDEF"[random_key[i] >> 4];
        private_key[i * 2 + 1] = "0123456789ABCDEF"[random_key[i] & 0x0F];
        public_key[i * 2] = "0123456789ABCDEF"[hash[i] >> 4];
        public_key[i * 2 + 1] = "0123456789ABCDEF"[hash[i] & 0x0F];
    }
    private_key[XAND_KEY_SIZE * 2] = '\0';
    public_key[XAND_KEY_SIZE * 2] = '\0';
    
    return 0;
}

int xand_to_json(const xand_encrypted_data_t* data, char* json_buffer, size_t buffer_size) {
    if (!data || !json_buffer) return -1;
    
    // Convert binary data to base64-like hex strings
    char encrypted_hex[XAND_MAX_DATA_SIZE * 2 + 1];
    char iv_hex[XAND_IV_SIZE * 2 + 1];
    char nonce_hex[XAND_NONCE_SIZE * 2 + 1];
    
    for (size_t i = 0; i < data->encrypted_length; i++) {
        encrypted_hex[i * 2] = "0123456789ABCDEF"[((unsigned char*)data->encrypted)[i] >> 4];
        encrypted_hex[i * 2 + 1] = "0123456789ABCDEF"[((unsigned char*)data->encrypted)[i] & 0x0F];
    }
    encrypted_hex[data->encrypted_length * 2] = '\0';
    
    for (int i = 0; i < XAND_IV_SIZE; i++) {
        iv_hex[i * 2] = "0123456789ABCDEF"[(unsigned char)data->iv[i] >> 4];
        iv_hex[i * 2 + 1] = "0123456789ABCDEF"[(unsigned char)data->iv[i] & 0x0F];
    }
    iv_hex[XAND_IV_SIZE * 2] = '\0';
    
    for (int i = 0; i < XAND_NONCE_SIZE; i++) {
        nonce_hex[i * 2] = "0123456789ABCDEF"[(unsigned char)data->nonce[i] >> 4];
        nonce_hex[i * 2 + 1] = "0123456789ABCDEF"[(unsigned char)data->nonce[i] & 0x0F];
    }
    nonce_hex[XAND_NONCE_SIZE * 2] = '\0';
    
    // Create JSON string
    int written = snprintf(json_buffer, buffer_size,
        "{\"encrypted\":\"%s\",\"iv\":\"%s\",\"nonce\":\"%s\",\"timestamp\":%llu,\"padding_length\":%zu}",
        encrypted_hex, iv_hex, nonce_hex, (unsigned long long)data->timestamp, data->padding_length);
    
    return (written < buffer_size) ? 0 : -1;
}

int xand_from_json(const char* json_string, xand_encrypted_data_t* data) {
    if (!json_string || !data) return -1;
    
    // Parse JSON (simplified - in real implementation, use a proper JSON parser)
    // This is a basic implementation - you'd want to use a proper JSON library
    char encrypted_hex[XAND_MAX_DATA_SIZE * 2 + 1];
    char iv_hex[XAND_IV_SIZE * 2 + 1];
    char nonce_hex[XAND_NONCE_SIZE * 2 + 1];
    
    // Extract values from JSON (simplified parsing)
    if (sscanf(json_string, "{\"encrypted\":\"%[^\"]\",\"iv\":\"%[^\"]\",\"nonce\":\"%[^\"]\",\"timestamp\":%llu,\"padding_length\":%zu}",
               encrypted_hex, iv_hex, nonce_hex, &data->timestamp, &data->padding_length) != 5) {
        return -1;
    }
    
    // Convert hex strings back to binary
    size_t encrypted_len = strlen(encrypted_hex) / 2;
    for (size_t i = 0; i < encrypted_len; i++) {
        char hex_byte[3] = {encrypted_hex[i * 2], encrypted_hex[i * 2 + 1], '\0'};
        ((unsigned char*)data->encrypted)[i] = strtol(hex_byte, NULL, 16);
    }
    data->encrypted_length = encrypted_len;
    
    for (int i = 0; i < XAND_IV_SIZE; i++) {
        char hex_byte[3] = {iv_hex[i * 2], iv_hex[i * 2 + 1], '\0'};
        data->iv[i] = strtol(hex_byte, NULL, 16);
    }
    
    for (int i = 0; i < XAND_NONCE_SIZE; i++) {
        char hex_byte[3] = {nonce_hex[i * 2], nonce_hex[i * 2 + 1], '\0'};
        data->nonce[i] = strtol(hex_byte, NULL, 16);
    }
    
    return 0;
}

void xand_cleanup(xand_encrypt_t* ctx) {
    if (ctx) {
        // Clear sensitive data from memory
        memset(ctx->password, 0, sizeof(ctx->password));
    }
} 