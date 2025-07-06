#include <stdio.h>
#include <string.h>
#include "xand_encrypt.h"

int main() {

    xand_encrypt_t ctx;
    const char* password = "my-secret-password";
    
    if (xand_init(&ctx, password) != 0) {
        printf("Failed to initialize encryption\n");
        return 1;
    }
    
   
    const char* original_data = "Hello, this is a secret message!";
    printf("Original data: %s\n", original_data);
    
    
    xand_encrypted_data_t encrypted_data;
    if (xand_encrypt(&ctx, original_data, strlen(original_data), &encrypted_data) != 0) {
        printf("Failed to encrypt data\n");
        return 1;
    }
    
  
    char json_buffer[4096];
    if (xand_to_json(&encrypted_data, json_buffer, sizeof(json_buffer)) == 0) {
        printf("Encrypted data: %s\n", json_buffer);
    }
    
  
    char decrypted_buffer[1024];
    size_t decrypted_len;
    if (xand_decrypt(&ctx, &encrypted_data, decrypted_buffer, &decrypted_len) != 0) {
        printf("Failed to decrypt data\n");
        return 1;
    }
    
    decrypted_buffer[decrypted_len] = '\0';
    printf("Decrypted data: %s\n", decrypted_buffer);
    

    if (strcmp(original_data, decrypted_buffer) == 0) {
        printf("Data matches: true\n");
    } else {
        printf("Data matches: false\n");
    }
    
   
    xand_encrypted_data_t encrypted_data2;
    if (xand_encrypt(&ctx, original_data, strlen(original_data), &encrypted_data2) == 0) {
        char json_buffer2[4096];
        if (xand_to_json(&encrypted_data2, json_buffer2, sizeof(json_buffer2)) == 0) {
            if (strcmp(json_buffer, json_buffer2) != 0) {
                printf("Different outputs: true\n");
            } else {
                printf("Different outputs: false\n");
            }
        }
    }
    
  
    char private_key[128];
    char public_key[128];
    if (xand_generate_key_pair(private_key, public_key) == 0) {
        printf("Key pair generated:\n");
        printf("  Private key: %s\n", private_key);
        printf("  Public key: %s\n", public_key);
    }
    
    
    xand_cleanup(&ctx);
    
    return 0;
} 