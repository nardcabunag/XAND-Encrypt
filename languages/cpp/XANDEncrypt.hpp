#ifndef XAND_ENCRYPT_HPP
#define XAND_ENCRYPT_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace xand {

/**
 * Our encrypted data structure - holds all the pieces we need to decrypt later
 * Think of this like a secure envelope with all the instructions inside
 */
struct EncryptedData {
    std::vector<uint8_t> encrypted;  // The actual encrypted data
    std::vector<uint8_t> iv;         // Initialization vector for AES
    std::vector<uint8_t> nonce;      // Random number to make each encryption unique
    uint64_t timestamp;              // When this was encrypted
    size_t padding_length;           // How much padding we added
    
    // Convert to JSON string for easy storage and transmission
    std::string toJson() const;
    
    // Create from JSON string
    static EncryptedData fromJson(const std::string& json);
};

/**
 * The main encryption class - this is what you'll use to protect your data
 * It handles all the complex cryptography so you don't have to worry about it
 */
class XANDEncrypt {
public:
    // Constructor takes your password - keep it safe!
    explicit XANDEncrypt(const std::string& password);
    
    // Destructor cleans up any sensitive data
    ~XANDEncrypt();
    
    // Copy constructor and assignment are disabled for security
    XANDEncrypt(const XANDEncrypt&) = delete;
    XANDEncrypt& operator=(const XANDEncrypt&) = delete;
    
    // Move constructor and assignment are allowed
    XANDEncrypt(XANDEncrypt&&) = default;
    XANDEncrypt& operator=(XANDEncrypt&&) = default;
    
    /**
     * Encrypt some data - this is the main function you'll use
     * It goes through all three layers to make your data super secure
     */
    EncryptedData encrypt(const std::string& data);
    
    /**
     * Decrypt data that was encrypted with this class
     * This reverses all three layers to get your original data back
     */
    std::string decrypt(const EncryptedData& encrypted_data);
    
    /**
     * Generate a key pair for asymmetric operations
     * This creates a public and private key for advanced use cases
     */
    std::pair<std::string, std::string> generateKeyPair();
    
    /**
     * Check if the encryption system is properly initialized
     * Returns true if everything is ready to encrypt/decrypt
     */
    bool isInitialized() const;

private:
    // Our configuration constants
    static constexpr size_t KEY_SIZE = 32;        // 256 bits
    static constexpr size_t NONCE_SIZE = 16;      // 128 bits
    static constexpr size_t PADDING_SIZE = 16;    // Max padding
    static constexpr size_t IV_SIZE = 16;         // AES IV size
    
    // Internal data
    std::string password_;
    bool initialized_;
    
    // Helper functions with human-readable names
    std::vector<uint8_t> hashPassword(const std::string& password);
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>, uint64_t> 
        generateTimeShiftedKeys(const std::vector<uint8_t>& base_key, uint64_t timestamp);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateNonceAndPadding();
    std::vector<uint8_t> layer1Scramble(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::vector<uint8_t> layer2Manipulate(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> layer3Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::vector<uint8_t> layer3Decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    void applyKeyDecay(std::vector<uint8_t>& key1, std::vector<uint8_t>& key2, std::vector<uint8_t>& key3);
    
    // Utility functions
    uint64_t getCurrentTimestamp();
    std::vector<uint8_t> generateRandomBytes(size_t length);
    std::string bytesToHex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hexToBytes(const std::string& hex);
};

} // namespace xand

#endif // XAND_ENCRYPT_HPP 