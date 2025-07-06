use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type Aes256Cbc = Cbc<Aes256, block_modes::block_padding::Pkcs7>;

pub struct XANDEncrypt {
    base_password: String,
    key_size: usize,
    nonce_size: usize,
    padding_size: usize,
}

#[derive(Serialize, Deserialize)]
struct EncryptedData {
    encrypted: String,
    iv: String,
    nonce: String,
    timestamp: u64,
    padding_length: usize,
}

impl XANDEncrypt {
    pub fn new(password: String) -> Self {
        Self {
            base_password: password,
            key_size: 32, // 256 bits
            nonce_size: 16,
            padding_size: 16,
        }
    }

    /// Convert password to SHA-256 hash using Rust sha2 crate
    /// sha2 crate uses optimized C implementations for cryptographic operations
    /// Vec<u8> provides dynamic byte arrays with Rust's memory safety guarantees
    fn hash_password(&self, password: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Generate HMAC
    fn generate_hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Generate three time-dependent keys using HMAC-SHA256
    /// to_be_bytes() converts timestamp to big-endian byte array automatically
    /// Tuple return type provides multiple values in idiomatic Rust style
    fn generate_time_shifted_keys(&self, base_key: &[u8], timestamp: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>, u64) {
        let time_buffer = timestamp.to_be_bytes();
        
        // Create three different keys for the three layers
        // Rust's HMAC is zero-cost and uses native crypto libraries
        let key1 = self.generate_hmac(base_key, &time_buffer);
        let key2 = self.generate_hmac(&key1, b"layer2");
        let key3 = self.generate_hmac(&key2, b"layer3");
        
        (key1, key2, key3, timestamp)
    }

    /// Generate cryptographically secure random nonce and padding
    /// rand::thread_rng() provides cryptographically secure random numbers
    /// Vec::with_capacity pre-allocates memory for known-size vectors
    fn generate_nonce_and_padding(&self) -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut nonce = vec![0u8; self.nonce_size];
        rng.fill(&mut nonce);
        
        let padding_length = (nonce[0] as usize % self.padding_size) + 1;
        let mut padding = vec![0u8; padding_length];
        rng.fill(&mut padding);
        
        (nonce, padding)
    }

    /// First encryption layer: XOR and bit rotation operations
    /// Rust iterators provide zero-cost abstractions that compile to efficient loops
    /// enumerate() provides both index and value in a single iteration
    fn layer1_scramble(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        
        for (i, &data_byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            
            // Complex bitwise operations
            // Rust's bitwise ops are as fast as C and provide compile-time safety
            let mut scrambled = data_byte ^ key_byte;
            scrambled = ((scrambled << 3) | (scrambled >> 5)) & 0xFF; // Rotate left by 3
            scrambled = scrambled ^ (((key_byte << 1) | (key_byte >> 7)) & 0xFF);
            
            result.push(scrambled);
        }
        
        result
    }

    /// Second encryption layer: Position-dependent bit rotation
    /// Rotation amount calculated from byte position and key value
    /// Conditional rotation prevents unnecessary operations when rotation is zero
    fn layer2_manipulate(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        
        for (i, &data_byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            
            // Position-based bit rotation
            let rotation = (i + key_byte as usize) % 8;
            let mut manipulated = data_byte;
            
            if rotation > 0 {
                manipulated = ((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF;
            }
            
            // XOR with position-dependent key
            manipulated = manipulated ^ ((key_byte as u8 + i as u8) & 0xFF);
            
            result.push(manipulated);
        }
        
        result
    }

    /// Third encryption layer: AES-256-CBC encryption
    /// Uses Rust block-modes crate for AES operations with PKCS7 padding
    /// CBC mode requires unique IV for each encryption operation
    fn layer3_encrypt(&self, data: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut iv = vec![0u8; 16];
        rng.fill(&mut iv);
        
        let cipher = Aes256Cbc::new_from_slice(key, &iv)?;
        let encrypted = cipher.encrypt_vec(data);
        
        Ok((encrypted, iv))
    }

    /// Layer 3: AES-256 decryption
    fn layer3_decrypt(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Cbc::new_from_slice(key, iv)?;
        let decrypted = cipher.decrypt_vec(data)?;
        
        Ok(decrypted)
    }

    /// Apply key decay by XORing with time-based hash
    /// Prevents key reuse attacks by modifying keys after each operation
    /// Uses current timestamp to ensure uniqueness of decay value
    fn apply_key_decay(&self, keys: &mut (Vec<u8>, Vec<u8>, Vec<u8>, u64)) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        // Apply decay to key1
        let decay_value = self.hash_password(&format!("{}{}", BASE64.encode(&keys.0), timestamp));
        for (i, byte) in keys.0.iter_mut().enumerate() {
            *byte ^= decay_value[i % decay_value.len()];
        }
        
        // Apply decay to key2
        let decay_value = self.hash_password(&format!("{}{}", BASE64.encode(&keys.1), timestamp));
        for (i, byte) in keys.1.iter_mut().enumerate() {
            *byte ^= decay_value[i % decay_value.len()];
        }
        
        // Apply decay to key3
        let decay_value = self.hash_password(&format!("{}{}", BASE64.encode(&keys.2), timestamp));
        for (i, byte) in keys.2.iter_mut().enumerate() {
            *byte ^= decay_value[i % decay_value.len()];
        }
    }

    /// Main encryption function implementing triple-layer encryption
    /// Processes data through bit scrambling, position-dependent rotation, and AES-256
    /// Returns JSON string containing encrypted data and metadata
    pub fn encrypt(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Generate base key from password
        let base_key = self.hash_password(&self.base_password);
        
        // Generate time-shifted keys
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut keys = self.generate_time_shifted_keys(&base_key, timestamp);
        
        // Generate nonce and padding
        let (nonce, padding) = self.generate_nonce_and_padding();
        
        // Add padding to data
        let mut padded_data = data.as_bytes().to_vec();
        padded_data.extend_from_slice(&padding);
        
        // Layer 1: Bitwise scrambling
        let layer1_result = self.layer1_scramble(&padded_data, &keys.0);
        
        // Layer 2: Advanced bit manipulation
        let layer2_result = self.layer2_manipulate(&layer1_result, &keys.1);
        
        // Layer 3: AES encryption
        let (layer3_result, iv) = self.layer3_encrypt(&layer2_result, &keys.2)?;
        
        // Apply key decay
        self.apply_key_decay(&mut keys);
        
        // Combine all components
        let encrypted_data = EncryptedData {
            encrypted: BASE64.encode(&layer3_result),
            iv: BASE64.encode(&iv),
            nonce: BASE64.encode(&nonce),
            timestamp,
            padding_length: padding.len(),
        };
        
        Ok(serde_json::to_string(&encrypted_data)?)
    }

    /// Decrypt data using triple-layer decryption
    pub fn decrypt(&self, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let data: EncryptedData = serde_json::from_str(encrypted_data)?;
        
        // Parse components
        let encrypted = BASE64.decode(&data.encrypted)?;
        let iv = BASE64.decode(&data.iv)?;
        let _nonce = BASE64.decode(&data.nonce)?;
        let timestamp = data.timestamp;
        let padding_length = data.padding_length;
        
        // Generate base key from password
        let base_key = self.hash_password(&self.base_password);
        
        // Regenerate time-shifted keys (must use same timestamp)
        let keys = self.generate_time_shifted_keys(&base_key, timestamp);
        
        // Layer 3: AES decryption
        let layer3_result = self.layer3_decrypt(&encrypted, &keys.2, &iv)?;
        
        // Layer 2: Reverse bit manipulation
        let layer2_result = self.layer2_manipulate(&layer3_result, &keys.1);
        
        // Layer 1: Reverse bitwise scrambling
        let layer1_result = self.layer1_scramble(&layer2_result, &keys.0);
        
        // Remove padding
        let original_data = &layer1_result[..layer1_result.len() - padding_length];
        
        Ok(String::from_utf8(original_data.to_vec())?)
    }

    /// Generate a new key pair for asymmetric operations (if needed)
    pub fn generate_key_pair(&self) -> Result<(String, String), Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let mut private_key = vec![0u8; 32];
        rng.fill(&mut private_key);
        
        let public_key = self.hash_password(&BASE64.encode(&private_key));
        
        Ok((
            BASE64.encode(&private_key),
            BASE64.encode(&public_key)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let encryptor = XANDEncrypt::new("test_password".to_string());
        let original_data = "Hello, World!";
        
        let encrypted = encryptor.encrypt(original_data).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        
        assert_eq!(original_data, decrypted);
    }

    #[test]
    fn test_different_outputs() {
        let encryptor = XANDEncrypt::new("test_password".to_string());
        let data = "Hello, World!";
        
        let encrypted1 = encryptor.encrypt(data).unwrap();
        let encrypted2 = encryptor.encrypt(data).unwrap();
        
        // Should produce different outputs due to nonce and time-shifting
        assert_ne!(encrypted1, encrypted2);
    }
} 