<?php

class XANDEncrypt {
    private $basePassword;
    private $keySize = 32; // 256 bits
    private $nonceSize = 16;
    private $paddingSize = 16;

    public function __construct($password) {
        $this->basePassword = $password;
    }

    /**
     * Generate a hash from the password
     */
    private function hashPassword($password) {
        return hash('sha256', $password, true);
    }

    /**
     * Generate HMAC
     */
    private function generateHMAC($key, $data) {
        return hash_hmac('sha256', $data, $key, true);
    }

    /**
     * Generate time-shifted keys based on current timestamp
     */
    private function generateTimeShiftedKeys($baseKey, $timestamp) {
        $timeBuffer = pack('J', $timestamp); // 8-byte timestamp
        
        // Create three different keys for the three layers
        $key1 = $this->generateHMAC($baseKey, $timeBuffer);
        $key2 = $this->generateHMAC($key1, 'layer2');
        $key3 = $this->generateHMAC($key2, 'layer3');
        
        return [
            'key1' => $key1,
            'key2' => $key2,
            'key3' => $key3,
            'timestamp' => $timestamp
        ];
    }

    /**
     * Generate random nonce and derive padding
     */
    private function generateNonceAndPadding() {
        $nonce = random_bytes($this->nonceSize);
        $paddingLength = ord($nonce[0]) % $this->paddingSize + 1;
        $padding = random_bytes($paddingLength);
        
        return [
            'nonce' => $nonce,
            'padding' => $padding
        ];
    }

    /**
     * Layer 1: Bitwise scrambling with time-shifted key
     */
    private function layer1Scramble($data, $key) {
        $result = '';
        $dataLength = strlen($data);
        $keyLength = strlen($key);
        
        for ($i = 0; $i < $dataLength; $i++) {
            $keyByte = ord($key[$i % $keyLength]);
            $dataByte = ord($data[$i]);
            
            // Complex bitwise operations
            $scrambled = $dataByte ^ $keyByte;
            $scrambled = (($scrambled << 3) | ($scrambled >> 5)) & 0xFF; // Rotate left by 3
            $scrambled = $scrambled ^ ((($keyByte << 1) | ($keyByte >> 7)) & 0xFF);
            
            $result .= chr($scrambled);
        }
        
        return $result;
    }

    /**
     * Layer 2: Advanced bit manipulation
     */
    private function layer2Manipulate($data, $key) {
        $result = '';
        $dataLength = strlen($data);
        $keyLength = strlen($key);
        
        for ($i = 0; $i < $dataLength; $i++) {
            $keyByte = ord($key[$i % $keyLength]);
            $dataByte = ord($data[$i]);
            
            // Position-based bit rotation
            $rotation = ($i + $keyByte) % 8;
            $manipulated = $dataByte;
            
            if ($rotation > 0) {
                $manipulated = (($manipulated << $rotation) | ($manipulated >> (8 - $rotation))) & 0xFF;
            }
            
            // XOR with position-dependent key
            $manipulated = $manipulated ^ (($keyByte + $i) & 0xFF);
            
            $result .= chr($manipulated);
        }
        
        return $result;
    }

    /**
     * Layer 3: AES-256 encryption
     */
    private function layer3Encrypt($data, $key) {
        $iv = random_bytes(16);
        
        // Use OpenSSL for AES encryption
        $encrypted = openssl_encrypt(
            $data,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        return [
            'encrypted' => $encrypted,
            'iv' => $iv
        ];
    }

    /**
     * Layer 3: AES-256 decryption
     */
    private function layer3Decrypt($data, $key, $iv) {
        return openssl_decrypt(
            $data,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }

    /**
     * Apply key decay - modify keys after use
     */
    private function applyKeyDecay($keys) {
        $decayedKeys = [];
        
        foreach ($keys as $keyName => $key) {
            if ($keyName === 'timestamp') {
                $decayedKeys[$keyName] = $key;
                continue;
            }
            
            // Apply decay by XORing with a derived value
            $timeStr = (string)(microtime(true) * 1000);
            $decayValue = hash('sha256', $key . $timeStr, true);
            
            $decayedKey = '';
            $keyLength = strlen($key);
            $decayLength = strlen($decayValue);
            
            for ($i = 0; $i < $keyLength; $i++) {
                $decayedKey .= chr(ord($key[$i]) ^ ord($decayValue[$i % $decayLength]));
            }
            
            $decayedKeys[$keyName] = $decayedKey;
        }
        
        return $decayedKeys;
    }

    /**
     * Encrypt data using triple-layer encryption
     */
    public function encrypt($data) {
        // Generate base key from password
        $baseKey = $this->hashPassword($this->basePassword);
        
        // Generate time-shifted keys
        $timestamp = (int)(microtime(true) * 1000);
        $keys = $this->generateTimeShiftedKeys($baseKey, $timestamp);
        
        // Generate nonce and padding
        $nonceAndPadding = $this->generateNonceAndPadding();
        $nonce = $nonceAndPadding['nonce'];
        $padding = $nonceAndPadding['padding'];
        
        // Add padding to data
        $paddedData = $data . $padding;
        
        // Layer 1: Bitwise scrambling
        $layer1Result = $this->layer1Scramble($paddedData, $keys['key1']);
        
        // Layer 2: Advanced bit manipulation
        $layer2Result = $this->layer2Manipulate($layer1Result, $keys['key2']);
        
        // Layer 3: AES encryption
        $layer3Result = $this->layer3Encrypt($layer2Result, $keys['key3']);
        
        // Apply key decay
        $this->applyKeyDecay($keys);
        
        // Combine all components
        $result = [
            'encrypted' => base64_encode($layer3Result['encrypted']),
            'iv' => base64_encode($layer3Result['iv']),
            'nonce' => base64_encode($nonce),
            'timestamp' => $timestamp,
            'padding_length' => strlen($padding)
        ];
        
        return json_encode($result);
    }

    /**
     * Decrypt data using triple-layer decryption
     */
    public function decrypt($encryptedData) {
        $data = json_decode($encryptedData, true);
        
        // Parse components
        $encrypted = base64_decode($data['encrypted']);
        $iv = base64_decode($data['iv']);
        $nonce = base64_decode($data['nonce']);
        $timestamp = $data['timestamp'];
        $paddingLength = $data['padding_length'];
        
        // Generate base key from password
        $baseKey = $this->hashPassword($this->basePassword);
        
        // Regenerate time-shifted keys (must use same timestamp)
        $keys = $this->generateTimeShiftedKeys($baseKey, $timestamp);
        
        // Layer 3: AES decryption
        $layer3Result = $this->layer3Decrypt($encrypted, $keys['key3'], $iv);
        
        // Layer 2: Reverse bit manipulation
        $layer2Result = $this->layer2Manipulate($layer3Result, $keys['key2']);
        
        // Layer 1: Reverse bitwise scrambling
        $layer1Result = $this->layer1Scramble($layer2Result, $keys['key1']);
        
        // Remove padding
        $originalData = substr($layer1Result, 0, -$paddingLength);
        
        return $originalData;
    }

    /**
     * Generate a new key pair for asymmetric operations (if needed)
     */
    public function generateKeyPair() {
        $privateKey = random_bytes(32);
        $publicKey = hash('sha256', base64_encode($privateKey), true);
        
        return [
            'private_key' => base64_encode($privateKey),
            'public_key' => base64_encode($publicKey)
        ];
    }
} 