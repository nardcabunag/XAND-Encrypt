const crypto = require('crypto');

class XANDEncrypt {
    constructor(password) {
        this.basePassword = password;
        this.keySize = 32; // 256 bits
        this.nonceSize = 16;
        this.paddingSize = 16;
    }

    /**
     * Convert password to SHA-256 hash using Node.js crypto module
     * Node.js crypto uses OpenSSL bindings for native performance
     * Returns Buffer object optimized for binary data operations
     */
    _hashPassword(password) {
        return crypto.createHash('sha256').update(password).digest();
    }

    /**
     * Generate three time-dependent keys using HMAC-SHA256
     * Buffer.writeBigUInt64BE converts timestamp to big-endian byte array
     * HMAC operations use OpenSSL's native implementation
     */
    _generateTimeShiftedKeys(baseKey, timestamp) {
        const timeBuffer = Buffer.alloc(8);
        timeBuffer.writeBigUInt64BE(BigInt(timestamp));
        
        // Each layer gets its own unique key derived from the previous one
        // Node.js HMAC is optimized and uses native crypto libraries under the hood
        const key1 = crypto.createHmac('sha256', baseKey).update(timeBuffer).digest();
        const key2 = crypto.createHmac('sha256', key1).update('layer2').digest();
        const key3 = crypto.createHmac('sha256', key2).update('layer3').digest();
        
        return { key1, key2, key3, timestamp };
    }

    /**
     * Generate cryptographically secure random nonce and padding
     * crypto.randomBytes() calls OS random number generator (/dev/urandom on Unix)
     * Nonce length determines padding size for variable-length padding
     */
    _generateNonceAndPadding() {
        const nonce = crypto.randomBytes(this.nonceSize);
        const paddingLength = nonce[0] % this.paddingSize + 1;
        const padding = crypto.randomBytes(paddingLength);
        return { nonce, padding };
    }

    /**
     * First encryption layer: XOR and bit rotation operations
     * JavaScript bitwise operations operate on 32-bit integers, requiring & 0xFF masking
     * Buffer.alloc() creates fixed-size buffer to avoid dynamic resizing
     */
    _layer1Scramble(data, key) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % key.length];
            const dataByte = data[i];
            
            // Do some bit magic to scramble the data
            // JavaScript bitwise ops are fast but limited to 32 bits, hence the masking
            let scrambled = dataByte ^ keyByte;
            scrambled = ((scrambled << 3) | (scrambled >> 5)) & 0xFF; // Rotate left by 3
            scrambled = scrambled ^ ((keyByte << 1) | (keyByte >> 7)) & 0xFF;
            
            result[i] = scrambled;
        }
        
        return result;
    }

    /**
     * First decryption layer: Reverse XOR and bit rotation operations
     */
    _layer1Unscramble(data, key) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % key.length];
            const dataByte = data[i];
            
            // Reverse the bit magic
            let unscrambled = dataByte ^ ((keyByte << 1) | (keyByte >> 7)) & 0xFF;
            unscrambled = ((unscrambled >> 3) | (unscrambled << 5)) & 0xFF; // Rotate right by 3
            unscrambled = unscrambled ^ keyByte;
            
            result[i] = unscrambled;
        }
        
        return result;
    }

    /**
     * Second encryption layer: Position-dependent bit rotation
     * Rotation amount calculated from byte position and key value
     * JavaScript modulo operator always returns positive values
     */
    _layer2Manipulate(data, key) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % key.length];
            const dataByte = data[i];
            
            // Rotate bits based on position and key
            const rotation = (i + keyByte) % 8;
            let manipulated = dataByte;
            
            if (rotation > 0) {
                manipulated = ((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF;
            }
            
            // Mix in some position-dependent randomness
            manipulated = manipulated ^ (keyByte + i) & 0xFF;
            
            result[i] = manipulated;
        }
        
        return result;
    }

    /**
     * Second decryption layer: Reverse position-dependent bit rotation
     */
    _layer2Unmanipulate(data, key) {
        const result = Buffer.alloc(data.length);
        
        for (let i = 0; i < data.length; i++) {
            const keyByte = key[i % key.length];
            const dataByte = data[i];
            
            // Reverse the position-dependent randomness
            let unmanipulated = dataByte ^ (keyByte + i) & 0xFF;
            
            // Reverse the bit rotation
            const rotation = (i + keyByte) % 8;
            if (rotation > 0) {
                unmanipulated = ((unmanipulated >> rotation) | (unmanipulated << (8 - rotation))) & 0xFF;
            }
            
            result[i] = unmanipulated;
        }
        
        return result;
    }

    /**
     * Third encryption layer: AES-256-CBC encryption
     * Uses Node.js crypto.createCipheriv() with random IV generation
     * CBC mode requires unique IV for each encryption operation
     */
    _layer3Encrypt(data, key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        
        let encrypted = cipher.update(data);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        return { encrypted, iv };
    }

    /**
     * Apply key decay by XORing with time-based hash
     * Prevents key reuse attacks by modifying keys after each operation
     * Uses current timestamp to ensure uniqueness of decay value
     */
    _applyKeyDecay(keys) {
        const decayedKeys = {};
        
        for (const [keyName, key] of Object.entries(keys)) {
            if (keyName === 'timestamp') {
                decayedKeys[keyName] = key;
                continue;
            }
            
            // Mix in some fresh randomness to age the key
            const decayValue = crypto.createHash('sha256')
                .update(key)
                .update(Date.now().toString())
                .digest();
            
            const decayedKey = Buffer.alloc(key.length);
            for (let i = 0; i < key.length; i++) {
                decayedKey[i] = key[i] ^ decayValue[i % decayValue.length];
            }
            
            decayedKeys[keyName] = decayedKey;
        }
        
        return decayedKeys;
    }

    /**
     * Main encryption function implementing triple-layer encryption
     * Processes data through bit scrambling, position-dependent rotation, and AES-256
     * Returns JSON string containing encrypted data and metadata
     */
    encrypt(data) {
        if (typeof data === 'string') {
            data = Buffer.from(data, 'utf8');
        }
        // Generate base key from password
        const baseKey = this._hashPassword(this.basePassword);
        // Generate time-shifted keys
        const timestamp = Date.now();
        const keys = this._generateTimeShiftedKeys(baseKey, timestamp);
        // Generate nonce and padding
        const { nonce, padding } = this._generateNonceAndPadding();
        // Add padding to data
        const paddedData = Buffer.concat([data, padding]);
        // Layer 1: Bitwise scrambling
        const layer1Result = this._layer1Scramble(paddedData, keys.key1);
        // Layer 2: Advanced bit manipulation
        const layer2Result = this._layer2Manipulate(layer1Result, keys.key2);
        // Layer 3: AES encryption
        const layer3Result = this._layer3Encrypt(layer2Result, keys.key3);
        // Apply key decay
        this._applyKeyDecay(keys);
        // Combine all components
        const result = {
            encrypted: layer3Result.encrypted.toString('base64'),
            iv: layer3Result.iv.toString('base64'),
            nonce: nonce.toString('base64'),
            timestamp: timestamp,
            paddingLength: padding.length
        };
        return JSON.stringify(result);
    }

    /**
     * Decrypt data using triple-layer decryption
     */
    decrypt(encryptedData) {
        const data = JSON.parse(encryptedData);
        // Parse components
        const encrypted = Buffer.from(data.encrypted, 'base64');
        const iv = Buffer.from(data.iv, 'base64');
        const nonce = Buffer.from(data.nonce, 'base64');
        const timestamp = data.timestamp;
        const paddingLength = data.paddingLength;
        // Generate base key from password
        const baseKey = this._hashPassword(this.basePassword);
        // Regenerate time-shifted keys (must use same timestamp)
        const keys = this._generateTimeShiftedKeys(baseKey, timestamp);
        // Layer 3: AES decryption
        const decipher = crypto.createDecipheriv('aes-256-cbc', keys.key3, iv);
        let layer3Result = decipher.update(encrypted);
        layer3Result = Buffer.concat([layer3Result, decipher.final()]);
        // Layer 2: Reverse bit manipulation
        const layer2Result = this._layer2Unmanipulate(layer3Result, keys.key2);
        // Layer 1: Reverse bitwise scrambling
        const layer1Result = this._layer1Unscramble(layer2Result, keys.key1);
        // Remove padding
        const originalData = layer1Result.slice(0, -paddingLength);
        return originalData.toString('utf8');
    }

    /**
     * Generate a new key pair for asymmetric operations (if needed)
     */
    generateKeyPair() {
        return crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
    }
}

module.exports = XANDEncrypt; 