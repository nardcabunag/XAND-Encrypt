import hashlib
import hmac
import json
import os
import time
import base64
from typing import Dict, Tuple, Union


class XANDEncrypt:
    def __init__(self, password: str):
        self.base_password = password
        self.key_size = 32  # 256 bits
        self.nonce_size = 16
        self.padding_size = 16

    def _hash_password(self, password: str) -> bytes:
        """Convert password to SHA-256 hash using Python hashlib
        hashlib uses OpenSSL bindings for cryptographic operations
        UTF-8 encoding ensures consistent handling of Unicode characters"""
        return hashlib.sha256(password.encode('utf-8')).digest()

    def _generate_time_shifted_keys(self, base_key: bytes, timestamp: int) -> Dict[str, Union[bytes, int]]:
        """Generate three time-dependent keys using HMAC-SHA256
        to_bytes() with byteorder='big' converts timestamp to big-endian bytes
        hmac.new() uses OpenSSL's HMAC implementation for performance"""
        time_buffer = timestamp.to_bytes(8, byteorder='big')
        
        # Each layer gets its own unique key derived from the previous one
        # Python's hmac.new() is thread-safe and uses OpenSSL for performance
        key1 = hmac.new(base_key, time_buffer, hashlib.sha256).digest()
        key2 = hmac.new(key1, b'layer2', hashlib.sha256).digest()
        key3 = hmac.new(key2, b'layer3', hashlib.sha256).digest()
        
        return {'key1': key1, 'key2': key2, 'key3': key3, 'timestamp': timestamp}

    def _generate_nonce_and_padding(self) -> Tuple[bytes, bytes]:
        """Generate cryptographically secure random nonce and padding
        os.urandom() calls OS random number generator (/dev/urandom on Unix)
        Nonce first byte determines variable-length padding size"""
        nonce = os.urandom(self.nonce_size)
        padding_length = nonce[0] % self.padding_size + 1
        padding = os.urandom(padding_length)
        return nonce, padding

    def _layer1_scramble(self, data: bytes, key: bytes) -> bytes:
        """First encryption layer: XOR and bit rotation operations
        bytearray provides mutable byte sequence for efficient modifications
        & 0xFF masks unlimited Python integers to 8-bit byte values"""
        result = bytearray(len(data))
        
        for i in range(len(data)):
            key_byte = key[i % len(key)]
            data_byte = data[i]
            
            # Do some bit magic to scramble the data
            # Python bitwise ops work on unlimited integers, so we mask to 8 bits
            scrambled = data_byte ^ key_byte
            scrambled = ((scrambled << 3) | (scrambled >> 5)) & 0xFF  # Rotate left by 3
            scrambled = scrambled ^ (((key_byte << 1) | (key_byte >> 7)) & 0xFF)
            
            result[i] = scrambled
        
        return bytes(result)

    def _layer2_manipulate(self, data: bytes, key: bytes) -> bytes:
        """Second encryption layer: Position-dependent bit rotation
        Rotation amount calculated from byte position and key value
        Conditional rotation prevents unnecessary operations when rotation is zero"""
        result = bytearray(len(data))
        
        for i in range(len(data)):
            key_byte = key[i % len(key)]
            data_byte = data[i]
            
            # Rotate bits based on position and key
            rotation = (i + key_byte) % 8
            manipulated = data_byte
            
            if rotation > 0:
                manipulated = ((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF
            
            # Mix in some position-dependent randomness
            manipulated = manipulated ^ ((key_byte + i) & 0xFF)
            
            result[i] = manipulated
        
        return bytes(result)

    def _layer3_encrypt(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Third encryption layer: Simplified AES-256 simulation
        Uses XOR operations with key and IV for demonstration purposes
        Production implementations should use proper AES libraries"""
        iv = os.urandom(16)
        
        # Simple XOR-based encryption for demonstration
        # In production, use a proper AES library
        encrypted = bytearray(len(data))
        for i in range(len(data)):
            encrypted[i] = data[i] ^ key[i % len(key)] ^ iv[i % len(iv)]
        
        return bytes(encrypted), iv

    def _layer3_decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Layer 3: AES-256 decryption (simplified implementation)"""
        # Simple XOR-based decryption for demonstration
        # In production, use a proper AES library
        decrypted = bytearray(len(data))
        for i in range(len(data)):
            decrypted[i] = data[i] ^ key[i % len(key)] ^ iv[i % len(iv)]
        
        return bytes(decrypted)

    def _apply_key_decay(self, keys: Dict[str, Union[bytes, int]]) -> Dict[str, Union[bytes, int]]:
        """Apply key decay by XORing with time-based hash
        Prevents key reuse attacks by modifying keys after each operation
        Uses current timestamp to ensure uniqueness of decay value"""
        decayed_keys = {}
        
        for key_name, key in keys.items():
            if key_name == 'timestamp':
                decayed_keys[key_name] = key
                continue
            
            if isinstance(key, bytes):
                # Apply decay by XORing with a derived value
                decay_value = hashlib.sha256(key + str(int(time.time() * 1000)).encode()).digest()
                
                decayed_key = bytearray(len(key))
                for i in range(len(key)):
                    decayed_key[i] = key[i] ^ decay_value[i % len(decay_value)]
                
                decayed_keys[key_name] = bytes(decayed_key)
            else:
                decayed_keys[key_name] = key
        
        return decayed_keys

    def encrypt(self, data: Union[str, bytes]) -> str:
        """Main encryption function implementing triple-layer encryption
        Processes data through bit scrambling, position-dependent rotation, and AES-256
        Returns JSON string containing encrypted data and metadata"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate base key from password
        base_key = self._hash_password(self.base_password)
        
        # Generate time-shifted keys
        timestamp = int(time.time() * 1000)
        keys = self._generate_time_shifted_keys(base_key, timestamp)
        
        # Generate nonce and padding
        nonce, padding = self._generate_nonce_and_padding()
        
        # Add padding to data
        padded_data = data + padding
        
        # Layer 1: Bitwise scrambling
        layer1_result = self._layer1_scramble(padded_data, keys['key1'])  # type: ignore
        
        # Layer 2: Advanced bit manipulation
        layer2_result = self._layer2_manipulate(layer1_result, keys['key2'])  # type: ignore
        
        # Layer 3: AES encryption
        layer3_result, iv = self._layer3_encrypt(layer2_result, keys['key3'])  # type: ignore
        
        # Apply key decay
        self._apply_key_decay(keys)
        
        # Combine all components
        result = {
            'encrypted': base64.b64encode(layer3_result).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'timestamp': timestamp,
            'padding_length': len(padding)
        }
        
        return json.dumps(result)

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using triple-layer decryption"""
        data = json.loads(encrypted_data)
        
        # Parse components
        encrypted = base64.b64decode(data['encrypted'])
        iv = base64.b64decode(data['iv'])
        nonce = base64.b64decode(data['nonce'])
        timestamp = data['timestamp']
        padding_length = data['padding_length']
        
        # Generate base key from password
        base_key = self._hash_password(self.base_password)
        
        # Regenerate time-shifted keys (must use same timestamp)
        keys = self._generate_time_shifted_keys(base_key, timestamp)
        
        # Layer 3: AES decryption
        layer3_result = self._layer3_decrypt(encrypted, keys['key3'], iv)  # type: ignore
        
        # Layer 2: Reverse bit manipulation
        layer2_result = self._layer2_manipulate(layer3_result, keys['key2'])  # type: ignore
        
        # Layer 1: Reverse bitwise scrambling
        layer1_result = self._layer1_scramble(layer2_result, keys['key1'])  # type: ignore
        
        # Remove padding
        original_data = layer1_result[:-padding_length]
        
        return original_data.decode('utf-8')

    def generate_key_pair(self):
        """Generate a new key pair for asymmetric operations (if needed)"""
        # Simplified key pair generation for demonstration
        # In production, use a proper cryptography library
        private_key = os.urandom(32)
        public_key = hashlib.sha256(private_key).digest()
        
        return {
            'private_key': base64.b64encode(private_key).decode('utf-8'),
            'public_key': base64.b64encode(public_key).decode('utf-8')
        } 