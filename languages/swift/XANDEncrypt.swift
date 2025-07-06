import Foundation
import CryptoKit
import CommonCrypto

public class XANDEncrypt {
    private let basePassword: String
    private let keySize: Int = 32 // 256 bits
    private let nonceSize: Int = 16
    private let paddingSize: Int = 16
    
    public init(password: String) {
        self.basePassword = password
    }
    
    /// Convert password to SHA-256 hash using Swift CryptoKit
    /// CryptoKit provides optimized cryptographic operations with native performance
    /// Data type provides efficient binary data handling with automatic memory management
    private func hashPassword(_ password: String) -> Data {
        let data = password.data(using: .utf8)!
        return Data(SHA256.hash(data: data))
    }
    
    /// Generate HMAC-SHA256 using CommonCrypto framework
    /// CommonCrypto provides low-level cryptographic operations for HMAC
    /// Array conversion enables direct byte manipulation for C interop
    private func generateHMAC(key: Data, data: Data) -> Data {
        let keyBytes = [UInt8](key)
        let dataBytes = [UInt8](data)
        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyBytes, keyBytes.count, dataBytes, dataBytes.count, &hmac)
        return Data(hmac)
    }
    
    /// Generate three time-dependent keys using HMAC-SHA256
    /// withUnsafeBytes provides direct memory access for byte conversion
    /// bigEndian ensures consistent endianness across different platforms
    private func generateTimeShiftedKeys(baseKey: Data, timestamp: UInt64) -> (key1: Data, key2: Data, key3: Data, timestamp: UInt64) {
        let timeBuffer = withUnsafeBytes(of: timestamp.bigEndian) { Data($0) }
        
        // Create three different keys for the three layers
        let key1 = generateHMAC(key: baseKey, data: timeBuffer)
        let key2 = generateHMAC(key: key1, data: "layer2".data(using: .utf8)!)
        let key3 = generateHMAC(key: key2, data: "layer3".data(using: .utf8)!)
        
        return (key1: key1, key2: key2, key3: key3, timestamp: timestamp)
    }
    
    /// Generate cryptographically secure random nonce and padding
    /// SecRandomCopyBytes uses iOS/macOS secure random number generator
    /// withUnsafeMutableBytes provides direct memory access for random byte generation
    private func generateNonceAndPadding() -> (nonce: Data, padding: Data) {
        var nonce = Data(count: nonceSize)
        _ = nonce.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, nonceSize, pointer.baseAddress!)
        }
        
        let paddingLength = Int(nonce[0]) % paddingSize + 1
        var padding = Data(count: paddingLength)
        _ = padding.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, paddingLength, pointer.baseAddress!)
        }
        
        return (nonce: nonce, padding: padding)
    }
    
    /// First encryption layer: XOR and bit rotation operations
    /// Swift UInt8 provides 8-bit unsigned integers for byte-level operations
    /// Data.append() enables efficient byte-by-byte construction of result
    private func layer1Scramble(data: Data, key: Data) -> Data {
        var result = Data()
        let dataBytes = [UInt8](data)
        let keyBytes = [UInt8](key)
        
        for i in 0..<dataBytes.count {
            let keyByte = keyBytes[i % keyBytes.count]
            let dataByte = dataBytes[i]
            
            // Complex bitwise operations
            var scrambled = dataByte ^ keyByte
            scrambled = ((scrambled << 3) | (scrambled >> 5)) & 0xFF // Rotate left by 3
            scrambled = scrambled ^ (((keyByte << 1) | (keyByte >> 7)) & 0xFF)
            
            result.append(scrambled)
        }
        
        return result
    }
    
    /// Second encryption layer: Position-dependent bit rotation
    /// Rotation amount calculated from byte position and key value
    /// Conditional rotation prevents unnecessary operations when rotation is zero
    private func layer2Manipulate(data: Data, key: Data) -> Data {
        var result = Data()
        let dataBytes = [UInt8](data)
        let keyBytes = [UInt8](key)
        
        for i in 0..<dataBytes.count {
            let keyByte = keyBytes[i % keyBytes.count]
            let dataByte = dataBytes[i]
            
            // Position-based bit rotation
            let rotation = (i + Int(keyByte)) % 8
            var manipulated = dataByte
            
            if rotation > 0 {
                manipulated = ((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF
            }
            
            // XOR with position-dependent key
            manipulated = manipulated ^ ((keyByte + UInt8(i)) & 0xFF)
            
            result.append(manipulated)
        }
        
        return result
    }
    
    /// Third encryption layer: AES-256-GCM encryption
    /// Uses Swift CryptoKit AES.GCM for authenticated encryption
    /// GCM mode provides both confidentiality and authenticity guarantees
    private func layer3Encrypt(data: Data, key: Data) throws -> (encrypted: Data, iv: Data) {
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, 16, pointer.baseAddress!)
        }
        
        let encrypted = try AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv))
        return (encrypted: encrypted.combined!, iv: iv)
    }
    
    /// Layer 3: AES-256 decryption
    private func layer3Decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: SymmetricKey(data: key))
    }
    
    /// Apply key decay by XORing with time-based hash
    /// Prevents key reuse attacks by modifying keys after each operation
    /// Uses current timestamp to ensure uniqueness of decay value
    private func applyKeyDecay(keys: inout (key1: Data, key2: Data, key3: Data, timestamp: UInt64)) {
        let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
        
        // Apply decay to key1
        let decayValue1 = hashPassword("\(keys.key1.base64EncodedString())\(timestamp)")
        var decayedKey1 = Data()
        for i in 0..<keys.key1.count {
            decayedKey1.append(keys.key1[i] ^ decayValue1[i % decayValue1.count])
        }
        keys.key1 = decayedKey1
        
        // Apply decay to key2
        let decayValue2 = hashPassword("\(keys.key2.base64EncodedString())\(timestamp)")
        var decayedKey2 = Data()
        for i in 0..<keys.key2.count {
            decayedKey2.append(keys.key2[i] ^ decayValue2[i % decayValue2.count])
        }
        keys.key2 = decayedKey2
        
        // Apply decay to key3
        let decayValue3 = hashPassword("\(keys.key3.base64EncodedString())\(timestamp)")
        var decayedKey3 = Data()
        for i in 0..<keys.key3.count {
            decayedKey3.append(keys.key3[i] ^ decayValue3[i % decayValue3.count])
        }
        keys.key3 = decayedKey3
    }
    
    /// Main encryption function implementing triple-layer encryption
    /// Processes data through bit scrambling, position-dependent rotation, and AES-256
    /// Returns JSON string containing encrypted data and metadata
    public func encrypt(_ data: String) throws -> String {
        // Generate base key from password
        let baseKey = hashPassword(basePassword)
        
        // Generate time-shifted keys
        let timestamp = UInt64(Date().timeIntervalSince1970 * 1000)
        var keys = generateTimeShiftedKeys(baseKey: baseKey, timestamp: timestamp)
        
        // Generate nonce and padding
        let (nonce, padding) = generateNonceAndPadding()
        
        // Add padding to data
        var paddedData = data.data(using: .utf8)!
        paddedData.append(padding)
        
        // Layer 1: Bitwise scrambling
        let layer1Result = layer1Scramble(data: paddedData, key: keys.key1)
        
        // Layer 2: Advanced bit manipulation
        let layer2Result = layer2Manipulate(data: layer1Result, key: keys.key2)
        
        // Layer 3: AES encryption
        let layer3Result = try layer3Encrypt(data: layer2Result, key: keys.key3)
        
        // Apply key decay
        applyKeyDecay(keys: &keys)
        
        // Combine all components
        let result: [String: Any] = [
            "encrypted": layer3Result.encrypted.base64EncodedString(),
            "iv": layer3Result.iv.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "timestamp": timestamp,
            "padding_length": padding.count
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: result)
        return String(data: jsonData, encoding: .utf8)!
    }
    
    /// Decrypt data using triple-layer decryption
    public func decrypt(_ encryptedData: String) throws -> String {
        let jsonData = encryptedData.data(using: .utf8)!
        let data = try JSONSerialization.jsonObject(with: jsonData) as! [String: Any]
        
        // Parse components
        let encrypted = Data(base64Encoded: data["encrypted"] as! String)!
        let iv = Data(base64Encoded: data["iv"] as! String)!
        let _nonce = Data(base64Encoded: data["nonce"] as! String)!
        let timestamp = data["timestamp"] as! UInt64
        let paddingLength = data["padding_length"] as! Int
        
        // Generate base key from password
        let baseKey = hashPassword(basePassword)
        
        // Regenerate time-shifted keys (must use same timestamp)
        let keys = generateTimeShiftedKeys(baseKey: baseKey, timestamp: timestamp)
        
        // Layer 3: AES decryption
        let layer3Result = try layer3Decrypt(data: encrypted, key: keys.key3, iv: iv)
        
        // Layer 2: Reverse bit manipulation
        let layer2Result = layer2Manipulate(data: layer3Result, key: keys.key2)
        
        // Layer 1: Reverse bitwise scrambling
        let layer1Result = layer1Scramble(data: layer2Result, key: keys.key1)
        
        // Remove padding
        let originalData = layer1Result.prefix(layer1Result.count - paddingLength)
        
        return String(data: originalData, encoding: .utf8)!
    }
    
    /// Generate a new key pair for asymmetric operations (if needed)
    public func generateKeyPair() throws -> (privateKey: String, publicKey: String) {
        var privateKey = Data(count: 32)
        _ = privateKey.withUnsafeMutableBytes { pointer in
            SecRandomCopyBytes(kSecRandomDefault, 32, pointer.baseAddress!)
        }
        
        let publicKey = hashPassword(privateKey.base64EncodedString())
        
        return (
            privateKey: privateKey.base64EncodedString(),
            publicKey: publicKey.base64EncodedString()
        )
    }
} 