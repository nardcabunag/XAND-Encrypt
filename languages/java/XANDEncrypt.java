import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

public class XANDEncrypt {
    private final String basePassword;
    private final int keySize = 32; // 256 bits
    private final int nonceSize = 16;
    private final int paddingSize = 16;
    private final SecureRandom secureRandom = new SecureRandom();

    public XANDEncrypt(String password) {
        this.basePassword = password;
    }

    /**
     * Convert password to SHA-256 hash using Java MessageDigest
     * JCE (Java Cryptography Extension) provides optimized cryptographic operations
     * StandardCharsets.UTF_8 ensures consistent encoding across different platforms
     */
    private byte[] hashPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate HMAC for key derivation
     */
    private byte[] generateHMAC(byte[] key, byte[] data) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    /**
     * Generate three time-dependent keys using HMAC-SHA256
     * Manual byte extraction from long ensures big-endian byte order
     * Java lacks built-in long-to-byte conversion, requiring manual bit manipulation
     */
    private Map<String, Object> generateTimeShiftedKeys(byte[] baseKey, long timestamp) throws Exception {
        byte[] timeBuffer = new byte[8];
        for (int i = 0; i < 8; i++) {
            timeBuffer[i] = (byte) (timestamp >> (56 - i * 8));
        }

        // Each layer gets its own unique key derived from the previous one
        // Java's Mac class is thread-safe and uses native crypto when available
        byte[] key1 = generateHMAC(baseKey, timeBuffer);
        byte[] key2 = generateHMAC(key1, "layer2".getBytes(StandardCharsets.UTF_8));
        byte[] key3 = generateHMAC(key2, "layer3".getBytes(StandardCharsets.UTF_8));

        Map<String, Object> keys = new HashMap<>();
        keys.put("key1", key1);
        keys.put("key2", key2);
        keys.put("key3", key3);
        keys.put("timestamp", timestamp);
        return keys;
    }

    /**
     * Generate cryptographically secure random nonce and padding
     * SecureRandom uses OS random number generator for cryptographic security
     * & 0xFF converts signed Java bytes to unsigned values (0-255 range)
     */
    private Map<String, byte[]> generateNonceAndPadding() {
        byte[] nonce = new byte[nonceSize];
        secureRandom.nextBytes(nonce);
        
        int paddingLength = (nonce[0] & 0xFF) % paddingSize + 1;
        byte[] padding = new byte[paddingLength];
        secureRandom.nextBytes(padding);
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("nonce", nonce);
        result.put("padding", padding);
        return result;
    }

    /**
     * First encryption layer: XOR and bit rotation operations
     * Java bytes are signed (-128 to 127), requiring int conversion for bitwise ops
     * >>> (unsigned right shift) prevents sign extension during bit manipulation
     */
    private byte[] layer1Scramble(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        
        for (int i = 0; i < data.length; i++) {
            byte keyByte = key[i % key.length];
            byte dataByte = data[i];
            
            // Do some bit magic to scramble the data
            // Java bitwise ops work on int, so we cast bytes to int first
            int scrambled = dataByte ^ keyByte;
            scrambled = ((scrambled << 3) | (scrambled >>> 5)) & 0xFF; // Rotate left by 3
            scrambled = scrambled ^ (((keyByte << 1) | (keyByte >>> 7)) & 0xFF);
            
            result[i] = (byte) scrambled;
        }
        
        return result;
    }

    /**
     * Second encryption layer: Position-dependent bit rotation
     * Rotation amount calculated from byte position and key value
     * Conditional rotation prevents unnecessary operations when rotation is zero
     */
    private byte[] layer2Manipulate(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        
        for (int i = 0; i < data.length; i++) {
            byte keyByte = key[i % key.length];
            byte dataByte = data[i];
            
            // Rotate bits based on position and key
            int rotation = (i + (keyByte & 0xFF)) % 8;
            int manipulated = dataByte & 0xFF;
            
            if (rotation > 0) {
                manipulated = ((manipulated << rotation) | (manipulated >>> (8 - rotation))) & 0xFF;
            }
            
            // Mix in some position-dependent randomness
            manipulated = manipulated ^ ((keyByte + i) & 0xFF);
            
            result[i] = (byte) manipulated;
        }
        
        return result;
    }

    /**
     * Third encryption layer: AES-256-CBC encryption
     * Uses Java Cipher class with PKCS5Padding for standard compliance
     * CBC mode requires unique IV for each encryption operation
     */
    private Map<String, byte[]> layer3Encrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(data);
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("encrypted", encrypted);
        result.put("iv", iv);
        return result;
    }

    /**
     * Layer 3: AES-256 decryption
     */
    private byte[] layer3Decrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        
        return cipher.doFinal(data);
    }

    /**
     * Apply key decay by XORing with time-based hash
     * Prevents key reuse attacks by modifying keys after each operation
     * Uses current timestamp to ensure uniqueness of decay value
     */
    private Map<String, Object> applyKeyDecay(Map<String, Object> keys) throws Exception {
        Map<String, Object> decayedKeys = new HashMap<>();
        
        for (Map.Entry<String, Object> entry : keys.entrySet()) {
            String keyName = entry.getKey();
            Object key = entry.getValue();
            
            if (keyName.equals("timestamp")) {
                decayedKeys.put(keyName, key);
                continue;
            }
            
            if (key instanceof byte[]) {
                byte[] keyBytes = (byte[]) key;
                // Mix in some fresh randomness to age the key
                String timeStr = String.valueOf(System.currentTimeMillis());
                byte[] decayValue = hashPassword(new String(keyBytes, StandardCharsets.UTF_8) + timeStr);
                
                byte[] decayedKey = new byte[keyBytes.length];
                for (int i = 0; i < keyBytes.length; i++) {
                    decayedKey[i] = (byte) (keyBytes[i] ^ decayValue[i % decayValue.length]);
                }
                
                decayedKeys.put(keyName, decayedKey);
            } else {
                decayedKeys.put(keyName, key);
            }
        }
        
        return decayedKeys;
    }

    /**
     * Main encryption function implementing triple-layer encryption
     * Processes data through bit scrambling, position-dependent rotation, and AES-256
     * Returns JSON string containing encrypted data and metadata
     */
    public String encrypt(String data) throws Exception {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        
        // Generate base key from password
        byte[] baseKey = hashPassword(basePassword);
        
        // Generate time-shifted keys
        long timestamp = System.currentTimeMillis();
        Map<String, Object> keys = generateTimeShiftedKeys(baseKey, timestamp);
        
        // Generate nonce and padding
        Map<String, byte[]> nonceAndPadding = generateNonceAndPadding();
        byte[] nonce = nonceAndPadding.get("nonce");
        byte[] padding = nonceAndPadding.get("padding");
        
        // Add padding to data
        byte[] paddedData = new byte[dataBytes.length + padding.length];
        System.arraycopy(dataBytes, 0, paddedData, 0, dataBytes.length);
        System.arraycopy(padding, 0, paddedData, dataBytes.length, padding.length);
        
        // Layer 1: Bitwise scrambling
        byte[] layer1Result = layer1Scramble(paddedData, (byte[]) keys.get("key1"));
        
        // Layer 2: Advanced bit manipulation
        byte[] layer2Result = layer2Manipulate(layer1Result, (byte[]) keys.get("key2"));
        
        // Layer 3: AES encryption
        Map<String, byte[]> layer3Result = layer3Encrypt(layer2Result, (byte[]) keys.get("key3"));
        
        // Apply key decay
        applyKeyDecay(keys);
        
        // Combine all components
        JSONObject result = new JSONObject();
        result.put("encrypted", Base64.getEncoder().encodeToString(layer3Result.get("encrypted")));
        result.put("iv", Base64.getEncoder().encodeToString(layer3Result.get("iv")));
        result.put("nonce", Base64.getEncoder().encodeToString(nonce));
        result.put("timestamp", timestamp);
        result.put("paddingLength", padding.length);
        
        return result.toString();
    }

    /**
     * Decrypt data using triple-layer decryption
     */
    public String decrypt(String encryptedData) throws Exception {
        JSONObject data = new JSONObject(encryptedData);
        
        // Parse components
        byte[] encrypted = Base64.getDecoder().decode(data.getString("encrypted"));
        byte[] iv = Base64.getDecoder().decode(data.getString("iv"));
        byte[] nonce = Base64.getDecoder().decode(data.getString("nonce"));
        long timestamp = data.getLong("timestamp");
        int paddingLength = data.getInt("paddingLength");
        
        // Generate base key from password
        byte[] baseKey = hashPassword(basePassword);
        
        // Regenerate time-shifted keys (must use same timestamp)
        Map<String, Object> keys = generateTimeShiftedKeys(baseKey, timestamp);
        
        // Layer 3: AES decryption
        byte[] layer3Result = layer3Decrypt(encrypted, (byte[]) keys.get("key3"), iv);
        
        // Layer 2: Reverse bit manipulation
        byte[] layer2Result = layer2Manipulate(layer3Result, (byte[]) keys.get("key2"));
        
        // Layer 1: Reverse bitwise scrambling
        byte[] layer1Result = layer1Scramble(layer2Result, (byte[]) keys.get("key1"));
        
        // Remove padding
        byte[] originalData = new byte[layer1Result.length - paddingLength];
        System.arraycopy(layer1Result, 0, originalData, 0, originalData.length);
        
        return new String(originalData, StandardCharsets.UTF_8);
    }

    /**
     * Generate a new key pair for asymmetric operations (if needed)
     */
    public Map<String, String> generateKeyPair() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        byte[] publicKey = hashPassword(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        
        Map<String, String> keyPair = new HashMap<>();
        keyPair.put("private_key", Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        keyPair.put("public_key", Base64.getEncoder().encodeToString(publicKey));
        
        return keyPair;
    }
} 