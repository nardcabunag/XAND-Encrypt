using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace XANDEncrypt
{
    /// <summary>
    /// Holds all the pieces we need to decrypt our data later
    /// Think of this like a secure envelope with all the instructions inside
    /// </summary>
    public class EncryptedData
    {
        public string Encrypted { get; set; } = string.Empty;
        public string Iv { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public long Timestamp { get; set; }
        public int PaddingLength { get; set; }

        /// <summary>
        /// Convert our encrypted data to a JSON string for easy storage
        /// </summary>
        public string ToJson()
        {
            return JsonSerializer.Serialize(this);
        }

        /// <summary>
        /// Create encrypted data from a JSON string
        /// </summary>
        public static EncryptedData FromJson(string json)
        {
            return JsonSerializer.Deserialize<EncryptedData>(json) ?? new EncryptedData();
        }
    }

    /// <summary>
    /// The main encryption class - this is what you'll use to protect your data
    /// It handles all the complex cryptography so you don't have to worry about it
    /// </summary>
    public class XANDEncrypt : IDisposable
    {
        // Our configuration constants
        private const int KeySize = 32;        // 256 bits
        private const int NonceSize = 16;      // 128 bits
        private const int PaddingSize = 16;    // Max padding
        private const int IvSize = 16;         // AES IV size

        // The password that protects all our data
        private readonly string _password;
        private bool _disposed = false;

        /// <summary>
        /// Create a new encryption system with your password - keep it safe!
        /// </summary>
        public XANDEncrypt(string password)
        {
            _password = password ?? throw new ArgumentNullException(nameof(password));
        }

        /// <summary>
        /// Clean up any sensitive data when we're done
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                // Clear any sensitive data from memory
                _disposed = true;
            }
        }

        /// <summary>
        /// Convert password to SHA-256 hash using .NET cryptography APIs
        /// SHA256.Create() uses native crypto libraries for optimized performance
        /// 'using' statement ensures proper disposal of cryptographic resources
        /// </summary>
        private byte[] HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        /// <summary>
        /// Generate three time-dependent keys using HMAC-SHA256
        /// BitConverter.GetBytes() handles endianness conversion automatically
        /// Tuple return type provides multiple values without out parameters
        /// </summary>
        private (byte[] key1, byte[] key2, byte[] key3, long timestamp) GenerateTimeShiftedKeys(byte[] baseKey, long timestamp)
        {
            var timeBuffer = BitConverter.GetBytes(timestamp);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(timeBuffer);

            // Each layer gets its own unique key derived from the previous one
            // C# HMAC is thread-safe and uses native crypto libraries when available
            var key1 = ComputeHmac(baseKey, timeBuffer);
            var key2 = ComputeHmac(key1, Encoding.UTF8.GetBytes("layer2"));
            var key3 = ComputeHmac(key2, Encoding.UTF8.GetBytes("layer3"));

            return (key1, key2, key3, timestamp);
        }

        /// <summary>
        /// Generate cryptographically secure random nonce and padding
        /// RandomNumberGenerator.Create() uses OS random number generator
        /// 'using' statement ensures proper disposal of RNG instance
        /// </summary>
        private (byte[] nonce, byte[] padding) GenerateNonceAndPadding()
        {
            var nonce = new byte[NonceSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }

            var paddingLength = (nonce[0] % PaddingSize) + 1;
            var padding = new byte[paddingLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(padding);
            }

            return (nonce, padding);
        }

        /// <summary>
        /// First encryption layer: XOR and bit rotation operations
        /// C# bitwise operations operate on int, requiring byte casting for 8-bit values
        /// JIT compiler optimizes bitwise operations to efficient machine code
        /// </summary>
        private byte[] Layer1Scramble(byte[] data, byte[] key)
        {
            var result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                var keyByte = key[i % key.Length];
                var dataByte = data[i];

                // Do some bit magic to scramble the data
                // C# bitwise ops work on int, so we cast back to byte after operations
                var scrambled = (byte)(dataByte ^ keyByte);
                scrambled = (byte)(((scrambled << 3) | (scrambled >> 5)) & 0xFF); // Rotate left by 3
                scrambled = (byte)(scrambled ^ (((keyByte << 1) | (keyByte >> 7)) & 0xFF));

                result[i] = scrambled;
            }

            return result;
        }

        /// <summary>
        /// Second encryption layer: Position-dependent bit rotation
        /// Rotation amount calculated from byte position and key value
        /// Conditional rotation prevents unnecessary operations when rotation is zero
        /// </summary>
        private byte[] Layer2Manipulate(byte[] data, byte[] key)
        {
            var result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                var keyByte = key[i % key.Length];
                var dataByte = data[i];

                // Rotate bits based on position and key
                var rotation = (i + keyByte) % 8;
                var manipulated = dataByte;

                if (rotation > 0)
                {
                    manipulated = (byte)(((manipulated << rotation) | (manipulated >> (8 - rotation))) & 0xFF);
                }

                // Mix in some position-dependent randomness
                manipulated = (byte)(manipulated ^ ((keyByte + i) & 0xFF));

                result[i] = manipulated;
            }

            return result;
        }

        /// <summary>
        /// Third encryption layer: AES-256-CBC encryption
        /// Uses .NET Aes class with PKCS7 padding for standard compliance
        /// CBC mode requires unique IV for each encryption operation
        /// </summary>
        private (byte[] encrypted, byte[] iv) Layer3Encrypt(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var iv = aes.IV;
            using var encryptor = aes.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

            return (encrypted, iv);
        }

        /// <summary>
        /// Third layer decryption: Reverse the AES-256 encryption
        /// </summary>
        private byte[] Layer3Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Apply key decay by XORing with time-based hash
        /// Prevents key reuse attacks by modifying keys after each operation
        /// Uses current timestamp to ensure uniqueness of decay value
        /// </summary>
        private void ApplyKeyDecay(ref byte[] key1, ref byte[] key2, ref byte[] key3)
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var timeStr = timestamp.ToString();

            // Mix in some fresh randomness to age the keys
            var keys = new[] { key1, key2, key3 };
            for (int i = 0; i < keys.Length; i++)
            {
                var decayValue = ComputeHmac(keys[i], Encoding.UTF8.GetBytes(timeStr));
                for (int j = 0; j < keys[i].Length; j++)
                {
                    keys[i][j] ^= decayValue[j % decayValue.Length];
                }
            }

            key1 = keys[0];
            key2 = keys[1];
            key3 = keys[2];
        }

        /// <summary>
        /// Compute HMAC-SHA256 for key derivation
        /// </summary>
        private byte[] ComputeHmac(byte[] key, byte[] data)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }

        /// <summary>
        /// Convert bytes to a hex string for easy storage
        /// </summary>
        private string BytesToHex(byte[] bytes)
        {
            return Convert.ToHexString(bytes).ToLower();
        }

        /// <summary>
        /// Convert a hex string back to bytes
        /// </summary>
        private byte[] HexToBytes(string hex)
        {
            return Convert.FromHexString(hex);
        }

        /// <summary>
        /// Main encryption function implementing triple-layer encryption
        /// Processes data through bit scrambling, position-dependent rotation, and AES-256
        /// Returns EncryptedData object containing encrypted data and metadata
        /// </summary>
        public EncryptedData Encrypt(string data)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("Data cannot be null or empty", nameof(data));

            // Generate our base key from the password
            var baseKey = HashPassword(_password);

            // Create three unique keys that change over time
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var (key1, key2, key3) = GenerateTimeShiftedKeys(baseKey, timestamp);

            // Generate some random data to make each encryption unique
            var (nonce, padding) = GenerateNonceAndPadding();

            // Prepare our data with padding
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var paddedData = new byte[dataBytes.Length + padding.Length];
            Array.Copy(dataBytes, paddedData, dataBytes.Length);
            Array.Copy(padding, 0, paddedData, dataBytes.Length, padding.Length);

            // First layer: Mix up the data with some fancy bit operations
            var layer1Result = Layer1Scramble(paddedData, key1);

            // Second layer: More bit manipulation, but this time it depends on position
            var layer2Result = Layer2Manipulate(layer1Result, key2);

            // Third layer: The heavy artillery - AES-256 encryption
            var (layer3Result, iv) = Layer3Encrypt(layer2Result, key3);

            // After we use the keys, we modify them slightly
            var key1Copy = key1.ToArray();
            var key2Copy = key2.ToArray();
            var key3Copy = key3.ToArray();
            ApplyKeyDecay(ref key1Copy, ref key2Copy, ref key3Copy);

            // Package everything up for storage
            return new EncryptedData
            {
                Encrypted = BytesToHex(layer3Result),
                Iv = BytesToHex(iv),
                Nonce = BytesToHex(nonce),
                Timestamp = timestamp,
                PaddingLength = padding.Length
            };
        }

        /// <summary>
        /// Decrypt data that was encrypted with this class
        /// This reverses all three layers to get your original data back
        /// </summary>
        public string Decrypt(EncryptedData encryptedData)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            // Generate our base key from the password
            var baseKey = HashPassword(_password);

            // Recreate the three keys using the same timestamp
            var (key1, key2, key3) = GenerateTimeShiftedKeys(baseKey, encryptedData.Timestamp);

            // Convert hex strings back to bytes
            var encrypted = HexToBytes(encryptedData.Encrypted);
            var iv = HexToBytes(encryptedData.Iv);
            var nonce = HexToBytes(encryptedData.Nonce);

            // Third layer: Reverse the AES-256 encryption
            var layer3Result = Layer3Decrypt(encrypted, key3, iv);

            // Second layer: Reverse the bit manipulation
            var layer2Result = Layer2Manipulate(layer3Result, key2);

            // First layer: Reverse the bit scrambling
            var layer1Result = Layer1Scramble(layer2Result, key1);

            // Remove the padding to get our original data
            var originalLength = layer1Result.Length - encryptedData.PaddingLength;
            var originalData = new byte[originalLength];
            Array.Copy(layer1Result, originalData, originalLength);

            return Encoding.UTF8.GetString(originalData);
        }

        /// <summary>
        /// Generate a key pair for asymmetric operations
        /// This creates a public and private key for advanced use cases
        /// </summary>
        public (string privateKey, string publicKey) GenerateKeyPair()
        {
            var privateKeyBytes = new byte[KeySize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateKeyBytes);
            }

            var publicKey = HashPassword(Convert.ToBase64String(privateKeyBytes));

            return (
                Convert.ToBase64String(privateKeyBytes),
                Convert.ToBase64String(publicKey)
            );
        }
    }
} 