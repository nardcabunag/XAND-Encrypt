using System;
using XANDEncrypt;

class Example
{
    static void Main()
    {
        try
        {
            // Create an instance with a password
            using var encryptor = new XANDEncrypt("my-secret-password");
            
            // Data to encrypt
            var originalData = "Hello, this is a secret message!";
            Console.WriteLine($"Original data: {originalData}");
            
            // Encrypt the data
            var encrypted = encryptor.Encrypt(originalData);
            Console.WriteLine($"Encrypted data: {encrypted.ToJson()}");
            
            // Decrypt the data
            var decrypted = encryptor.Decrypt(encrypted);
            Console.WriteLine($"Decrypted data: {decrypted}");
            
            // Verify the data matches
            Console.WriteLine($"Data matches: {originalData == decrypted}");
            
            // Demonstrate that each encryption produces different output
            var encrypted1 = encryptor.Encrypt(originalData);
            var encrypted2 = encryptor.Encrypt(originalData);
            Console.WriteLine($"Different outputs: {encrypted1.ToJson() != encrypted2.ToJson()}");
            
            // Generate a key pair
            var (privateKey, publicKey) = encryptor.GenerateKeyPair();
            Console.WriteLine($"Key pair generated:");
            Console.WriteLine($"  Private key: {privateKey}");
            Console.WriteLine($"  Public key: {publicKey}");
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
} 