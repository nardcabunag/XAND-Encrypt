import java.util.Map;

public class Example {
    public static void main(String[] args) {
        try {
            // Create an instance with a password
            XANDEncrypt encryptor = new XANDEncrypt("my-secret-password");
            
            // Data to encrypt
            String originalData = "Hello, this is a secret message!";
            System.out.println("Original data: " + originalData);
            
            // Encrypt the data
            String encrypted = encryptor.encrypt(originalData);
            System.out.println("Encrypted data: " + encrypted);
            
            // Decrypt the data
            String decrypted = encryptor.decrypt(encrypted);
            System.out.println("Decrypted data: " + decrypted);
            
            // Verify the data matches
            System.out.println("Data matches: " + originalData.equals(decrypted));
            
            // Demonstrate that each encryption produces different output
            String encrypted1 = encryptor.encrypt(originalData);
            String encrypted2 = encryptor.encrypt(originalData);
            System.out.println("Different outputs: " + !encrypted1.equals(encrypted2));
            
            // Generate a key pair
            Map<String, String> keyPair = encryptor.generateKeyPair();
            System.out.println("Key pair generated: " + keyPair);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 