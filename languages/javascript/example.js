const XANDEncrypt = require('./xand-encrypt');

// Example usage
async function main() {
    try {
        // Create an instance with a password
        const encryptor = new XANDEncrypt('my-secret-password');
        
        // Data to encrypt
        const originalData = 'Hello, this is a secret message!';
        console.log('Original data:', originalData);
        
        // Encrypt the data
        const encrypted = encryptor.encrypt(originalData);
        console.log('Encrypted data:', encrypted);
        
        // Decrypt the data
        const decrypted = encryptor.decrypt(encrypted);
        console.log('Decrypted data:', decrypted);
        
        // Verify the data matches
        console.log('Data matches:', originalData === decrypted);
        
        // Demonstrate that each encryption produces different output
        const encrypted1 = encryptor.encrypt(originalData);
        const encrypted2 = encryptor.encrypt(originalData);
        console.log('Different outputs:', encrypted1 !== encrypted2);
        
        // Generate a key pair
        const keyPair = encryptor.generateKeyPair();
        console.log('Key pair generated:', keyPair);
        
    } catch (error) {
        console.error('Error:', error.message);
    }
}

main(); 