<?php

require_once 'XANDEncrypt.php';

try {
    // Create an instance with a password
    $encryptor = new XANDEncrypt('my-secret-password');
    
    // Data to encrypt
    $originalData = 'Hello, this is a secret message!';
    echo "Original data: " . $originalData . "\n";
    
    // Encrypt the data
    $encrypted = $encryptor->encrypt($originalData);
    echo "Encrypted data: " . $encrypted . "\n";
    
    // Decrypt the data
    $decrypted = $encryptor->decrypt($encrypted);
    echo "Decrypted data: " . $decrypted . "\n";
    
    // Verify the data matches
    echo "Data matches: " . ($originalData === $decrypted ? 'true' : 'false') . "\n";
    
    // Demonstrate that each encryption produces different output
    $encrypted1 = $encryptor->encrypt($originalData);
    $encrypted2 = $encryptor->encrypt($originalData);
    echo "Different outputs: " . ($encrypted1 !== $encrypted2 ? 'true' : 'false') . "\n";
    
    // Generate a key pair
    $keyPair = $encryptor->generateKeyPair();
    echo "Key pair generated: " . json_encode($keyPair) . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
} 