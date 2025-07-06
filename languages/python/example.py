from xand_encrypt import XANDEncrypt

def main():
    try:
        # Create an instance with a password
        encryptor = XANDEncrypt('my-secret-password')
        
        # Data to encrypt
        original_data = 'Hello, this is a secret message!'
        print('Original data:', original_data)
        
        # Encrypt the data
        encrypted = encryptor.encrypt(original_data)
        print('Encrypted data:', encrypted)
        
        # Decrypt the data
        decrypted = encryptor.decrypt(encrypted)
        print('Decrypted data:', decrypted)
        
        # Verify the data matches
        print('Data matches:', original_data == decrypted)
        
        # Demonstrate that each encryption produces different output
        encrypted1 = encryptor.encrypt(original_data)
        encrypted2 = encryptor.encrypt(original_data)
        print('Different outputs:', encrypted1 != encrypted2)
        
        # Generate a key pair
        key_pair = encryptor.generate_key_pair()
        print('Key pair generated:', key_pair)
        
    except Exception as error:
        print('Error:', str(error))

if __name__ == '__main__':
    main() 