# XAND-Encrypt Installation Guide

This guide provides installation instructions for the XAND-Encrypt library across all supported programming languages.

## Prerequisites

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 512MB RAM
- **Storage**: 100MB free space
- **Network**: Internet connection for downloading dependencies

### Language-Specific Requirements

#### JavaScript/Node.js
- **Node.js**: Version 14.0.0 or higher
- **npm**: Usually included with Node.js
- **Platform**: All platforms supported

#### Python
- **Python**: Version 3.7 or higher
- **pip**: Package installer for Python
- **Platform**: All platforms supported

#### Java
- **Java Development Kit (JDK)**: Version 11 or higher
- **Maven**: Version 3.6 or higher
- **Platform**: All platforms supported

#### PHP
- **PHP**: Version 7.4 or higher
- **OpenSSL**: Extension enabled
- **Platform**: All platforms supported

#### Rust
- **Rust**: Version 1.56 or higher
- **Cargo**: Usually included with Rust
- **Platform**: All platforms supported

#### Swift
- **Swift**: Version 5.3 or higher
- **Xcode**: Version 12.0 or higher (macOS)
- **Platform**: macOS, Linux, Windows (limited)

## Installation Instructions

### JavaScript/Node.js

#### Option 1: Direct Download
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/javascript

# Install dependencies (if any)
npm install

# Test the installation
node example.js
```

#### Option 2: npm Package (when published)
```bash
npm install xand-encrypt
```

### Python

#### Option 1: Direct Download
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/python

# No external dependencies required
python example.py
```

#### Option 2: pip Package (when published)
```bash
pip install xand-encrypt
```

### Java

#### Option 1: Maven Project
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/java

# Build the project
mvn clean install

# Run the example
mvn exec:java -Dexec.mainClass="Example"
```

#### Option 2: Direct Compilation
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/java

# Compile the Java files
javac -cp ".:json-20231013.jar" XANDEncrypt.java Example.java

# Run the example
java -cp ".:json-20231013.jar" Example
```

### PHP

#### Option 1: Direct Download
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/php

# Run the example
php example.php
```

#### Option 2: Composer Package (when published)
```bash
composer require xand-encrypt/xand-encrypt
```

### Rust

#### Option 1: Cargo Project
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/rust

# Build the project
cargo build

# Run tests
cargo test

# Run example (if available)
cargo run --example basic_usage
```

#### Option 2: Cargo Package (when published)
```bash
cargo add xand-encrypt
```

### Swift

#### Option 1: Swift Package Manager
```bash
# Clone the repository
git clone https://github.com/your-username/XAND-Encrypt.git
cd XAND-Encrypt/languages/swift

# Build the project
swift build

# Run tests
swift test
```

#### Option 2: Xcode Project
1. Open Xcode
2. Open the Swift project in `languages/swift/`
3. Build and run the project

## Verification

### Running Tests
Each language implementation includes example files and tests:

```bash
# JavaScript
cd languages/javascript && node example.js

# Python
cd languages/python && python example.py

# Java
cd languages/java && java Example

# PHP
cd languages/php && php example.php

# Rust
cd languages/rust && cargo test

# Swift
cd languages/swift && swift test
```

### Comprehensive Testing
Run the cross-language test suite:

```bash
# From the root directory
python test_all_languages.py
```

## Configuration

### Environment Variables
Some implementations may use environment variables for configuration:

```bash
# Optional: Set custom random seed (for testing only)
export XAND_ENCRYPT_SEED=12345

# Optional: Set custom key size (advanced users only)
export XAND_ENCRYPT_KEY_SIZE=32
```

### Security Considerations
1. **Random Number Generation**: Ensure your system has a good entropy source
2. **Password Strength**: Use strong passwords (12+ characters, mixed case, numbers, symbols)
3. **Key Storage**: Never store keys in plaintext
4. **Network Security**: Use secure channels for key transmission

## Troubleshooting

### Common Issues

#### JavaScript/Node.js
```bash
# Error: Cannot find module 'crypto'
# Solution: Node.js crypto module is built-in, no installation needed

# Error: Permission denied
# Solution: Run with appropriate permissions or use sudo (Linux/macOS)
```

#### Python
```bash
# Error: ModuleNotFoundError: No module named 'hashlib'
# Solution: hashlib is built-in, check Python version (3.7+)

# Error: Permission denied
# Solution: Check file permissions or use virtual environment
```

#### Java
```bash
# Error: javac: command not found
# Solution: Install JDK and set JAVA_HOME environment variable

# Error: ClassNotFoundException
# Solution: Ensure all required JAR files are in the classpath
```

#### PHP
```bash
# Error: Call to undefined function openssl_encrypt()
# Solution: Enable OpenSSL extension in php.ini

# Error: Permission denied
# Solution: Check file permissions and PHP execution rights
```

#### Rust
```bash
# Error: rustc: command not found
# Solution: Install Rust using rustup

# Error: Cargo.toml not found
# Solution: Ensure you're in the correct directory
```

#### Swift
```bash
# Error: swift: command not found
# Solution: Install Swift or Xcode Command Line Tools

# Error: Package.swift not found
# Solution: Ensure you're in the correct directory
```

### Performance Issues
- **Slow Encryption**: Normal for triple-layer encryption (3x slower than single AES)
- **High Memory Usage**: Check for memory leaks in your application
- **CPU Usage**: Encryption is CPU-intensive, consider background processing

### Security Issues
- **Weak Random Numbers**: Ensure cryptographically secure RNG
- **Key Exposure**: Check for logging or debugging output
- **Timing Attacks**: Use constant-time operations where possible

## Support

### Getting Help
1. **Documentation**: Check the [README.md](README.md) and [docs/](docs/) directory
2. **Issues**: Report bugs on GitHub Issues
3. **Discussions**: Ask questions on GitHub Discussions
4. **Email**: Contact team@xandencrypt.com

### Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to the project.

### Security Reporting
For security vulnerabilities, email security@xandencrypt.com instead of creating public issues.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details. 