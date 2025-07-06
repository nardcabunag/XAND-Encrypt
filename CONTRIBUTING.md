# Contributing to XAND-Encrypt

Thank you for your interest in contributing to XAND-Encrypt! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites
- Knowledge of cryptography and security best practices
- Experience with at least one of the supported programming languages
- Understanding of the triple-layer encryption algorithm

### Supported Languages
- JavaScript/Node.js
- Python
- Java
- PHP
- Rust
- Swift

## Development Setup

### 1. Fork the Repository
```bash
git clone https://github.com/nardcabunag/XAND-Encrypt.git
cd XAND-Encrypt
```

### 2. Set Up Development Environment
Each language has its own setup requirements:

#### JavaScript/Node.js
```bash
cd languages/javascript
npm install
```

#### Python
```bash
cd languages/python
# No external dependencies required for basic functionality
```

#### Java
```bash
cd languages/java
mvn install
```

#### PHP
```bash
cd languages/php
# No external dependencies required
```

#### Rust
```bash
cd languages/rust
cargo build
```

#### Swift
```bash
cd languages/swift
# Use Xcode or Swift Package Manager
```

## Code Style Guidelines

### General Principles
1. **Security First**: All code must prioritize security over performance
2. **Consistency**: Follow the existing code style in each language
3. **Documentation**: Document all public APIs and security-critical functions
4. **Testing**: Include comprehensive tests for all new features

### Language-Specific Guidelines

#### JavaScript/Node.js
- Use ES6+ features
- Follow Node.js best practices
- Use async/await for asynchronous operations
- Include JSDoc comments for all public methods

#### Python
- Follow PEP 8 style guide
- Use type hints where appropriate
- Include docstrings for all functions
- Use f-strings for string formatting

#### Java
- Follow Google Java Style Guide
- Use meaningful variable and method names
- Include comprehensive JavaDoc
- Handle exceptions appropriately

#### PHP
- Follow PSR-12 coding standards
- Use strict typing where possible
- Include PHPDoc comments
- Use modern PHP features (7.4+)

#### Rust
- Follow Rust coding conventions
- Use meaningful error types
- Include comprehensive documentation
- Write unit tests for all functions

#### Swift
- Follow Swift API Design Guidelines
- Use meaningful naming conventions
- Include comprehensive documentation
- Handle errors appropriately

## Security Guidelines

### Cryptographic Implementation
1. **Never implement custom cryptographic algorithms**
2. **Use well-established cryptographic libraries**
3. **Validate all inputs thoroughly**
4. **Use constant-time operations where possible**
5. **Never log or expose sensitive data**

### Code Review Checklist
- [ ] No hardcoded secrets or keys
- [ ] Proper input validation
- [ ] Secure random number generation
- [ ] No timing vulnerabilities
- [ ] Proper error handling
- [ ] No information leakage

## Testing Requirements

### Unit Tests
- Test all public methods
- Test edge cases and error conditions
- Test cryptographic properties
- Ensure deterministic behavior where required

### Integration Tests
- Test cross-language compatibility
- Test encryption/decryption round-trips
- Test key generation and management
- Test error handling scenarios

### Security Tests
- Test against known attack vectors
- Verify entropy sources
- Test key derivation functions
- Validate cryptographic properties

## Submitting Changes

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes
- Implement the feature or fix
- Add appropriate tests
- Update documentation
- Follow coding standards

### 3. Test Your Changes
```bash
# Run all tests for your language
npm test          # JavaScript
python -m pytest  # Python
mvn test          # Java
# etc.
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "feat: add new feature description"
```

### 5. Push and Create Pull Request
```bash
git push origin feature/your-feature-name
```

### Commit Message Format
Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `test:` for test additions
- `refactor:` for code refactoring
- `security:` for security-related changes

## Pull Request Process

### 1. Create Pull Request
- Provide clear description of changes
- Reference any related issues
- Include test results
- Update documentation if needed

### 2. Code Review
- All PRs require at least one review
- Security-related changes require security review
- Address all review comments
- Ensure all tests pass

### 3. Merge Requirements
- All tests must pass
- Code review approved
- Documentation updated
- Security review completed (if applicable)

## Security Reporting

### Reporting Security Issues
If you discover a security vulnerability, please:

1. **DO NOT** create a public issue
2. Email jonardcabunag66@gmail.com
3. Include detailed description of the vulnerability
4. Provide proof-of-concept if possible
5. Allow time for response and fix

### Security Response Process
1. Acknowledge receipt within 48 hours
2. Investigate and validate the issue
3. Develop and test fixes
4. Release security update
5. Credit the reporter (if desired)

## Documentation

### Required Documentation
- API documentation for all public methods
- Security considerations and limitations
- Usage examples and best practices
- Performance characteristics
- Compatibility information

### Documentation Standards
- Clear and concise writing
- Include code examples
- Document security implications
- Keep documentation up-to-date

## Release Process

### Versioning
Follow semantic versioning (SemVer):
- MAJOR.MINOR.PATCH
- MAJOR: Breaking changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes, backward compatible

### Release Checklist
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Security review completed
- [ ] Performance benchmarks run
- [ ] Changelog updated
- [ ] Version numbers updated

## Community Guidelines

### Code of Conduct
- Be respectful and inclusive
- Focus on technical discussions
- Help others learn and grow
- Report inappropriate behavior

### Communication
- Use GitHub issues for bug reports
- Use GitHub discussions for questions
- Be patient and helpful
- Provide constructive feedback

## Getting Help

### Resources
- [Algorithm Documentation](docs/ALGORITHM.md)
- [Security Guidelines](docs/SECURITY.md)
- [API Reference](docs/API.md)

### Contact
- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For questions and discussions
- Email: jonardcabunag66@gmail.com

Thank you for contributing to XAND-Encrypt! 
