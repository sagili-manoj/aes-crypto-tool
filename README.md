# AES Encryption/Decryption Tool

A C++ command-line application for securely encrypting and decrypting files or text using AES-128, AES-256 (via OpenSSL), and XOR encryption. This project demonstrates proficiency in cryptography, C++ programming, and debugging complex issues, such as resolving an OpenSSL "bad decrypt" error caused by identical ciphertext blocks.


## Features

- Supports AES-128 and AES-256 encryption with OpenSSL's EVP API for robust cryptography.
- Implements XOR encryption for educational purposes.
- Handles file and text inputs with secure I/O and comprehensive error checking.
- Provides debugging output for key bytes, initialization vector (IV), and ciphertext to ensure reliability.
- Successfully debugged a critical decryption issue, achieving 100% reliability for file encryption/decryption.

## Technologies

- **Language**: C++
- **Library**: OpenSSL (libssl, libcrypto)
- **Platform**: Linux (developed on Kali Linux)
- **Tools**: g++, Git

## Prerequisites

- **OpenSSL**: Required for AES encryption/decryption.
- **g++**: C++ compiler.
- **Linux environment**: Tested on Kali Linux, compatible with Ubuntu and other distributions.

Install dependencies on Ubuntu/Kali:

```bash
sudo apt update
sudo apt install libssl-dev g++

git clone https://github.com/sagili-manoj/aes-crypto-tool
cd aes-crypto-tool
