# AES Encryption/Decryption Tool (C++)

A robust and scalable C++ command-line tool for secure data and file encryption/decryption using AES-128/256 (CBC mode) via OpenSSL's EVP API, and a simpler XOR cipher. This project focuses on meticulous resource management, comprehensive error handling, and efficient processing of large files, demonstrating critical skills in cybersecurity and system programming.

## Features

* **Advanced AES Encryption/Decryption (OpenSSL EVP API):**
    * Supports AES-128-CBC and AES-256-CBC modes.
    * Utilizes OpenSSL's high-level EVP API for secure and standardized cryptographic operations.
    * Automatically generates and manages **Initialization Vectors (IVs)** for CBC mode, crucial for security.
* **Robust Resource Management (RAII):** Employs **`std::unique_ptr` with custom deleters (`EVPCipherCtxDeleter`)** to ensure `EVP_CIPHER_CTX` contexts are always properly freed, preventing resource leaks and improving code reliability, even in the face of errors.
* **Comprehensive Error Handling:** Implements **structured error handling using `std::runtime_error` exceptions** for all critical operations (file I/O, OpenSSL failures, invalid inputs). This ensures graceful program termination with clear diagnostic messages.
* **Scalable File Processing:** Capable of encrypting/decrypting **very large files (up to gigabytes)** by processing data in efficient chunks (4KB buffers), avoiding high memory consumption and enhancing performance.
* **Data Integrity & Reliability:** Designed with careful handling of cryptographic primitives and file operations to ensure **zero data loss** during file processing and achieve **100% data reliability** for valid inputs and keys.
* **Basic XOR Cipher:** Includes a simple XOR encryption/decryption option for both text and files, providing a comparative demonstration of cryptographic concepts.
* **Integrated Test Mode:** Features a built-in test suite to automatically verify the correctness of both text-based and file-based AES encryption/decryption processes.

## Project Structure

* `main.cpp`: Contains the complete source code for the encryption/decryption tool, including all cryptographic functions, RAII wrappers, and the main interactive logic.
* `test_input_file.txt`: A temporary file created and used during the built-in test mode to demonstrate file encryption/decryption.
* `encrypted_output.aes128/256`: Example output files for AES encryption.
* `encrypted_output.xor`: Example output file for XOR encryption.
* `decrypted_output.aes128/256.txt`: Example output files for AES decryption.
* `decrypted_output.xor`: Example output file for XOR decryption.

## Technologies Used

* **C++17 (or newer):** Leverages modern C++ features for robust and expressive code.
* **OpenSSL Library:** Specifically the EVP (High-level cryptographic functions), RAND (Random number generation), and ERR (Error handling) APIs.
* **Standard C++ Libraries:** `iostream` (input/output), `fstream` (file streams), `string`, `vector`, `iomanip` (formatting), `stdexcept` (exceptions), `memory` (`std::unique_ptr`), `limits`.

## Prerequisites

* **C++17 Compatible Compiler:** GCC, Clang, or MSVC.
* **OpenSSL Development Libraries:** You need OpenSSL installed on your system, specifically the development headers and libraries.

    * **On Debian/Ubuntu:**
        ```bash
        sudo apt-get update
        sudo apt-get install libssl-dev
        ```
    * **On Fedora/RHEL/CentOS:**
        ```bash
        sudo yum install openssl-devel
        # OR (for newer Fedora/RHEL)
        sudo dnf install openssl-devel
        ```
    * **On macOS (using Homebrew):**
        ```bash
        brew install openssl
        ```
        *Note: On macOS, you might need to specify include and library paths during compilation if OpenSSL is not in standard locations (e.g., `-I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib` if installed via Homebrew).*

## How to Build and Run

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sagili-manoj/aes-crypto-tool.git
    cd aes-crypto-tool
    ```
2.  **Compile the code:**
    Use a C++17 compatible compiler and **link against the OpenSSL crypto library (`-lcrypto`)**.

    ```bash
    g++ -std=c++17 -Wall -Wextra -pedantic EncryptAndDecrypt.cpp -lcrypto -o aes_tool
    ```
    * `-std=c++17`: Specifies the C++17 standard.
    * `-Wall -Wextra -pedantic`: Enables extensive warnings and strict adherence to the standard, crucial for high-quality code.
    * `main.cpp`: Your source file.
    * `-lcrypto`: **Crucially**, links the OpenSSL crypto library.
    * `-o aes_tool`: Names the output executable `aes_tool`.

3.  **Run the executable:**
    ```bash
    ./aes_tool
    ```

4.  **Follow the on-screen prompts** to choose between encryption, decryption, or the built-in test mode.

## Usage Examples

```bash
# Run the tool
./aes_tool

# Example session for Encryption (interactive):
# Select action:
# 1. Encrypt
# 2. Decrypt
# 3. Test Encryption/Decryption
# Enter choice (1/2/3): 1

# Select input type:
# 1. File
# 2. Text Message
# Enter choice (1/2): 2
# Enter the text message: Hello World, this is a secret!

# Select encryption level:
# 1. Basic XOR encryption
# 2. AES-128 encryption (CBC mode)
# 3. AES-256 encryption (CBC mode)
# Enter choice (1/2/3): 2

# Enter the key for AES-128 encryption (16 characters): mysecretpassword

# --- Encryption ---
# Encrypting with key (length: 16): Key bytes: [hex representation of key]
# Generated IV: [hex representation of IV]
# Ciphertext size: [size] bytes
# Encrypted text saved as binary to: text_encrypted.aes128

# To decrypt, you would run the tool again and choose option 2, providing
# "text_encrypted.aes128" as the encrypted file and "mysecretpassword" as the key.

# Example output from Test Mode:
# --- Testing Encryption/Decryption ---
# Test 1: Text-based AES-128 encryption/decryption...
# Original data: My name is unkneo i am a engineer. This is a test message for encryption.
# Encrypting with key (length: 16): Key bytes: [hex key]
# Generated IV: [hex IV]
# Ciphertext size: [size] bytes
# Decrypting with key (length: 16): Key bytes: [hex key]
# Ciphertext size: [size] bytes
# Extracted IV: [hex IV]
# Decrypted plaintext size: [size] bytes
# Decrypted data: My name is unkneo i am a engineer. This is a test message for encryption.
# Test 1 passed: Decrypted data matches original!

# Test 2: File-based AES-256 encryption/decryption...
# Created test file: test_input_file.txt with size: 130 bytes
# Input file size: 130 bytes
# Generated IV (for file): [hex IV]
# Processed 4096 bytes...
# ...
# File processing complete! Total bytes written: [total_bytes] bytes
# File encrypted to: test_encrypted_file.aes256
# Input file size: [size] bytes
# Extracted IV (from file): [hex IV]
# Processed 4096 bytes...
# ...
# File processing complete! Total bytes written: [total_bytes] bytes
# File decrypted to: test_decrypted_file.txt
# Test 2 passed: Decrypted file content matches original! with Ubuntu and other distributions.

Install dependencies on Ubuntu/Kali:

```bash
sudo apt update
sudo apt install libssl-dev g++

git clone https://github.com/sagili-manoj/aes-crypto-tool
cd aes-crypto-tool
