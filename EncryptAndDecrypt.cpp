#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <stdexcept>
#include <memory>
#include <limits>

#define AES_BLOCK_SIZE 16
#define FILE_BUFFER_SIZE 4096

struct EVPCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxDeleter>;

void printOpenSSLErrors(const std::string& msg) {
    std::cerr << "OpenSSL Error: " << msg << std::endl;
    ERR_print_errors_fp(stderr);
    ERR_clear_error();
}

void printHex(const std::string& label, const unsigned char* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

bool validateKeyLength(const std::string& key, int keyBits) {
    size_t expectedLength = (keyBits == 128) ? 16 : 32;
    if (key.length() != expectedLength) {
        std::cerr << "Error: Invalid key length! AES-" << keyBits << " requires a " << expectedLength << "-byte key. Provided: " << key.length() << " bytes." << std::endl;
        return false;
    }
    return true;
}

std::vector<unsigned char> AES_Encrypt_EVP_Buffer(const std::vector<unsigned char>& plaintext_buffer, const std::string& key, int keyBits) {
    std::cout << "Encrypting with key (length: " << key.length() << "): ";
    printHex("Key bytes", (const unsigned char*)key.c_str(), key.length());

    const EVP_CIPHER* cipher = nullptr;
    if (keyBits == 128) {
        cipher = EVP_aes_128_cbc();
    } else if (keyBits == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        throw std::runtime_error("Unsupported key size: " + std::to_string(keyBits));
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        printOpenSSLErrors("Error creating cipher context");
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        printOpenSSLErrors("Error generating IV");
        throw std::runtime_error("Failed to generate random IV.");
    }
    printHex("Generated IV", iv, AES_BLOCK_SIZE);

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
        printOpenSSLErrors("Error initializing encryption");
        throw std::runtime_error("Failed to initialize encryption.");
    }

    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(AES_BLOCK_SIZE + plaintext_buffer.size() + AES_BLOCK_SIZE);
    ciphertext.insert(ciphertext.end(), iv, iv + AES_BLOCK_SIZE);

    std::vector<unsigned char> outBuffer(plaintext_buffer.size() + AES_BLOCK_SIZE);
    int outLen = 0;

    if (EVP_EncryptUpdate(ctx.get(), outBuffer.data(), &outLen, plaintext_buffer.data(), plaintext_buffer.size()) != 1) {
        printOpenSSLErrors("Error during encryption update");
        throw std::runtime_error("Failed during encryption update.");
    }
    ciphertext.insert(ciphertext.end(), outBuffer.begin(), outBuffer.begin() + outLen);

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &finalLen) != 1) {
        printOpenSSLErrors("Error during final encryption");
        throw std::runtime_error("Failed during final encryption (padding error or context issue).");
    }
    ciphertext.insert(ciphertext.end(), outBuffer.begin(), outBuffer.begin() + finalLen);

    std::cout << "Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
    return ciphertext;
}

std::vector<unsigned char> AES_Decrypt_EVP_Buffer(const std::vector<unsigned char>& ciphertext, const std::string& key, int keyBits) {
    std::cout << "Decrypting with key (length: " << key.length() << "): ";
    printHex("Key bytes", (const unsigned char*)key.c_str(), key.length());
    std::cout << "Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;

    if (ciphertext.size() < AES_BLOCK_SIZE) {
        throw std::runtime_error("Ciphertext too short to contain IV! Size: " + std::to_string(ciphertext.size()) + " bytes.");
    }
    if ((ciphertext.size() - AES_BLOCK_SIZE) % AES_BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid ciphertext length after IV extraction: " + std::to_string(ciphertext.size() - AES_BLOCK_SIZE) + " bytes. Must be a multiple of " + std::to_string(AES_BLOCK_SIZE) + " bytes.");
    }

    const EVP_CIPHER* cipher = nullptr;
    if (keyBits == 128) {
        cipher = EVP_aes_128_cbc();
    } else if (keyBits == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        throw std::runtime_error("Unsupported key size: " + std::to_string(keyBits));
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        printOpenSSLErrors("Error creating cipher context");
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    std::copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);
    printHex("Extracted IV", iv, AES_BLOCK_SIZE);

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
        printOpenSSLErrors("Error initializing decryption");
        throw std::runtime_error("Failed to initialize decryption (e.g., bad key).");
    }

    std::vector<unsigned char> inBuffer(ciphertext.begin() + AES_BLOCK_SIZE, ciphertext.end());
    std::vector<unsigned char> outBuffer(inBuffer.size() + AES_BLOCK_SIZE);
    int outLen = 0;

    if (EVP_DecryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), inBuffer.size()) != 1) {
        printOpenSSLErrors("Error during decryption update");
        throw std::runtime_error("Failed during decryption update.");
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), outBuffer.data() + outLen, &finalLen) != 1) {
        printOpenSSLErrors("Error during final decryption (possible causes: wrong key, corrupted ciphertext, or invalid padding)");
        throw std::runtime_error("Failed during final decryption.");
    }
    outLen += finalLen;

    std::vector<unsigned char> plaintext(outBuffer.begin(), outBuffer.begin() + outLen);
    std::cout << "Decrypted plaintext size: " << plaintext.size() << " bytes" << std::endl;
    return plaintext;
}

std::vector<unsigned char> readFileToBuffer(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Error opening file for reading: " + filename);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size == 0) return {};

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Error reading from file: " + filename);
    }
    file.close();
    return buffer;
}

void writeBufferToFile(const std::string& filename, const std::vector<unsigned char>& buffer) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error opening file for writing: " + filename);
    }
    if (!file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size())) {
        throw std::runtime_error("Error writing to file: " + filename);
    }
    file.close();
}

void AES_File_Process(const std::string& inputFile, const std::string& outputFile, const std::string& key, int keyBits, bool encrypt) {
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Error opening input file: " + inputFile);
    }
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        inFile.close();
        throw std::runtime_error("Error opening output file: " + outputFile);
    }

    // Check input file size
    inFile.seekg(0, std::ios::end);
    std::streamsize inputSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    std::cout << "Input file size: " << inputSize << " bytes" << std::endl;

    const EVP_CIPHER* cipher = nullptr;
    if (keyBits == 128) {
        cipher = EVP_aes_128_cbc();
    } else if (keyBits == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        inFile.close();
        outFile.close();
        throw std::runtime_error("Unsupported key size: " + std::to_string(keyBits));
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        inFile.close();
        outFile.close();
        printOpenSSLErrors("Error creating cipher context");
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (encrypt) {
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            printOpenSSLErrors("Error generating IV");
            throw std::runtime_error("Failed to generate random IV.");
        }
        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outFile.flush(); // Ensure IV is written
        printHex("Generated IV (for file)", iv, AES_BLOCK_SIZE);
        if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
            printOpenSSLErrors("Error initializing encryption");
            throw std::runtime_error("Failed to initialize encryption.");
        }
    } else {
        if (!inFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE)) {
            inFile.close();
            outFile.close();
            throw std::runtime_error("Error reading IV from encrypted file: " + inputFile);
        }
        printHex("Extracted IV (from file)", iv, AES_BLOCK_SIZE);
        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
            printOpenSSLErrors("Error initializing decryption");
            throw std::runtime_error("Failed to initialize decryption (e.g., bad key or IV).");
        }
    }

    unsigned char inBuffer[FILE_BUFFER_SIZE];
    unsigned char outBuffer[FILE_BUFFER_SIZE + AES_BLOCK_SIZE];
    int outLen = 0;
    int totalBytesProcessed = 0;
    int totalBytesWritten = 0;

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(inBuffer), FILE_BUFFER_SIZE);
        int bytesRead = inFile.gcount();
        if (bytesRead > 0) {
            if (encrypt) {
                if (EVP_EncryptUpdate(ctx.get(), outBuffer, &outLen, inBuffer, bytesRead) != 1) {
                    printOpenSSLErrors("Error during encryption update");
                    throw std::runtime_error("Failed during encryption update.");
                }
            } else {
                if (EVP_DecryptUpdate(ctx.get(), outBuffer, &outLen, inBuffer, bytesRead) != 1) {
                    printOpenSSLErrors("Error during decryption update");
                    throw std::runtime_error("Failed during decryption update.");
                }
            }
            if (outLen > 0) {
                outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
                outFile.flush(); // Ensure data is written
                if (!outFile) {
                    throw std::runtime_error("Error writing to output file: " + outputFile);
                }
                totalBytesWritten += outLen;
                std::cout << "Wrote " << outLen << " bytes to output (total written: " << totalBytesWritten << " bytes)\r" << std::flush;
            }
            totalBytesProcessed += bytesRead;
            std::cout << "Processed " << totalBytesProcessed << " bytes...\r" << std::flush;
        }
    }

    int finalLen = 0;
    if (encrypt) {
        if (EVP_EncryptFinal_ex(ctx.get(), outBuffer, &finalLen) != 1) {
            printOpenSSLErrors("Error during final encryption");
            throw std::runtime_error("Failed during final encryption (padding error).");
        }
    } else {
        if (EVP_DecryptFinal_ex(ctx.get(), outBuffer, &finalLen) != 1) {
            printOpenSSLErrors("Error during final decryption (possible causes: wrong key, corrupted ciphertext, or invalid padding)");
            throw std::runtime_error("Failed during final decryption.");
        }
    }
    if (finalLen > 0) {
        outFile.write(reinterpret_cast<char*>(outBuffer), finalLen);
        outFile.flush(); // Ensure final data is written
        if (!outFile) {
            throw std::runtime_error("Error writing final bytes to output file: " + outputFile);
        }
        totalBytesWritten += finalLen;
        std::cout << "Wrote final " << finalLen << " bytes to output (total written: " << totalBytesWritten << " bytes)\r" << std::flush;
    }
    std::cout << "\nFile processing complete! Total bytes written: " << totalBytesWritten << " bytes" << std::endl;

    outFile.close();
    std::ifstream checkFile(outputFile, std::ios::binary | std::ios::ate);
    std::cout << "Output file size: " << checkFile.tellg() << " bytes" << std::endl;
    checkFile.close();

    inFile.close();
}

std::string XOR_Text(const std::string& text, const std::string& key) {
    std::string result = text;
    size_t keyIndex = 0;
    for (char& c : result) {
        c ^= key[keyIndex];
        keyIndex = (keyIndex + 1) % key.size();
    }
    return result;
}

void XOR_File(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    std::ifstream in(inputFile, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Error opening input file for XOR: " + inputFile);
    }
    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        in.close();
        throw std::runtime_error("Error opening output file for XOR: " + outputFile);
    }

    std::vector<char> buffer(FILE_BUFFER_SIZE);
    size_t keyIndex = 0;
    int totalBytesProcessed = 0;

    while (in.read(buffer.data(), FILE_BUFFER_SIZE)) {
        int bytesRead = in.gcount();
        for (int i = 0; i < bytesRead; ++i) {
            buffer[i] ^= key[keyIndex];
            keyIndex = (keyIndex + 1) % key.size();
        }
        out.write(buffer.data(), bytesRead);
        if (!out) {
            throw std::runtime_error("Error writing to output file during XOR processing: " + outputFile);
        }
        totalBytesProcessed += bytesRead;
        std::cout << "Processed " << totalBytesProcessed << " bytes...\r" << std::flush;
    }

    int bytesRead = in.gcount();
    for (int i = 0; i < bytesRead; ++i) {
        buffer[i] ^= key[keyIndex];
        keyIndex = (keyIndex + 1) % key.size();
    }
    out.write(buffer.data(), bytesRead);
    if (!out) {
        throw std::runtime_error("Error writing final bytes to output file during XOR processing: " + outputFile);
    }
    std::cout << "File processing complete!                         " << std::endl;

    in.close();
    out.close();
}

int main() {
    std::cout << "OpenSSL version: " << OPENSSL_VERSION_TEXT << std::endl;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    try {
        int actionChoice;
        std::cout << "Select action:\n";
        std::cout << "1. Encrypt\n";
        std::cout << "2. Decrypt\n";
        std::cout << "3. Test Encryption/Decryption\n";
        std::cout << "Enter choice (1/2/3): ";
        std::cin >> actionChoice;
        std::cin.ignore();

        if (actionChoice == 1) {
            int inputChoice;
            std::string inputSource;
            std::string key;
            int encryptionChoice;

            std::cout << "Select input type:\n";
            std::cout << "1. File\n";
            std::cout << "2. Text Message\n";
            std::cout << "Enter choice (1/2): ";
            std::cin >> inputChoice;
            std::cin.ignore();

            if (inputChoice == 1) {
                std::cout << "Enter the path to the input file: ";
                std::getline(std::cin, inputSource);
                std::ifstream checkFile(inputSource, std::ios::ate | std::ios::binary);
                if (!checkFile) {
                    throw std::runtime_error("Error: Input file does not exist or cannot be opened: " + inputSource);
                }
                if (checkFile.tellg() == 0) {
                    throw std::runtime_error("Error: Input file is empty: " + inputSource);
                }
                checkFile.close();
            } else if (inputChoice == 2) {
                std::cout << "Enter the text message: ";
                std::getline(std::cin, inputSource);
                if (inputSource.empty()) {
                    throw std::runtime_error("Error: Input text message is empty!");
                }
            } else {
                throw std::runtime_error("Invalid input choice!");
            }

            std::cout << "Select encryption level:\n";
            std::cout << "1. Basic XOR encryption\n";
            std::cout << "2. AES-128 encryption (CBC mode)\n";
            std::cout << "3. AES-256 encryption (CBC mode)\n";
            std::cout << "Enter choice (1/2/3): ";
            std::cin >> encryptionChoice;
            std::cin.ignore();

            if (encryptionChoice == 2 || encryptionChoice == 3) {
                int keyBits = (encryptionChoice == 2) ? 128 : 256;
                std::cout << "Enter the key for AES-" << keyBits << " encryption (" << (keyBits == 128 ? 16 : 32) << " characters): ";
                std::getline(std::cin, key);
                if (!validateKeyLength(key, keyBits)) {
                    return 1;
                }
            } else if (encryptionChoice == 1) {
                std::cout << "Enter the key for XOR encryption: ";
                std::getline(std::cin, key);
                if (key.empty()) {
                    throw std::runtime_error("XOR key cannot be empty!");
                }
            } else {
                throw std::runtime_error("Invalid encryption choice!");
            }

            std::cout << "\n--- Encryption ---\n";
            
            switch (encryptionChoice) {
                case 1: {
                    std::cout << "Using Basic XOR encryption...\n";
                    if (inputChoice == 1) {
                        std::string encryptedFile = inputSource + ".xor";
                        XOR_File(inputSource, encryptedFile, key);
                        std::cout << "Encrypted data saved to: " << encryptedFile << std::endl;
                    } else {
                        std::string encryptedText = XOR_Text(inputSource, key);
                        std::cout << "Encrypted Text: " << encryptedText << std::endl;
                        std::cout << "Note: Encrypted text not saved to file. Copy and paste for decryption." << std::endl;
                    }
                    break;
                }
                case 2:
                case 3: {
                    int keyBits = (encryptionChoice == 2) ? 128 : 256;
                    std::cout << "Using AES-" << keyBits << " encryption (EVP)...\n";
                    std::string outputFileExtension = ".aes" + std::to_string(keyBits);

                    if (inputChoice == 1) {
                        std::string encryptedFile = inputSource + outputFileExtension;
                        AES_File_Process(inputSource, encryptedFile, key, keyBits, true);
                        std::cout << "Encrypted file saved to: " << encryptedFile << std::endl;
                    } else {
                        std::vector<unsigned char> plaintext_buffer(inputSource.begin(), inputSource.end());
                        std::vector<unsigned char> encryptedBuffer = AES_Encrypt_EVP_Buffer(plaintext_buffer, key, keyBits);
                        
                        std::string encryptedFile = "text_encrypted" + outputFileExtension;
                        writeBufferToFile(encryptedFile, encryptedBuffer);
                        std::cout << "Encrypted text saved as binary to: " << encryptedFile << std::endl;
                    }
                    break;
                }
                default:
                    break;
            }

        } else if (actionChoice == 2) {
            std::cout << "\n--- Decryption ---\n";
            std::string encryptedSource;
            std::string key;
            int encryptionChoice;

            std::cout << "Enter the path to the encrypted file: ";
            std::getline(std::cin, encryptedSource);
            
            std::cout << "Enter the key used for encryption: ";
            std::getline(std::cin, key);
            std::cout << "Decryption key: '" << key << "' (length: " << key.length() << ")" << std::endl;

            std::cout << "Select encryption type used:\n";
            std::cout << "1. Basic XOR encryption\n";
            std::cout << "2. AES-128 encryption\n";
            std::cout << "3. AES-256 encryption\n";
            std::cout << "Enter choice (1/2/3): ";
            std::cin >> encryptionChoice;
            std::cin.ignore();

            if (encryptionChoice == 2 || encryptionChoice == 3) {
                int keyBits = (encryptionChoice == 2) ? 128 : 256;
                if (!validateKeyLength(key, keyBits)) {
                    return 1;
                }

                std::string outputDecryptedFile = encryptedSource + ".decrypted.txt";
                AES_File_Process(encryptedSource, outputDecryptedFile, key, keyBits, false);
                std::cout << "Decrypted file saved as: " << outputDecryptedFile << std::endl;
            } else if (encryptionChoice == 1) {
                if (key.empty()) {
                    throw std::runtime_error("XOR key cannot be empty!");
                }
                std::string outputDecryptedFile = encryptedSource + ".decrypted.txt";
                XOR_File(encryptedSource, outputDecryptedFile, key);
                std::cout << "Decrypted file saved as: " << outputDecryptedFile << std::endl;
            } else {
                throw std::runtime_error("Invalid encryption type choice!");
            }

        } else if (actionChoice == 3) {
            std::cout << "\n--- Testing Encryption/Decryption ---\n";

            std::cout << "Test 1: Text-based AES-128 encryption/decryption...\n";
            std::string testDataStr = "My name is unkneo i am a engineer. This is a test message for encryption.";
            std::string testKeyStr = "1234567890abcdef";
            std::cout << "Original data: " << testDataStr << std::endl;
            std::vector<unsigned char> testDataBuffer(testDataStr.begin(), testDataStr.end());

            std::vector<unsigned char> encryptedBuffer = AES_Encrypt_EVP_Buffer(testDataBuffer, testKeyStr, 128);
            std::cout << "Encrypted size: " << encryptedBuffer.size() << " bytes" << std::endl;

            std::vector<unsigned char> decryptedBuffer = AES_Decrypt_EVP_Buffer(encryptedBuffer, testKeyStr, 128);
            std::string decryptedStr(decryptedBuffer.begin(), decryptedBuffer.end());
            std::cout << "Decrypted data: " << decryptedStr << std::endl;

            if (testDataStr == decryptedStr) {
                std::cout << "Test 1 passed: Decrypted data matches original!" << std::endl;
            } else {
                std::cout << "Test 1 failed: Decrypted data does not match original!" << std::endl;
            }

            std::cout << "\nTest 2: File-based AES-256 encryption/decryption...\n";
            std::string testFile = "test_input_file.txt";
            std::string encryptedTestFile = "test_encrypted_file.aes256";
            std::string decryptedTestFile = "test_decrypted_file.txt";
            std::string fileContent = "This is a longer test message for file encryption demonstration. It needs to be long enough to span multiple blocks for a good test. Let's add some more text to make it substantial.";
            
            std::ofstream tempOut(testFile, std::ios::binary);
            tempOut << fileContent;
            tempOut.close();
            std::cout << "Created test file: " << testFile << " with size: " << fileContent.size() << " bytes" << std::endl;

            std::string testKey256 = "ThisIsA256BitKeyForTestingAES256!";
            
            AES_File_Process(testFile, encryptedTestFile, testKey256, 256, true);
            std::cout << "File encrypted to: " << encryptedTestFile << std::endl;

            AES_File_Process(encryptedTestFile, decryptedTestFile, testKey256, 256, false);
            std::cout << "File decrypted to: " << decryptedTestFile << std::endl;

            std::vector<unsigned char> originalFileBuffer = readFileToBuffer(testFile);
            std::vector<unsigned char> decryptedFileBuffer = readFileToBuffer(decryptedTestFile);

            if (originalFileBuffer == decryptedFileBuffer) {
                std::cout << "Test 2 passed: Decrypted file content matches original!" << std::endl;
            } else {
                std::cout << "Test 2 failed: Decrypted file content does not match original!" << std::endl;
            }

            std::remove(testFile.c_str());
            std::remove(encryptedTestFile.c_str());
            std::remove(decryptedTestFile.c_str());

        } else {
            throw std::runtime_error("Invalid action choice!");
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Application Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred!" << std::endl;
        return 1;
    }

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
