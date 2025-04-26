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
#include <iterator>

using namespace std;

#define AES_BLOCK_SIZE 16

// Print OpenSSL errors and exit
void handleErrors(const string& msg) {
    cerr << msg << ": ";
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Print bytes as hex for debugging
void printHex(const string& label, const unsigned char* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    }
    cout << dec << endl;
}

// Validate key length for AES
bool validateKeyLength(const string& key, int keyBits) {
    size_t expectedLength = (keyBits == 128) ? 16 : 32;
    if (key.length() != expectedLength) {
        cerr << "Invalid key length! AES-" << keyBits << " requires a " << expectedLength << "-byte key. Provided: " << key.length() << " bytes." << endl;
        return false;
    }
    return true;
}

// AES encryption using EVP API
vector<unsigned char> AES_Encrypt_EVP_Buffer(const string& data, const string& key, int keyBits) {
    cout << "Encrypting with key (length: " << key.length() << "): ";
    printHex("Key bytes", (const unsigned char*)key.c_str(), key.length());

    const EVP_CIPHER* cipher = (keyBits == 128) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    if (!cipher) {
        cerr << "Unsupported key size: " << keyBits << endl;
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error generating IV");
    }
    printHex("Generated IV", iv, AES_BLOCK_SIZE);

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error initializing encryption");
    }

    vector<unsigned char> ciphertext;
    ciphertext.reserve(data.size() + 2 * AES_BLOCK_SIZE); // Reserve space for IV + ciphertext + padding
    ciphertext.insert(ciphertext.end(), iv, iv + AES_BLOCK_SIZE);

    vector<unsigned char> inBuffer(data.begin(), data.end());
    vector<unsigned char> outBuffer(inBuffer.size() + AES_BLOCK_SIZE);
    int outLen = 0;

    if (EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), inBuffer.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error during encryption update");
    }
    ciphertext.insert(ciphertext.end(), outBuffer.begin(), outBuffer.begin() + outLen);

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, outBuffer.data(), &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error during final encryption");
    }
    ciphertext.insert(ciphertext.end(), outBuffer.begin(), outBuffer.begin() + finalLen);

    // Log ciphertext
    cout << "Ciphertext size: " << ciphertext.size() << " bytes" << endl;
    printHex("Ciphertext", ciphertext.data(), ciphertext.size());

    // Check for identical blocks (heuristic)
    if (ciphertext.size() >= 2 * AES_BLOCK_SIZE) {
        for (size_t i = AES_BLOCK_SIZE; i < ciphertext.size() - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
            if (equal(ciphertext.begin() + i, ciphertext.begin() + i + AES_BLOCK_SIZE,
                      ciphertext.begin() + i + AES_BLOCK_SIZE)) {
                cerr << "Warning: Identical ciphertext blocks detected at offset " << i << ". This is unusual and may indicate an encryption error." << endl;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES decryption using EVP API
string AES_Decrypt_EVP_Buffer(const vector<unsigned char>& ciphertext, const string& key, int keyBits) {
    cout << "Decrypting with key (length: " << key.length() << "): ";
    printHex("Key bytes", (const unsigned char*)key.c_str(), key.length());
    cout << "Ciphertext size: " << ciphertext.size() << " bytes" << endl;
    printHex("Ciphertext", ciphertext.data(), ciphertext.size());

    if (ciphertext.size() < AES_BLOCK_SIZE) {
        cerr << "Ciphertext too short to contain IV! Size: " << ciphertext.size() << " bytes." << endl;
        return "";
    }
    if ((ciphertext.size() - AES_BLOCK_SIZE) % AES_BLOCK_SIZE != 0) {
        cerr << "Invalid ciphertext length: " << ciphertext.size() << " bytes. Must include IV (16 bytes) and be a multiple of block size (16 bytes)." << endl;
        return "";
    }

    const EVP_CIPHER* cipher = (keyBits == 128) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();
    if (!cipher) {
        cerr << "Unsupported key size: " << keyBits << endl;
        return "";
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Error creating cipher context");

    unsigned char iv[AES_BLOCK_SIZE];
    copy(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE, iv);
    printHex("Extracted IV", iv, AES_BLOCK_SIZE);

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, (const unsigned char*)key.c_str(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error initializing decryption");
    }

    vector<unsigned char> inBuffer(ciphertext.begin() + AES_BLOCK_SIZE, ciphertext.end());
    vector<unsigned char> outBuffer(inBuffer.size());
    int outLen = 0;

    if (EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), inBuffer.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Error during decryption update");
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, outBuffer.data() + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        cerr << "Error during final decryption (possible causes: wrong key, corrupted ciphertext, or invalid padding): ";
        ERR_print_errors_fp(stderr);
        return "";
    }
    outLen += finalLen;

    string plaintext(outBuffer.begin(), outBuffer.begin() + outLen);
    cout << "Decrypted plaintext size: " << plaintext.size() << " bytes" << endl;
    printHex("Plaintext", (const unsigned char*)plaintext.data(), plaintext.size());
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// XOR encryption/decryption for text
string XOR_Text(const string& text, const string& key) {
    string result = text;
    size_t keyIndex = 0;
    for (char& c : result) {
        c ^= key[keyIndex];
        keyIndex = (keyIndex + 1) % key.size();
    }
    return result;
}

// XOR encryption/decryption for files
void XOR_File(const string& inputFile, const string& outputFile, const string& key) {
    ifstream in(inputFile, ios::binary);
    if (!in) {
        cerr << "Error opening input file: " << inputFile << endl;
        return;
    }
    ofstream out(outputFile, ios::binary);
    if (!out) {
        cerr << "Error opening output file: " << outputFile << endl;
        in.close();
        return;
    }

    char buffer;
    size_t keyIndex = 0;

    while (in.read(&buffer, 1)) {
        buffer ^= key[keyIndex];
        out.write(&buffer, 1);
        keyIndex = (keyIndex + 1) % key.size();
    }

    if (!in.eof() && in.fail()) {
        cerr << "Error reading input file!" << endl;
    }
    in.close();
    out.close();
}

int main() {
    // Print OpenSSL version for debugging
    cout << "OpenSSL version: " << OPENSSL_VERSION_TEXT << endl;

    int actionChoice;
    cout << "Select action:\n";
    cout << "1. Encrypt\n";
    cout << "2. Decrypt\n";
    cout << "3. Test Encryption/Decryption\n";
    cout << "Enter choice (1/2/3): ";
    cin >> actionChoice;
    cin.ignore();

    if (actionChoice == 1) {
        // --- Encryption Part ---
        int inputChoice;
        string inputData;
        string key;
        int encryptionChoice;

        cout << "Select input type:\n";
        cout << "1. File\n";
        cout << "2. Text Message\n";
        cout << "Enter choice (1/2): ";
        cin >> inputChoice;
        cin.ignore();

        if (inputChoice == 1) {
            cout << "Enter the path to the input file: ";
            getline(cin, inputData);
            ifstream inputFile(inputData, ios::binary | ios::ate);
            if (!inputFile) {
                cerr << "Error opening input file: " << inputData << endl;
                return 1;
            }
            streamsize fileSize = inputFile.tellg();
            if (fileSize == 0) {
                cerr << "Input file is empty!" << endl;
                inputFile.close();
                return 1;
            }
            cout << "Input file size: " << fileSize << " bytes" << endl;
            inputFile.seekg(0, ios::beg);
            vector<char> buffer(fileSize);
            inputFile.read(buffer.data(), fileSize);
            if (!inputFile || inputFile.gcount() != fileSize) {
                cerr << "Error reading input file!" << endl;
                inputFile.close();
                return 1;
            }
            inputData = string(buffer.begin(), buffer.end());
            inputFile.close();
        } else if (inputChoice == 2) {
            cout << "Enter the text message: ";
            getline(cin, inputData);
            if (inputData.empty()) {
                cerr << "Input text is empty!" << endl;
                return 1;
            }
        } else {
            cerr << "Invalid input choice!" << endl;
            return 1;
        }

        cout << "Select encryption level:\n";
        cout << "1. Basic XOR encryption\n";
        cout << "2. AES-128 encryption\n";
        cout << "3. AES-256 encryption\n";
        cout << "Enter choice (1/2/3): ";
        cin >> encryptionChoice;
        cin.ignore();

        if (encryptionChoice == 2 || encryptionChoice == 3) {
            int keyBits = (encryptionChoice == 2) ? 128 : 256;
            cout << "Enter the key for encryption (" << (keyBits == 128 ? 16 : 32) << " characters for AES-" << keyBits << "): ";
            getline(cin, key);
            if (!validateKeyLength(key, keyBits)) {
                return 1;
            }
        } else if (encryptionChoice == 1) {
            cout << "Enter the key for XOR encryption: ";
            getline(cin, key);
            if (key.empty()) {
                cerr << "XOR key cannot be empty!" << endl;
                return 1;
            }
        } else {
            cerr << "Invalid encryption choice!" << endl;
            return 1;
        }

        cout << "\n--- Encryption ---\n";
        string encryptedText;
        vector<unsigned char> encryptedBuffer;

        switch (encryptionChoice) {
            case 1: {
                cout << "Using Basic XOR encryption...\n";
                if (inputChoice == 1) {
                    string encryptedFile = "encrypted_output.xor";
                    XOR_File(inputData, encryptedFile, key);
                    cout << "Encrypted data saved to: " << encryptedFile << endl;
                } else {
                    encryptedText = XOR_Text(inputData, key);
                    cout << "Encrypted Text: " << encryptedText << endl;
                }
                break;
            }
            case 2: {
                cout << "Using AES-128 encryption (EVP)...\n";
                encryptedBuffer = AES_Encrypt_EVP_Buffer(inputData, key, 128);
                if (encryptedBuffer.empty()) {
                    cerr << "Encryption failed!" << endl;
                    return 1;
                }
                string encryptedFile = "encrypted_output.aes128";
                ofstream outfile(encryptedFile, ios::binary);
                if (!outfile) {
                    cerr << "Error opening output file: " << encryptedFile << endl;
                    return 1;
                }
                outfile.write((char*)encryptedBuffer.data(), encryptedBuffer.size());
                if (!outfile) {
                    cerr << "Error writing to output file: " << encryptedFile << endl;
                    outfile.close();
                    return 1;
                }
                outfile.close();
                cout << "Encrypted data saved to: " << encryptedFile << endl;
                break;
            }
            case 3: {
                cout << "Using AES-256 encryption (EVP)...\n";
                encryptedBuffer = AES_Encrypt_EVP_Buffer(inputData, key, 256);
                if (encryptedBuffer.empty()) {
                    cerr << "Encryption failed!" << endl;
                    return 1;
                }
                string encryptedFile = "encrypted_output.aes256";
                ofstream outfile(encryptedFile, ios::binary);
                if (!outfile) {
                    cerr << "Error opening output file: " << encryptedFile << endl;
                    return 1;
                }
                outfile.write((char*)encryptedBuffer.data(), encryptedBuffer.size());
                if (!outfile) {
                    cerr << "Error writing to output file: " << encryptedFile << endl;
                    outfile.close();
                    return 1;
                }
                outfile.close();
                cout << "Encrypted data saved to: " << encryptedFile << endl;
                break;
            }
            default:
                cerr << "Invalid encryption choice!" << endl;
                return 1;
        }

    } else if (actionChoice == 2) {
        // --- Decryption Part ---
        cout << "\n--- Decryption ---\n";
        string decryptFile;
        string key;
        int encryptionChoice;

        cout << "Enter the path to the encrypted file: ";
        getline(cin, decryptFile);

        cout << "Enter the key used for encryption: ";
        getline(cin, key);
        cout << "Decryption key: '" << key << "' (length: " << key.length() << ")" << endl;

        cout << "Select encryption type used:\n";
        cout << "1. Basic XOR encryption\n";
        cout << "2. AES-128 encryption\n";
        cout << "3. AES-256 encryption\n";
        cout << "Enter choice (1/2/3): ";
        cin >> encryptionChoice;
        cin.ignore();

        if (encryptionChoice == 2 || encryptionChoice == 3) {
            int keyBits = (encryptionChoice == 2) ? 128 : 256;
            if (!validateKeyLength(key, keyBits)) {
                return 1;
            }

            ifstream inFile(decryptFile, ios::binary | ios::ate);
            if (!inFile) {
                cerr << "Error opening encrypted file: " << decryptFile << endl;
                return 1;
            }
            streamsize size = inFile.tellg();
            if (size < AES_BLOCK_SIZE) {
                cerr << "Encrypted file is too small to contain IV and ciphertext! Size: " << size << " bytes." << endl;
                inFile.close();
                return 1;
            }
            inFile.seekg(0, ios::beg);
            vector<unsigned char> encryptedBuffer(size);
            inFile.read((char*)encryptedBuffer.data(), size);
            if (!inFile || inFile.gcount() != size) {
                cerr << "Error reading encrypted file!" << endl;
                inFile.close();
                return 1;
            }
            inFile.close();

            string decryptedText = AES_Decrypt_EVP_Buffer(encryptedBuffer, key, keyBits);
            if (!decryptedText.empty()) {
                string outputDecryptedFile = "decrypted_output.aes" + to_string(keyBits) + ".txt";
                ofstream outFile(outputDecryptedFile, ios::binary);
                if (!outFile) {
                    cerr << "Error opening output file: " << outputDecryptedFile << endl;
                    return 1;
                }
                outFile << decryptedText;
                if (!outFile) {
                    cerr << "Error writing to output file: " << outputDecryptedFile << endl;
                    outFile.close();
                    return 1;
                }
                outFile.close();
                cout << "Decrypted file saved as: " << outputDecryptedFile << endl;
            } else {
                cerr << "Decryption failed! Possible reasons: wrong key, corrupted ciphertext, or invalid padding." << endl;
                return 1;
            }
        } else if (encryptionChoice == 1) {
            if (key.empty()) {
                cerr << "XOR key cannot be empty!" << endl;
                return 1;
            }
            string outputDecryptedFile = "decrypted_output.xor";
            XOR_File(decryptFile, outputDecryptedFile, key);
            cout << "Decrypted file saved as: " << outputDecryptedFile << endl;
        } else {
            cerr << "Invalid encryption type!" << endl;
            return 1;
        }

    } else if (actionChoice == 3) {
        // --- Test Mode ---
        cout << "\n--- Testing Encryption/Decryption ---\n";
        cout << "Test 1: Text-based AES-128 encryption/decryption...\n";
        string testData = "My name is unkneo i am a engineer";
        string testKey = "1234567890qwerty";
        cout << "Original data: " << testData << endl;

        auto encrypted = AES_Encrypt_EVP_Buffer(testData, testKey, 128);
        if (encrypted.empty()) {
            cerr << "Encryption test failed!" << endl;
            return 1;
        }
        cout << "Encrypted size: " << encrypted.size() << " bytes" << endl;

        string decrypted = AES_Decrypt_EVP_Buffer(encrypted, testKey, 128);
        if (decrypted.empty()) {
            cerr << "Decryption test failed!" << endl;
            return 1;
        }
        cout << "Decrypted data: " << decrypted << endl;

        if (testData == decrypted) {
            cout << "Test 1 passed: Decrypted data matches original!" << endl;
        } else {
            cout << "Test 1 failed: Decrypted data does not match original!" << endl;
        }

        // Test 2: File-based encryption/decryption
        cout << "\nTest 2: File-based AES-128 encryption/decryption...\n";
        string testFile = "test_input.txt";
        string testFileData = "My name is unkneo i am a engineer";
        {
            ofstream testOut(testFile, ios::binary);
            testOut << testFileData;
            testOut.close();
        }

        cout << "Creating test file: " << testFile << " with size: " << testFileData.size() << " bytes" << endl;
        ifstream testIn(testFile, ios::binary | ios::ate);
        streamsize fileSize = testIn.tellg();
        testIn.seekg(0, ios::beg);
        vector<char> buffer(fileSize);
        testIn.read(buffer.data(), fileSize);
        testIn.close();
        string fileInputData(buffer.begin(), buffer.end());

        auto fileEncrypted = AES_Encrypt_EVP_Buffer(fileInputData, testKey, 128);
        if (fileEncrypted.empty()) {
            cerr << "File encryption test failed!" << endl;
            return 1;
        }

        string fileDecrypted = AES_Decrypt_EVP_Buffer(fileEncrypted, testKey, 128);
        if (fileDecrypted.empty()) {
            cerr << "File decryption test failed!" << endl;
            return 1;
        }

        if (fileInputData == fileDecrypted) {
            cout << "Test 2 passed: Decrypted file data matches original!" << endl;
        } else {
            cout << "Test 2 failed: Decrypted file data does not match original!" << endl;
        }
    } else {
        cerr << "Invalid action choice!" << endl;
        return 1;
    }

    return 0;
}
