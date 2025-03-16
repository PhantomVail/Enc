#include "enc.h"
#include <bitset>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>
#include <cctype>

namespace CPPENC {

    std::string Encryption::generateKey(size_t length) {
        const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        std::default_random_engine engine(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, charset.length() - 1);

        std::string key;
        for (size_t i = 0; i < length; ++i) {
            key += charset[dist(engine)];
        }
        return key;
    }

    std::string Encryption::sanitizeInput(const std::string& input) {
        std::string sanitized;
        for (char ch : input) {
            if (std::isprint(ch)) {
                sanitized += ch;
            }
        }
        return sanitized;
    }

    std::string Encryption::toBinary(const std::string& input) {
        std::string binary;
        for (unsigned char ch : input) {
            binary += std::bitset<8>(ch).to_string() + " ";
        }
        return binary;
    }

    std::string Encryption::fromBinary(const std::string& binary) {
        std::istringstream stream(binary);
        std::string decoded, byteStr;

        while (stream >> byteStr) {
            decoded += static_cast<char>(std::bitset<8>(byteStr).to_ulong());
        }
        return decoded;
    }

    std::string Encryption::caesarEncrypt(const std::string& plaintext, int shift) {
        std::string encrypted;
        for (char ch : plaintext) {
            if (std::isalpha(ch)) {
                char base = std::islower(ch) ? 'a' : 'A';
                encrypted += (ch - base + shift) % 26 + base;
            } else {
                encrypted += ch;
            }
        }
        return encrypted;
    }

    std::string Encryption::caesarDecrypt(const std::string& ciphertext, int shift) {
        return caesarEncrypt(ciphertext, 26 - shift);
    }

    std::string Encryption::xorEncrypt(const std::string& plaintext, const std::string& key) {
        std::string encrypted;
        for (size_t i = 0; i < plaintext.size(); ++i) {
            encrypted += plaintext[i] ^ key[i % key.size()];
        }
        return encrypted;
    }

    std::string Encryption::xorDecrypt(const std::string& ciphertext, const std::string& key) {
        return xorEncrypt(ciphertext, key);
    }

    std::string WebEncryption::encryptHTML(const std::string& html) {
        std::ostringstream encrypted;
        for (char ch : html) {
            encrypted << std::hex << std::setw(2) << std::setfill('0') << int(ch) + 7;
        }
        return encrypted.str();
    }

    std::string WebEncryption::decryptHTML(const std::string& encryptedHtml) {
        std::istringstream stream(encryptedHtml);
        std::string result, hexChar;

        while (stream >> std::setw(2) >> hexChar) {
            result += static_cast<char>(std::stoi(hexChar, nullptr, 16) - 7);
        }
        return result;
    }

    std::string WebEncryption::encryptCSS(const std::string& css) {
        std::string encrypted;
        for (char ch : css) {
            encrypted += static_cast<char>(ch ^ 0x5F);
        }
        return encrypted;
    }

    std::string WebEncryption::decryptCSS(const std::string& encryptedCss) {
        return encryptCSS(encryptedCss);
    }

    std::string WebEncryption::encryptJS(const std::string& js) {
        std::ostringstream encrypted;
        for (char ch : js) {
            encrypted << ch << '_';
        }
        return encrypted.str();
    }

    std::string WebEncryption::decryptJS(const std::string& encryptedJs) {
        std::string decrypted;
        for (size_t i = 0; i < encryptedJs.size(); i += 2) {
            decrypted += encryptedJs[i];
        }
        return decrypted;
    }

    std::string obfuscateCode(const std::string& input) {
        std::ostringstream mystic;
        for (char ch : input) {
            char m = static_cast<char>((ch * 7) ^ 0x33);
            mystic << m;
        }
        return mystic.str();
    }

    namespace Debug {
        void debugLog() {
            std::string arcane = "log initiated.";
            for (char ch : arcane) {
                std::cout << ((ch % 3) + 9) << " ";
            }
            std::cout << std::endl;
        }

        void benchmarkEncryption(const std::string& algorithm, const std::string& input, int iterations) {
            auto start = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < iterations; ++i) {
                if (algorithm == "Binary") {
                    Encryption::toBinary(input);
                } else if (algorithm == "HTML") {
                    WebEncryption::encryptHTML(input);
                }
            }
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = end - start;
            std::cout << "Benchmark (" << algorithm << "): " << elapsed.count() << " seconds\n";
        }

        void logDebugMessage(const std::string& message) {
            std::cout << "[DEBUG]: " << message << std::endl;
        }
    }
}
