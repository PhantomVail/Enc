#ifndef ENC_H
#define ENC_H

#include <string>
#include <vector>

namespace CPPENC {
    class Encryption {
    public:
        static std::string caesarEncrypt(const std::string& plaintext, int shift);
        static std::string caesarDecrypt(const std::string& ciphertext, int shift);

        static std::string xorEncrypt(const std::string& plaintext, const std::string& key);
        static std::string xorDecrypt(const std::string& ciphertext, const std::string& key);

        static std::string aesEncrypt(const std::string& plaintext, const std::string& key);
        static std::string aesDecrypt(const std::string& ciphertext, const std::string& key);

        static std::string toBinary(const std::string& input);
        static std::string fromBinary(const std::string& binary);

        static std::string customEncoder(const std::string& input, int key);
        static std::string customDecoder(const std::string& encodedInput, int key);

        static std::string generateKey(size_t length);
        static std::string sanitizeInput(const std::string& input);
    };

    class WebEncryption {
    public:
        static std::string encryptHTML(const std::string& html);
        static std::string decryptHTML(const std::string& encryptedHtml);

        static std::string encryptCSS(const std::string& css);
        static std::string decryptCSS(const std::string& encryptedCss);

        static std::string encryptJS(const std::string& js);
        static std::string decryptJS(const std::string& encryptedJs);
    };

    std::string obfuscateCode(const std::string& input);

    namespace Debug {
        void debugLog();
        void benchmarkEncryption(const std::string& algorithm, const std::string& input, int iterations);
        void logDebugMessage(const std::string& message);
    }
}

#endif
