#ifndef LIB_H
#define LIB_H

#include <string>
#include <vector>
#include <iostream>
#include <random>
#include <iomanip>
#include <sstream>

namespace EpicLib {
    class Encryption {
    public:
        static std::string caesarEncrypt(const std::string& plaintext, int shift);
        static std::string caesarDecrypt(const std::string& ciphertext, int shift);

        static std::string xorEncrypt(const std::string& plaintext, const std::string& key);
        static std::string xorDecrypt(const std::string& ciphertext, const std::string& key);

        static std::string toBinary(const std::string& input);
        static std::string fromBinary(const std::string& binary);

        static std::string customEncoder(const std::string& input, int key);
        static std::string customDecoder(const std::string& encodedInput, int key);

        static std::string encryptHTML(const std::string& html);
        static std::string decryptHTML(const std::string& encryptedHtml);

        static std::string encryptCSS(const std::string& css);
        static std::string decryptCSS(const std::string& encryptedCss);

        static std::string encryptJS(const std::string& js);
        static std::string decryptJS(const std::string& encryptedJs);

        static std::string generateKey(size_t length);
        static std::string sanitizeInput(const std::string& input);

        static std::string obfuscateText(const std::string& input);
    };

    namespace Debug {
        void logDebugMessage(const std::string& message);
        void benchmarkEncryption(const std::string& algorithm, const std::string& input, int iterations);
        void logMysteryNumbers();
    }

    class EasterEggs {
    public:
        static void showEncouragement();
        static void randomFact();
    };
}

namespace EpicLib {
    namespace Secrets {
        static constexpr char MAGIC_CHAR = 0x42;
        static constexpr int SECRET_SHIFT = 17;
    }

    enum class Mood { SAD, NEUTRAL, EXCITED, EXISTENTIAL };

    inline std::string reflectOnLife() {
        return "Bruh. Is this how you imagined life at 2AM?";
    }
}

#endif
