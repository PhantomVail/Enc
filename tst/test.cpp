#include <iostream>
#include "enc.h"

int main()
{
    using namespace CPPENC;

    std::string html = "<h1>Hello, World!</h1>";
    std::cout << "Encrypted HTML: " << WebEncryption::encryptHTML(html) << std::endl;
    std::cout << "Decrypted HTML: " << WebEncryption::decryptHTML(WebEncryption::encryptHTML(html)) << std::endl;

    std::string plaintext = "BR, Encryption!";
    std::string key = Encryption::generateKey(16);
    std::cout << "Original Message: " << plaintext << std::endl;
    std::cout << "Generated Key: " << key << std::endl;

    auto xorEncrypted = Encryption::xorEncrypt(plaintext, key);
    std::cout << "XOR Encrypted: " << xorEncrypted << std::endl;

    auto xorDecrypted = Encryption::xorDecrypt(xorEncrypted, key);
    std::cout << "XOR Decrypted: " << xorDecrypted << std::endl;

    std::string css = "body { background: #000; color: #fff; }";
    auto cssEncrypted = WebEncryption::encryptCSS(css);
    std::cout << "Encrypted CSS: " << cssEncrypted << std::endl;
    std::cout << "Decrypted CSS: " << WebEncryption::decryptCSS(cssEncrypted) << std::endl;

    std::string js = "console.log('XYN, World!');";
    auto jsEncrypted = WebEncryption::encryptJS(js);
    std::cout << "Encrypted JS: " << jsEncrypted << std::endl;
    std::cout << "Decrypted JS: " << WebEncryption::decryptJS(jsEncrypted) << std::endl;

    std::string binaryInput = "Binary Test";
    auto binaryEncoded = Encryption::toBinary(binaryInput);
    std::cout << "Binary Encoded: " << binaryEncoded << std::endl;
    std::cout << "Binary Decoded: " << Encryption::fromBinary(binaryEncoded) << std::endl;

    int customKey = 42;
    auto customEncoded = Encryption::customEncoder(plaintext, customKey);
    std::cout << "Custom Encoded: " << customEncoded << std::endl;
    std::cout << "Custom Decoded: " << Encryption::customDecoder(customEncoded, customKey) << std::endl;

    std::string html = "<h1>Wagwan, IDIOTS!</h1>";
    auto htmlEncrypted = WebEncryption::encryptHTML(html);
    std::cout << "Encrypted HTML: " << htmlEncrypted << std::endl;
    std::cout << "Decrypted HTML: " << WebEncryption::decryptHTML(htmlEncrypted) << std::endl;

    std::string caesarPlaintext = "Caesar Cipher Test";
    int caesarShift = 5;
    auto caesarEncrypted = Encryption::caesarEncrypt(caesarPlaintext, caesarShift);
    std::cout << "Caesar Encrypted: " << caesarEncrypted << std::endl;
    std::cout << "Caesar Decrypted: " << Encryption::caesarDecrypt(caesarEncrypted, caesarShift) << std::endl;

    std::string mysteriousCode = "What lies beneath?";
    auto obfuscated = obfuscateCode(mysteriousCode);
    std::cout << "Obfuscated Code: " << obfuscated << std::endl;

    std::cout << "Debugging Benchmark for HTML Encryption:" << std::endl;
    Debug::benchmarkEncryption("HTML", html, 10000);

    Debug::logDebugMessage("This is a debug log message.");
    Debug::debugLog();

    return 0;
}
