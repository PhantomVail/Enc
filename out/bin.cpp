#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <random>
#include <string>
#include <vector>

namespace BinaryMadness {
    std::string generateRandomString(size_t length) {
        const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::default_random_engine engine(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

        std::string randomStr;
        for (size_t i = 0; i < length; ++i) {
            randomStr += charset[dist(engine)];
        }
        return randomStr;
    }

    std::string customHash(const std::string& data) {
        unsigned long hash = 5381;
        for (char ch : data) {
            hash = ((hash << 5) + hash) + ch;
        }
        std::ostringstream hexStream;
        hexStream << std::hex << hash;
        return hexStream.str();
    }

    void writeBinaryFile(const std::string& fileName) {
        std::ofstream binaryFile(fileName, std::ios::binary);
        if (!binaryFile) {
            std::cerr << "l, couldn't open the file for writing." << std::endl;
            return;
        }

        std::string randomData = generateRandomString(16);
        std::string encodedMessage = customHash("Welcome to the binary realm!");

        std::cout << "Random Data: " << randomData << std::endl;
        std::cout << "Msg: " << encodedMessage << std::endl;

        binaryFile.write(randomData.c_str(), randomData.size());
        binaryFile.write("\n", 1);
        binaryFile.write(encodedMessage.c_str(), encodedMessage.size());

        binaryFile.close();
        std::cout << "bin written successfully: " << fileName << std::endl;
    }
}

int main() {
    std::string fileName = "binary_output.dat";
    BinaryMadness::writeBinaryFile(fileName);
    std::cout << "Wag" << std::endl;
    return 0;
}
