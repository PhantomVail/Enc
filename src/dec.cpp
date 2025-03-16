#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace BinaryDecoder {
    void decodeBinaryFile(const std::string& fileName) {
        std::ifstream binaryFile(fileName, std::ios::binary);
        if (!binaryFile) {
            std::cerr << "B, couldn't open the binary file for decoding." << std::endl;
            return;
        }

        std::ostringstream rawData;
        rawData << binaryFile.rdbuf();
        std::string binaryContent = rawData.str();

        std::cout << "Binary File Content (hex): ";
        for (unsigned char ch : binaryContent) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ch << " ";
        }
        std::cout << std::endl;

        std::cout << "decoding binary madness... [not implemented]" << std::endl;

        binaryFile.close();
    }
}

int main() {
    std::string binaryPath = "bin.txt";
    std::cout << "starting the binary decoding" << std::endl;
    BinaryDecoder::decodeBinaryFile(binaryPath);
    std::cout << "mission complete." << std::endl;
    return 0;
}
