#include "../include/lib.h"
#include "../include/util.h"
#include "../include/enc.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <functional>
#include <numeric>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <queue>
#include <stack>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <atomic>
#include <memory>
#include <cstring>
#include <ctime>
#include <cassert>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <limits>
#include <array>
#include <tuple>
#include <regex>
#include <cctype>

namespace CPPENC
{
    namespace AdvancedEncryption
    {

        constexpr size_t AES_BLOCK_SIZE = 16;
        constexpr size_t DES_BLOCK_SIZE = 8;
        constexpr size_t BLOWFISH_BLOCK_SIZE = 8;
        constexpr size_t RSA_KEY_SIZE_MIN = 512;
        constexpr size_t RSA_KEY_SIZE_MAX = 4096;
        constexpr size_t DIFFIE_HELLMAN_MIN_PRIME_BITS = 1024;
        constexpr size_t SHA256_DIGEST_SIZE = 32;
        constexpr size_t SHA512_DIGEST_SIZE = 64;
        constexpr size_t MD5_DIGEST_SIZE = 16;

        const std::array<uint8_t, 256> AES_SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

        const std::array<uint8_t, 256> AES_INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

        const std::array<std::array<uint8_t, 64>, 8> DES_SBOX = {{
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
        }};

        template <typename T>
        std::vector<T> generateRandomVector(size_t size)
        {
            std::vector<T> result(size);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(0, 255);

            for (size_t i = 0; i < size; ++i)
            {
                result[i] = static_cast<T>(distrib(gen));
            }

            return result;
        }

        std::string bytesToHexString(const std::vector<uint8_t> &bytes)
        {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (const auto &byte : bytes)
            {
                ss << std::setw(2) << static_cast<int>(byte);
            }
            return ss.str();
        }

        std::vector<uint8_t> hexStringToBytes(const std::string &hex)
        {
            std::vector<uint8_t> bytes;
            for (size_t i = 0; i < hex.length(); i += 2)
            {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        }

        std::vector<uint8_t> stringToBytes(const std::string &str)
        {
            std::vector<uint8_t> bytes(str.begin(), str.end());
            return bytes;
        }

        std::string bytesToString(const std::vector<uint8_t> &bytes)
        {
            return std::string(bytes.begin(), bytes.end());
        }

        std::vector<uint8_t> pkcs7Padding(const std::vector<uint8_t> &data, size_t blockSize)
        {
            size_t paddingSize = blockSize - (data.size() % blockSize);
            std::vector<uint8_t> padded = data;
            for (size_t i = 0; i < paddingSize; ++i)
            {
                padded.push_back(static_cast<uint8_t>(paddingSize));
            }
            return padded;
        }

        std::vector<uint8_t> removePkcs7Padding(const std::vector<uint8_t> &paddedData)
        {
            if (paddedData.empty())
            {
                return paddedData;
            }

            uint8_t paddingSize = paddedData.back();
            if (paddingSize > paddedData.size())
            {
                throw std::runtime_error("Invalid PKCS#7 padding");
            }

            for (size_t i = paddedData.size() - paddingSize; i < paddedData.size(); ++i)
            {
                if (paddedData[i] != paddingSize)
                {
                    throw std::runtime_error("Invalid PKCS#7 padding");
                }
            }

            return std::vector<uint8_t>(paddedData.begin(), paddedData.end() - paddingSize);
        }

        uint32_t rotateLeft(uint32_t value, unsigned int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        uint32_t rotateRight(uint32_t value, unsigned int count)
        {
            return (value >> count) | (value << (32 - count));
        }

        static const std::string base64Chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string base64Encode(const std::vector<uint8_t> &data)
        {
            std::string encoded;
            encoded.reserve(((data.size() + 2) / 3) * 4);

            for (size_t i = 0; i < data.size(); i += 3)
            {
                uint32_t octet_a = i < data.size() ? data[i] : 0;
                uint32_t octet_b = i + 1 < data.size() ? data[i + 1] : 0;
                uint32_t octet_c = i + 2 < data.size() ? data[i + 2] : 0;

                uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

                encoded.push_back(base64Chars[(triple >> 18) & 0x3F]);
                encoded.push_back(base64Chars[(triple >> 12) & 0x3F]);
                encoded.push_back(i + 1 < data.size() ? base64Chars[(triple >> 6) & 0x3F] : '=');
                encoded.push_back(i + 2 < data.size() ? base64Chars[triple & 0x3F] : '=');
            }

            return encoded;
        }

        std::vector<uint8_t> base64Decode(const std::string &encoded)
        {
            std::vector<uint8_t> decoded;
            decoded.reserve(encoded.size() * 3 / 4);

            auto isBase64 = [](unsigned char c)
            {
                return (isalnum(c) || (c == '+') || (c == '/'));
            };

            auto findCharIndex = [](unsigned char c) -> int
            {
                auto it = std::find(base64Chars.begin(), base64Chars.end(), c);
                if (it != base64Chars.end())
                {
                    return std::distance(base64Chars.begin(), it);
                }
                return -1;
            };

            size_t i = 0;
            while (i < encoded.size() && encoded[i] != '=')
            {
                size_t remaining = std::min(encoded.size() - i, size_t(4));

                if (remaining < 2)
                {
                    throw std::runtime_error("Invalid base64 string");
                }

                int a = findCharIndex(encoded[i]);
                int b = findCharIndex(encoded[i + 1]);
                int c = remaining > 2 ? findCharIndex(encoded[i + 2]) : 0;
                int d = remaining > 3 ? findCharIndex(encoded[i + 3]) : 0;

                if (a == -1 || b == -1 || (remaining > 2 && c == -1) || (remaining > 3 && d == -1))
                {
                    throw std::runtime_error("Invalid base64 character");
                }

                uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;

                decoded.push_back((triple >> 16) & 0xFF);
                if (remaining > 2 && encoded[i + 2] != '=')
                {
                    decoded.push_back((triple >> 8) & 0xFF);
                }
                if (remaining > 3 && encoded[i + 3] != '=')
                {
                    decoded.push_back(triple & 0xFF);
                }

                i += 4;
            }

            return decoded;
        }

        std::vector<uint8_t> sha256(const std::vector<uint8_t> &message)
        {
            const std::array<uint32_t, 64> K = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

            uint32_t h0 = 0x6a09e667;
            uint32_t h1 = 0xbb67ae85;
            uint32_t h2 = 0x3c6ef372;
            uint32_t h3 = 0xa54ff53a;
            uint32_t h4 = 0x510e527f;
            uint32_t h5 = 0x9b05688c;
            uint32_t h6 = 0x1f83d9ab;
            uint32_t h7 = 0x5be0cd19;

            std::vector<uint8_t> padded = message;
            size_t originalLength = message.size() * 8;

            padded.push_back(0x80);

            while ((padded.size() * 8) % 512 != 448)
            {
                padded.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i)
            {
                padded.push_back((originalLength >> (i * 8)) & 0xFF);
            }

            for (size_t chunk = 0; chunk < padded.size(); chunk += 64)
            {
                std::array<uint32_t, 64> w = {};

                for (size_t i = 0; i < 16; ++i)
                {
                    w[i] = (padded[chunk + i * 4] << 24) | (padded[chunk + i * 4 + 1] << 16) |
                           (padded[chunk + i * 4 + 2] << 8) | (padded[chunk + i * 4 + 3]);
                }

                for (size_t i = 16; i < 64; ++i)
                {
                    uint32_t s0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
                    uint32_t s1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                uint32_t a = h0;
                uint32_t b = h1;
                uint32_t c = h2;
                uint32_t d = h3;
                uint32_t e = h4;
                uint32_t f = h5;
                uint32_t g = h6;
                uint32_t h = h7;

                for (size_t i = 0; i < 64; ++i)
                {
                    uint32_t S1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                    uint32_t ch = (e & f) ^ ((~e) & g);
                    uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                    uint32_t S0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                    uint32_t temp2 = S0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }

                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }

            std::vector<uint8_t> hash(32);
            for (int i = 0; i < 4; ++i)
            {
                hash[i] = (h0 >> (24 - i * 8)) & 0xFF;
                hash[i + 4] = (h1 >> (24 - i * 8)) & 0xFF;
                hash[i + 8] = (h2 >> (24 - i * 8)) & 0xFF;
                hash[i + 12] = (h3 >> (24 - i * 8)) & 0xFF;
                hash[i + 16] = (h4 >> (24 - i * 8)) & 0xFF;
                hash[i + 20] = (h5 >> (24 - i * 8)) & 0xFF;
                hash[i + 24] = (h6 >> (24 - i * 8)) & 0xFF;
                hash[i + 28] = (h7 >> (24 - i * 8)) & 0xFF;
            }

            return hash;
        }

        std::vector<uint8_t> md5(const std::vector<uint8_t> &message)
        {
            const std::array<uint32_t, 64> K = {
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

            const std::array<uint32_t, 64> S = {
                7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

            uint32_t a0 = 0x67452301;
            uint32_t b0 = 0xefcdab89;
            uint32_t c0 = 0x98badcfe;
            uint32_t d0 = 0x10325476;

            std::vector<uint8_t> padded = message;
            size_t originalLength = message.size() * 8;

            padded.push_back(0x80);

            while ((padded.size() * 8) % 512 != 448)
            {
                padded.push_back(0x00);
            }

            for (int i = 0; i < 8; ++i)
            {
                padded.push_back((originalLength >> (i * 8)) & 0xFF);
            }

            for (size_t chunk = 0; chunk < padded.size(); chunk += 64)
            {
                std::array<uint32_t, 16> M;
                for (size_t i = 0; i < 16; ++i)
                {
                    M[i] = padded[chunk + i * 4] | (padded[chunk + i * 4 + 1] << 8) |
                           (padded[chunk + i * 4 + 2] << 16) | (padded[chunk + i * 4 + 3] << 24);
                }

                uint32_t A = a0;
                uint32_t B = b0;
                uint32_t C = c0;
                uint32_t D = d0;

                for (uint32_t i = 0; i < 64; ++i)
                {
                    uint32_t F, g;

                    if (i < 16)
                    {
                        F = (B & C) | ((~B) & D);
                        g = i;
                    }
                    else if (i < 32)
                    {
                        F = (D & B) | ((~D) & C);
                        g = (5 * i + 1) % 16;
                    }
                    else if (i < 48)
                    {
                        F = B ^ C ^ D;
                        g = (3 * i + 5) % 16;
                    }
                    else
                    {
                        F = C ^ (B | (~D));
                        g = (7 * i) % 16;
                    }

                    uint32_t temp = D;
                    D = C;
                    C = B;
                    B = B + rotateLeft((A + F + K[i] + M[g]), S[i]);
                    A = temp;
                }

                a0 += A;
                b0 += B;
                c0 += C;
                d0 += D;
            }

            std::vector<uint8_t> hash(16);
            for (int i = 0; i < 4; ++i)
            {
                hash[i] = (a0 >> (i * 8)) & 0xFF;
                hash[i + 4] = (b0 >> (i * 8)) & 0xFF;
                hash[i + 8] = (c0 >> (i * 8)) & 0xFF;
                hash[i + 12] = (d0 >> (i * 8)) & 0xFF;
            }

            return hash;
        }

        std::vector<uint8_t> hmacSha256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &message)
        {
            const size_t blockSize = 64;

            std::vector<uint8_t> normalizedKey = key;
            if (normalizedKey.size() > blockSize)
            {
                normalizedKey = sha256(normalizedKey);
            }

            if (normalizedKey.size() < blockSize)
            {
                normalizedKey.resize(blockSize, 0);
            }

            std::vector<uint8_t> innerPaddedKey(blockSize);
            std::vector<uint8_t> outerPaddedKey(blockSize);

            for (size_t i = 0; i < blockSize; ++i)
            {
                innerPaddedKey[i] = normalizedKey[i] ^ 0x36;
                outerPaddedKey[i] = normalizedKey[i] ^ 0x5C;
            }

            std::vector<uint8_t> innerHash;
            innerPaddedKey.insert(innerPaddedKey.end(), message.begin(), message.end());
            innerHash = sha256(innerPaddedKey);

            outerPaddedKey.insert(outerPaddedKey.end(), innerHash.begin(), innerHash.end());
            return sha256(outerPaddedKey);
        }

        class AES
        {
        private:
            std::vector<std::vector<uint8_t>> roundKeys;

            void keyExpansion(const std::vector<uint8_t> &key)
            {
                const size_t keySize = key.size();
                const size_t rounds = keySize == 16 ? 10 : (keySize == 24 ? 12 : 14);

                roundKeys.resize(4 * (rounds + 1));

                for (size_t i = 0; i < keySize / 4; ++i)
                {
                    roundKeys[i].resize(4);
                    for (size_t j = 0; j < 4; ++j)
                    {
                        roundKeys[i][j] = key[i * 4 + j];
                    }
                }

                for (size_t i = keySize / 4; i < 4 * (rounds + 1); ++i)
                {
                    std::vector<uint8_t> temp = roundKeys[i - 1];

                    if (i % (keySize / 4) == 0)
                    {
                        uint8_t k = temp[0];
                        temp[0] = temp[1];
                        temp[1] = temp[2];
                        temp[2] = temp[3];
                        temp[3] = k;

                        for (size_t j = 0; j < 4; ++j)
                        {
                            temp[j] = AES_SBOX[temp[j]];
                        }

                        temp[0] ^= (1 << ((i / (keySize / 4)) - 1));
                    }
                    else if (keySize > 24 && i % (keySize / 4) == 4)
                    {
                        for (size_t j = 0; j < 4; ++j)
                        {
                            temp[j] = AES_SBOX[temp[j]];
                        }
                    }

                    roundKeys[i].resize(4);
                    for (size_t j = 0; j < 4; ++j)
                    {
                        roundKeys[i][j] = roundKeys[i - (keySize / 4)][j] ^ temp[j];
                    }
                }
            }

            void subBytes(std::vector<std::vector<uint8_t>> &state)
            {
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        state[i][j] = AES_SBOX[state[i][j]];
                    }
                }
            }

            void invSubBytes(std::vector<std::vector<uint8_t>> &state)
            {
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        state[i][j] = AES_INV_SBOX[state[i][j]];
                    }
                }
            }

            void shiftRows(std::vector<std::vector<uint8_t>> &state)
            {
                uint8_t temp = state[1][0];
                state[1][0] = state[1][1];
                state[1][1] = state[1][2];
                state[1][2] = state[1][3];
                state[1][3] = temp;

                temp = state[2][0];
                state[2][0] = state[2][2];
                state[2][2] = temp;
                temp = state[2][1];
                state[2][1] = state[2][3];
                state[2][3] = temp;

                temp = state[3][3];
                state[3][3] = state[3][2];
                state[3][2] = state[3][1];
                state[3][1] = state[3][0];
                state[3][0] = temp;
            }

            void invShiftRows(std::vector<std::vector<uint8_t>> &state)
            {
                uint8_t temp = state[1][3];
                state[1][3] = state[1][2];
                state[1][2] = state[1][1];
                state[1][1] = state[1][0];
                state[1][0] = temp;

                temp = state[2][0];
                state[2][0] = state[2][2];
                state[2][2] = temp;
                temp = state[2][1];
                state[2][1] = state[2][3];
                state[2][3] = temp;

                temp = state[3][0];
                state[3][0] = state[3][1];
                state[3][1] = state[3][2];
                state[3][2] = state[3][3];
                state[3][3] = temp;
            }

            uint8_t gmul(uint8_t a, uint8_t b)
            {
                uint8_t p = 0;
                uint8_t hi_bit_set;

                for (size_t i = 0; i < 8; ++i)
                {
                    if (b & 1)
                    {
                        p ^= a;
                    }

                    hi_bit_set = (a & 0x80);
                    a <<= 1;
                    if (hi_bit_set)
                    {
                        a ^= 0x1B;
                    }

                    b >>= 1;
                }

                return p;
            }

            void mixColumns(std::vector<std::vector<uint8_t>> &state)
            {
                for (size_t i = 0; i < 4; ++i)
                {
                    uint8_t a[4];
                    uint8_t b[4];

                    for (size_t j = 0; j < 4; ++j)
                    {
                        a[j] = state[j][i];
                        b[j] = (state[j][i] << 1) ^ (state[j][i] & 0x80 ? 0x1B : 0);
                    }

                    state[0][i] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
                    state[1][i] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
                    state[2][i] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
                    state[3][i] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
                }
            }

            void invMixColumns(std::vector<std::vector<uint8_t>> &state)
            {
                for (size_t i = 0; i < 4; ++i)
                {
                    uint8_t a[4];
                    for (size_t j = 0; j < 4; ++j)
                    {
                        a[j] = state[j][i];
                    }

                    state[0][i] = gmul(a[0], 0x0E) ^ gmul(a[1], 0x0B) ^ gmul(a[2], 0x0D) ^ gmul(a[3], 0x09);
                    state[1][i] = gmul(a[0], 0x09) ^ gmul(a[1], 0x0E) ^ gmul(a[2], 0x0B) ^ gmul(a[3], 0x0D);
                    state[2][i] = gmul(a[0], 0x0D) ^ gmul(a[1], 0x09) ^ gmul(a[2], 0x0E) ^ gmul(a[3], 0x0B);
                    state[3][i] = gmul(a[0], 0x0B) ^ gmul(a[1], 0x0D) ^ gmul(a[2], 0x09) ^ gmul(a[3], 0x0E);
                }
            }

            void addRoundKey(std::vector<std::vector<uint8_t>> &state, size_t round)
            {
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        state[j][i] ^= roundKeys[round * 4 + i][j];
                    }
                }
            }

        public:
            AES(const std::vector<uint8_t> &key)
            {
                if (key.size() != 16 && key.size() != 24 && key.size() != 32)
                {
                    throw std::runtime_error("AES key must be 128, 192, or 256 bits");
                }

                keyExpansion(key);
            }

            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext)
            {
                if (plaintext.size() != 16)
                {
                    throw std::runtime_error("AES plaintext block must be 128 bits");
                }

                std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        state[j][i] = plaintext[i * 4 + j];
                    }
                }

                const size_t rounds = roundKeys.size() / 4 - 1;

                addRoundKey(state, 0);

                for (size_t round = 1; round < rounds; ++round)
                {
                    subBytes(state);
                    shiftRows(state);
                    mixColumns(state);
                    addRoundKey(state, round);
                }

                subBytes(state);
                shiftRows(state);
                addRoundKey(state, rounds);

                std::vector<uint8_t> ciphertext(16);
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        ciphertext[i * 4 + j] = state[j][i];
                    }
                }

                return ciphertext;
            }

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext)
            {
                if (ciphertext.size() != 16)
                {
                    throw std::runtime_error("AES ciphertext block must be 128 bits");
                }

                std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        state[j][i] = ciphertext[i * 4 + j];
                    }
                }

                const size_t rounds = roundKeys.size() / 4 - 1;

                addRoundKey(state, rounds);

                for (size_t round = rounds - 1; round > 0; --round)
                {
                    invShiftRows(state);
                    invSubBytes(state);
                    addRoundKey(state, round);
                    invMixColumns(state);
                }

                invShiftRows(state);
                invSubBytes(state);
                addRoundKey(state, 0);

                std::vector<uint8_t> plaintext(16);
                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 4; ++j)
                    {
                        plaintext[i * 4 + j] = state[j][i];
                    }
                }

                return plaintext;
            }
        };

        class AES_CBC
        {
        private:
            AES aes;
            std::vector<uint8_t> iv;

        public:
            AES_CBC(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) : aes(key), iv(iv)
            {
                if (iv.size() != 16)
                {
                    throw std::runtime_error("AES IV must be 128 bits");
                }
            }

            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext)
            {
                std::vector<uint8_t> paddedPlaintext = pkcs7Padding(plaintext, 16);

                std::vector<uint8_t> ciphertext;
                std::vector<uint8_t> previousBlock = iv;

                for (size_t i = 0; i < paddedPlaintext.size(); i += 16)
                {
                    std::vector<uint8_t> block(paddedPlaintext.begin() + i, paddedPlaintext.begin() + i + 16);

                    for (size_t j = 0; j < 16; ++j)
                    {
                        block[j] ^= previousBlock[j];
                    }

                    std::vector<uint8_t> encryptedBlock = aes.encrypt(block);

                    ciphertext.insert(ciphertext.end(), encryptedBlock.begin(), encryptedBlock.end());

                    previousBlock = encryptedBlock;
                }

                return ciphertext;
            }

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext)
            {
                if (ciphertext.size() % 16 != 0)
                {
                    throw std::runtime_error("Ciphertext length must be a multiple of the block size");
                }

                std::vector<uint8_t> plaintext;
                std::vector<uint8_t> previousBlock = iv;

                for (size_t i = 0; i < ciphertext.size(); i += 16)
                {
                    std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);

                    std::vector<uint8_t> decryptedBlock = aes.decrypt(block);

                    for (size_t j = 0; j < 16; ++j)
                    {
                        decryptedBlock[j] ^= previousBlock[j];
                    }

                    plaintext.insert(plaintext.end(), decryptedBlock.begin(), decryptedBlock.end());

                    previousBlock = block;
                }

                return removePkcs7Padding(plaintext);
            }
        };

        class RSA
        {
        private:
            bool isPrime(uint64_t n, int k = 5)
            {
                if (n <= 1 || n == 4)
                    return false;
                if (n <= 3)
                    return true;

                uint64_t d = n - 1;
                while (d % 2 == 0)
                {
                    d /= 2;
                }

                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(2, n - 2);

                for (int i = 0; i < k; ++i)
                {
                    uint64_t a = dis(gen);
                    uint64_t x = powMod(a, d, n);

                    if (x == 1 || x == n - 1)
                    {
                        continue;
                    }

                    bool witness = true;
                    uint64_t r = d;
                    while (r != n - 1 && witness)
                    {
                        x = (x * x) % n;
                        r *= 2;

                        if (x == n - 1)
                        {
                            witness = false;
                        }
                    }

                    if (witness)
                    {
                        return false;
                    }
                }

                return true;
            }

            uint64_t generateLargePrime(int bits)
            {
                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(1ULL << (bits - 1), (1ULL << bits) - 1);

                uint64_t num;
                do
                {
                    num = dis(gen);
                    num |= 1;
                } while (!isPrime(num));

                return num;
            }

            int64_t modInverse(int64_t a, int64_t m)
            {
                int64_t m0 = m;
                int64_t y = 0, x = 1;

                if (m == 1)
                {
                    return 0;
                }

                while (a > 1)
                {
                    int64_t q = a / m;
                    int64_t t = m;

                    m = a % m;
                    a = t;
                    t = y;

                    y = x - q * y;
                    x = t;
                }

                if (x < 0)
                {
                    x += m0;
                }

                return x;
            }

            uint64_t powMod(uint64_t base, uint64_t exp, uint64_t mod)
            {
                uint64_t result = 1;
                base = base % mod;

                while (exp > 0)
                {
                    if (exp & 1)
                    {
                        result = (result * base) % mod;
                    }
                    exp >>= 1;
                    base = (base * base) % mod;
                }

                return result;
            }

        public:
            uint64_t n;
            uint64_t e;
            uint64_t d;
            uint64_t p, q;

            void generateKeyPair(int bits = 1024)
            {
                p = generateLargePrime(bits / 2);
                do
                {
                    q = generateLargePrime(bits / 2);
                } while (p == q);

                n = p * q;

                uint64_t phi = (p - 1) * (q - 1);

                e = 65537;

                d = modInverse(e, phi);
            }

            uint64_t encrypt(uint64_t message)
            {
                if (message >= n)
                {
                    throw std::runtime_error("Message too large for RSA encryption");
                }

                return powMod(message, e, n);
            }

            uint64_t decrypt(uint64_t ciphertext)
            {
                return powMod(ciphertext, d, n);
            }

            std::vector<uint8_t> encryptBytes(const std::vector<uint8_t> &message)
            {
                std::vector<uint8_t> ciphertext;
                size_t blockSize = (size_t)std::floor(std::log2(n) / 8);

                for (size_t i = 0; i < message.size(); i += blockSize)
                {
                    uint64_t block = 0;
                    for (size_t j = 0; j < blockSize && i + j < message.size(); ++j)
                    {
                        block = (block << 8) | message[i + j];
                    }

                    uint64_t encryptedBlock = encrypt(block);

                    for (int j = blockSize - 1; j >= 0; --j)
                    {
                        ciphertext.push_back((encryptedBlock >> (j * 8)) & 0xFF);
                    }
                }

                return ciphertext;
            }

            std::vector<uint8_t> decryptBytes(const std::vector<uint8_t> &ciphertext)
            {
                std::vector<uint8_t> plaintext;
                size_t blockSize = (size_t)std::floor(std::log2(n) / 8);

                for (size_t i = 0; i < ciphertext.size(); i += blockSize)
                {
                    uint64_t block = 0;
                    for (size_t j = 0; j < blockSize && i + j < ciphertext.size(); ++j)
                    {
                        block = (block << 8) | ciphertext[i + j];
                    }

                    uint64_t decryptedBlock = decrypt(block);

                    for (int j = blockSize - 1; j >= 0; --j)
                    {
                        plaintext.push_back((decryptedBlock >> (j * 8)) & 0xFF);
                    }
                }

                return plaintext;
            }
        };

        class DiffieHellman
        {
        private:
            bool isPrime(uint64_t n, int k = 5)
            {
                if (n <= 1 || n == 4)
                    return false;
                if (n <= 3)
                    return true;

                uint64_t d = n - 1;
                while (d % 2 == 0)
                {
                    d /= 2;
                }

                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(2, n - 2);

                for (int i = 0; i < k; ++i)
                {
                    uint64_t a = dis(gen);
                    uint64_t x = powMod(a, d, n);

                    if (x == 1 || x == n - 1)
                    {
                        continue;
                    }

                    bool witness = true;
                    uint64_t r = d;
                    while (r != n - 1 && witness)
                    {
                        x = (x * x) % n;
                        r *= 2;

                        if (x == n - 1)
                        {
                            witness = false;
                        }
                    }

                    if (witness)
                    {
                        return false;
                    }
                }

                return true;
            }

            uint64_t generateLargePrime(int bits)
            {
                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(1ULL << (bits - 1), (1ULL << bits) - 1);

                uint64_t num;
                do
                {
                    num = dis(gen);
                    num |= 1;
                } while (!isPrime(num));

                return num;
            }

            uint64_t powMod(uint64_t base, uint64_t exp, uint64_t mod)
            {
                uint64_t result = 1;
                base = base % mod;

                while (exp > 0)
                {
                    if (exp & 1)
                    {
                        result = (result * base) % mod;
                    }
                    exp >>= 1;
                    base = (base * base) % mod;
                }

                return result;
            }

            uint64_t findPrimitiveRoot(uint64_t p)
            {
                if (p == 2)
                    return 1;

                uint64_t phi = p - 1;
                std::vector<uint64_t> factors;

                uint64_t n = phi;
                for (uint64_t i = 2; i * i <= n; ++i)
                {
                    if (n % i == 0)
                    {
                        factors.push_back(i);
                        while (n % i == 0)
                        {
                            n /= i;
                        }
                    }
                }
                if (n > 1)
                {
                    factors.push_back(n);
                }

                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(2, p - 1);

                while (true)
                {
                    uint64_t g = dis(gen);
                    bool isPrimitiveRoot = true;

                    for (uint64_t factor : factors)
                    {
                        if (powMod(g, phi / factor, p) == 1)
                        {
                            isPrimitiveRoot = false;
                            break;
                        }
                    }

                    if (isPrimitiveRoot)
                    {
                        return g;
                    }
                }
            }

        public:
            uint64_t p;
            uint64_t g;
            uint64_t privateKey;
            uint64_t publicKey;

            DiffieHellman(uint64_t prime, uint64_t generator) : p(prime), g(generator)
            {
                generateKeys();
            }

            DiffieHellman(int bits = 1024)
            {
                p = generateLargePrime(bits);
                g = findPrimitiveRoot(p);
                generateKeys();
            }

            void generateKeys()
            {
                std::random_device rd;
                std::mt19937_64 gen(rd());
                std::uniform_int_distribution<uint64_t> dis(2, p - 2);

                privateKey = dis(gen);
                publicKey = powMod(g, privateKey, p);
            }

            uint64_t computeSharedSecret(uint64_t otherPublicKey)
            {
                return powMod(otherPublicKey, privateKey, p);
            }
        };

        class Blowfish
        {
        private:
            static constexpr size_t ROUNDS = 16;
            std::array<uint32_t, ROUNDS + 2> P;
            std::array<std::array<uint32_t, 256>, 4> S;

            static constexpr std::array<uint32_t, ROUNDS + 2> INITIAL_P = {
                0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
                0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
                0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b};

            static constexpr std::array<uint32_t, 256> INITIAL_S0 = {
                0xd1310ba6,
                0x98dfb5ac,
                0x2ffd72db,
                0xd01adfb7,
                0xb8e1afed,
                0x6a267e96,
                0xba7c9045,
                0xf12c7f99,
                0x24a19947,
                0xb3916cf7,
                0x0801f2e2,
                0x858efc16,
            };

            uint32_t F(uint32_t x)
            {
                uint32_t h = S[0][x >> 24] + S[1][(x >> 16) & 0xFF];
                return (h ^ S[2][(x >> 8) & 0xFF]) + S[3][x & 0xFF];
            }

            void expandKey(const std::vector<uint8_t> &key)
            {
                P = INITIAL_P;
                S[0] = INITIAL_S0;

                uint32_t keyIndex = 0;
                for (size_t i = 0; i < ROUNDS + 2; ++i)
                {
                    uint32_t data = 0;
                    for (size_t j = 0; j < 4; ++j)
                    {
                        data = (data << 8) | key[keyIndex % key.size()];
                        keyIndex++;
                    }
                    P[i] ^= data;
                }

                uint32_t left = 0, right = 0;
                for (size_t i = 0; i < ROUNDS + 2; i += 2)
                {
                    encryptBlock(left, right);
                    P[i] = left;
                    P[i + 1] = right;
                }

                for (size_t i = 0; i < 4; ++i)
                {
                    for (size_t j = 0; j < 256; j += 2)
                    {
                        encryptBlock(left, right);
                        S[i][j] = left;
                        S[i][j + 1] = right;
                    }
                }
            }

            void encryptBlock(uint32_t &left, uint32_t &right)
            {
                for (size_t i = 0; i < ROUNDS; ++i)
                {
                    left ^= P[i];
                    right ^= F(left);
                    std::swap(left, right);
                }

                std::swap(left, right);
                right ^= P[ROUNDS];
                left ^= P[ROUNDS + 1];
            }

            void decryptBlock(uint32_t &left, uint32_t &right)
            {
                for (size_t i = ROUNDS + 1; i > 1; --i)
                {
                    left ^= P[i];
                    right ^= F(left);
                    std::swap(left, right);
                }

                std::swap(left, right);
                right ^= P[1];
                left ^= P[0];
            }

        public:
            Blowfish(const std::vector<uint8_t> &key)
            {
                if (key.size() < 4 || key.size() > 56)
                {
                    throw std::runtime_error("Blowfish key must be between 4 and 56 bytes");
                }

                expandKey(key);
            }

            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext)
            {
                std::vector<uint8_t> paddedPlaintext = pkcs7Padding(plaintext, 8);
                std::vector<uint8_t> ciphertext(paddedPlaintext.size());

                for (size_t i = 0; i < paddedPlaintext.size(); i += 8)
                {
                    uint32_t left = (paddedPlaintext[i] << 24) | (paddedPlaintext[i + 1] << 16) |
                                    (paddedPlaintext[i + 2] << 8) | paddedPlaintext[i + 3];
                    uint32_t right = (paddedPlaintext[i + 4] << 24) | (paddedPlaintext[i + 5] << 16) |
                                     (paddedPlaintext[i + 6] << 8) | paddedPlaintext[i + 7];

                    encryptBlock(left, right);

                    ciphertext[i] = (left >> 24) & 0xFF;
                    ciphertext[i + 1] = (left >> 16) & 0xFF;
                    ciphertext[i + 2] = (left >> 8) & 0xFF;
                    ciphertext[i + 3] = left & 0xFF;
                    ciphertext[i + 4] = (right >> 24) & 0xFF;
                    ciphertext[i + 5] = (right >> 16) & 0xFF;
                    ciphertext[i + 6] = (right >> 8) & 0xFF;
                    ciphertext[i + 7] = right & 0xFF;
                }

                return ciphertext;
            }

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext)
            {
                if (ciphertext.size() % 8 != 0)
                {
                    throw std::runtime_error("Ciphertext length must be a multiple of the block size");
                }

                std::vector<uint8_t> plaintext(ciphertext.size());

                for (size_t i = 0; i < ciphertext.size(); i += 8)
                {
                    uint32_t left = (ciphertext[i] << 24) | (ciphertext[i + 1] << 16) |
                                    (ciphertext[i + 2] << 8) | ciphertext[i + 3];
                    uint32_t right = (ciphertext[i + 4] << 24) | (ciphertext[i + 5] << 16) |
                                     (ciphertext[i + 6] << 8) | ciphertext[i + 7];

                    decryptBlock(left, right);

                    plaintext[i] = (left >> 24) & 0xFF;
                    plaintext[i + 1] = (left >> 16) & 0xFF;
                    plaintext[i + 2] = (left >> 8) & 0xFF;
                    plaintext[i + 3] = left & 0xFF;
                    plaintext[i + 4] = (right >> 24) & 0xFF;
                    plaintext[i + 5] = (right >> 16) & 0xFF;
                    plaintext[i + 6] = (right >> 8) & 0xFF;
                    plaintext[i + 7] = right & 0xFF;
                }

                return removePkcs7Padding(plaintext);
            }
        };
    }
}