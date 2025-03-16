#include "util.h"
#include <iostream>
#include <ctime>

namespace CPPENC {
    void Util::log(const std::string& message) {
        std::time_t now = std::time(0);
        std::cout << "[" << std::ctime(&now) << "]: " << message << std::endl;
    }
}
