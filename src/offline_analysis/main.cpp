#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>
#include <string>

class InstructionDependencies {
public:
    void loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
            return;
        }

        std::cout << "Succ to open file" << std::endl;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;

            std::istringstream iss(line);
            std::string functionName;
            uint64_t startAddr, endAddr;
            char colon;
            iss >> functionName >> std::hex >> startAddr >> endAddr;
            iss >> colon;
            std::cout << functionName << " " << std::hex << startAddr << " " << endAddr << std::endl;

            std::vector<uint64_t> instructions;
            uint64_t addr;
            while (iss >> std::hex >> addr) {
                instructions.push_back(addr);
            }

            functionRanges[startAddr] = std::make_pair(endAddr, instructions);
        }
    }

    // 查询函数
    std::vector<uint64_t> query(uint64_t startAddr, uint64_t endAddr) const {
        std::vector<uint64_t> result;

        // 找到包含起始地址的函数范围
        auto it = functionRanges.lower_bound(startAddr);
        if (it == functionRanges.end() || it->first > startAddr) {
            if (it == functionRanges.begin()) return result;
            --it;
        }

        std::cout<< "[" << it->first << ", " << it->second.first << "]\n";
        // 检查结束地址是否在范围内
        if (it->first <= startAddr && it->second.first >= endAddr) {
            const auto& instructions = it->second.second;
            for (uint64_t addr : instructions) {
                if (addr >= startAddr && addr <= endAddr) {
                    result.push_back(addr);
                }
            }
        }

        return result;
    }

private:
    std::map<uint64_t, std::pair<uint64_t, std::vector<uint64_t>>> functionRanges;
};

// 测试函数
void testValidQuery() {
    InstructionDependencies deps;
    deps.loadFromFile("/home/melos/proj/LetBroRock/src/test/test_sample/instruction_dependencies.txt");

    std::vector<uint64_t> result = deps.query(0x1250, 0x12d4);
    std::vector<uint64_t> expected = {0x1250, 0x1254, 0x125f, 0x1266, 0x126a, 0x126c, 0x127d, 0x128d, 0x1292, 0x1295, 0x1299, 0x129b, 0x129f, 0x12b3, 0x12cf, 0x12d3, 0x12d4};

    if (result == expected) {
        std::cout << "Valid Query Test Passed" << std::endl;
    } else {
        std::cout << "Valid Query Test Failed" << std::endl;
        std::cout << "Expected: ";
        for (uint64_t addr : expected) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << "\nResult: ";
        for (uint64_t addr : result) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << std::endl;
    }
}

void testPartialRangeQuery() {
    InstructionDependencies deps;
    deps.loadFromFile("/home/melos/proj/LetBroRock/src/test/test_sample/instruction_dependencies.txt");

    std::vector<uint64_t> result = deps.query(0x1260, 0x1270);
    std::vector<uint64_t> expected = {0x1266, 0x126a, 0x126c};

    if (result == expected) {
        std::cout << "Partial Range Query Test Passed" << std::endl;
    } else {
        std::cout << "Partial Range Query Test Failed" << std::endl;
        std::cout << "Expected: ";
        for (uint64_t addr : expected) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << "\nResult: ";
        for (uint64_t addr : result) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << std::endl;
    }
}


void testInvalidQuery() {
    InstructionDependencies deps;
    deps.loadFromFile("/home/melos/proj/LetBroRock/src/test/test_sample/instruction_dependencies.txt");

    std::vector<uint64_t> result = deps.query(0x1000, 0x1050);
    std::vector<uint64_t> expected = {};

    if (result == expected) {
        std::cout << "Invalid Query Test Passed" << std::endl;
    } else {
        std::cout << "Invalid Query Test Failed" << std::endl;
        std::cout << "Expected: ";
        for (uint64_t addr : expected) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << "\nResult: ";
        for (uint64_t addr : result) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << std::endl;
    }
}

void testInvalidRangeQuery() {
    InstructionDependencies deps;
    deps.loadFromFile("/home/melos/proj/LetBroRock/src/test/test_sample/instruction_dependencies.txt");

    std::vector<uint64_t> result = deps.query(0x1300, 0x1200);
    std::vector<uint64_t> expected = {};

    if (result == expected) {
        std::cout << "Invalid Range Query Test Passed" << std::endl;
    } else {
        std::cout << "Invalid Range Query Test Failed" << std::endl;
        std::cout << "Expected: ";
        for (uint64_t addr : expected) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << "\nResult: ";
        for (uint64_t addr : result) {
            std::cout << std::hex << addr << " ";
        }
        std::cout << std::endl;
    }
}

int main() {
    InstructionDependencies deps;
    deps.loadFromFile("/home/melos/proj/LetBroRock/src/test/test_sample/instruction_dependencies.txt");

    testValidQuery();
    testPartialRangeQuery();
    testInvalidQuery();
    testInvalidRangeQuery();

    return 0;
}