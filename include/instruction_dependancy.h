#ifndef INSTRUCTION_DEPENDENCY
#define INSTRUCTION_DEPENDENCY
#include <cstdint>
#include <fstream>
#include <iostream>
#include <log.h>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

class InstructionDependencies {
public:
	void loadFromFile(const std::string &filename) {
		std::ifstream file(filename);
		if (!file.is_open()) {
			std::cerr << "Failed to open file: " << filename << std::endl;
			return;
		} else {
			std::cout << "Succ to open file\n";
		}

		std::string line;
		while (std::getline(file, line)) {
			if (line.empty())
				continue;

			std::istringstream iss(line);
			std::string functionName;
			uint64_t startAddr, endAddr;
			char colon;
			iss >> functionName >> std::hex >> startAddr >> endAddr;
			iss >> colon;
			ERROR("%s %#lx %#lx", functionName.c_str(), startAddr, endAddr);

			std::vector<uint64_t> instructions;
			uint64_t addr;
			while (iss >> std::hex >> addr) {
				instructionSets.insert(addr);
				instructions.push_back(addr);
			}

			functionRanges[startAddr] = std::make_pair(endAddr, instructions);
		}
	}

	std::vector<uint64_t> query(uint64_t startAddr, uint64_t endAddr) const {
		std::vector<uint64_t> result;

		auto it = functionRanges.lower_bound(startAddr);
		if (it == functionRanges.end() || it->first > startAddr) {
			if (it == functionRanges.begin())
				return result;
			--it;
		}

		ERROR("[%#lx, %#lx]", it->first, it->second.first);
		if (it->first <= startAddr && it->second.first >= endAddr) {
			const auto &instructions = it->second.second;
			for (uint64_t addr : instructions) {
				if (addr >= startAddr && addr <= endAddr) {
					result.push_back(addr);
				}
			}
		}

		return result;
	}

	bool isInstructionDependant(uint64_t addr) const {
		return instructionSets.count(addr) != 0;
	}

private:
	std::map<uint64_t, std::pair<uint64_t, std::vector<uint64_t>>> functionRanges;
	std::set<uint64_t> instructionSets; // all the needed instructions
};
#endif