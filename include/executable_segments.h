#ifndef EXECUTABLE_SEGMENTS
#define EXECUTABLE_SEGMENTS
#include "utils.h"

#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

class ExecutableSegments {
public:
	ExecutableSegments(bool exclude_shared_lib) {
		parseProcMaps(exclude_shared_lib);
	}

	bool isAddressInExecutableSegment(uintptr_t address) const {
		auto it = segment_map.upper_bound(address);
		if (it == segment_map.begin())
			return false;
		--it;
		return address >= it->first && address < it->second;
	}

	int getExecutableSegmentSize(uint64_t pc) const {
		auto it = segment_map.upper_bound(pc);
		if (it == segment_map.begin())
			return 0;
		--it;
		if (pc >= it->first && pc < it->second)
			return it->second - pc;
		return 0;
	}

private:
	std::map<uintptr_t, uintptr_t> segment_map;

	bool isProfiler(std::string pathname) {
		return /*pathname.find(".so") != std::string::npos || */ pathname.find("vdso") != std::string::npos ||
		       pathname.find("vsyscall") != std::string::npos || pathname.find("profiler.so") != std::string::npos ||
		       pathname.find("unwind.so") != std::string::npos || pathname.find("libdynamorio.so") != std::string::npos ||
		       pathname.find("dynarmic.so") != std::string::npos;
	}

	void parseProcMaps(bool exclude_shared_lib) {
		std::ifstream mapsFile("/proc/self/maps");
		if (!mapsFile.is_open()) {
			ERROR("open");
			return;
		}

		std::string line;
		char permissions[5]; // e.g., "r-xp"
		char path[256] = {0};

		// for debugging, dump all the segments in the file
		std::ofstream outFile("exec_segments.out");
		if (!outFile.is_open()) {
			ERROR("Failed to open exec_segments.out");
			return;
		}

		std::string mapContent((std::istreambuf_iterator<char>(mapsFile)), std::istreambuf_iterator<char>());
		outFile << mapContent;
		mapsFile.clear();
		mapsFile.seekg(0);

		while (std::getline(mapsFile, line)) {
			uintptr_t seg_start, seg_end;
			std::string permissions, offset, dev, inode, pathname;

			std::istringstream lineStream(line);
			lineStream >> std::hex >> seg_start;
			lineStream.ignore(1, '-');
			lineStream >> std::hex >> seg_end;
			lineStream >> permissions >> offset >> dev >> inode;
			if (permissions.find('x') == std::string::npos) {
				continue;
			}

			lineStream >> pathname;
			if ((exclude_shared_lib) && isProfiler(pathname)) {
				continue;
			}
			segment_map[seg_start] = seg_end;
		}
	}
};
#endif