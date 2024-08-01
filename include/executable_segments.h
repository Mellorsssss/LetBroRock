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

class ExecutableSegments
{
public:
  ExecutableSegments(bool exclude_shared_lib)
  {
    parseProcMaps(exclude_shared_lib);
  }

  bool isAddressInExecutableSegment(uintptr_t address) const
  {
    auto it = segment_map.upper_bound(address);
    if (it == segment_map.begin())
      return false;
    --it;
    return address >= it->first && address < it->second;
  }

 int getExecutableSegmentSize(uint64_t pc) const
 { 
    auto it = segment_map.upper_bound(pc);
    if (it == segment_map.begin())
      return 0;
    --it;
    if(pc >= it->first && pc < it->second)
      return it->second - pc;
    return 0;
 }

private:
  std::map<uintptr_t, uintptr_t> segment_map;

  void parseProcMaps(bool exclude_shared_lib)
  {
    std::ifstream mapsFile("/proc/self/maps");
    if (!mapsFile.is_open())
    {
      perror("open");
      return;
    }

    std::string line;
    char permissions[5]; // e.g., "r-xp"
    char path[256] = {0};
    while (std::getline(mapsFile, line))
    {
      uintptr_t seg_start, seg_end;
      std::string permissions, offset, dev, inode, pathname;

      std::istringstream lineStream(line);
      lineStream >> std::hex >> seg_start;
      lineStream.ignore(1, '-');
      lineStream >> std::hex >> seg_end;
      lineStream >> permissions >> offset >> dev >> inode;

      if (permissions.find('x') == std::string::npos)
      {
        continue;
      }

      if (!(lineStream >> pathname) || (exclude_shared_lib && pathname.find(".so") != std::string::npos))
      {
        DEBUG("(%#lx-%#lx) %s is skipped", seg_start, seg_end, pathname.c_str());
        // continue;
        if (pathname.find("profiler") != std::string::npos) {
          continue;
        }
      }
        
      segment_map[seg_start] = seg_end;
      DEBUG("new executable segment: %#lx-%#lx %s", seg_start, seg_end, pathname.c_str());
    }
  }
};
#endif