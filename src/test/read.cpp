#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <unistd.h>
std::mutex io_mutex;

void readFile(const std::string& filename, std::vector<char>& buffer) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::lock_guard<std::mutex> lock(io_mutex);
        std::cerr << "Failed to open file: " << filename << std::endl;
        sleep(1);
        return;
    }

    buffer.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::lock_guard<std::mutex> lock(io_mutex);
    std::cout << "Thread " << std::this_thread::get_id() << " finished reading " << filename << std::endl;
}

int main() {
    std::vector<std::string> filenames = {"file1.txt", "file2.txt", "file3.txt"};
    std::vector<std::thread> threads;
    std::vector<std::vector<char>> buffers(filenames.size());
while(true){
    for (size_t i = 0; i < filenames.size(); ++i) {
        threads.emplace_back(std::thread(readFile, std::cref(filenames[i]), std::ref(buffers[i])));
    }
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    // Optional: You can do further processing with the buffers here if needed
    // For example, printing the size of each buffer
    for (size_t i = 0; i < buffers.size(); ++i) {
        std::cout << "Buffer " << i << " size: " << buffers[i].size() << std::endl;
    }

    sleep(2);
}
    

    return 0;
}
