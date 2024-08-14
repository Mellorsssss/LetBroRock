#include <iostream>
#include <csignal>
#include <cstdlib>

void signalHandler(int signal) {
    std::cout << "Caught signal " << signal << ". Exiting." << std::endl;
    exit(signal);
}

int main() {
    // 注册信号处理程序
    std::signal(SIGSEGV, signalHandler);

    // 允许生成 core dump
    std::signal(SIGABRT, signalHandler);

    std::cout << "This program will generate a core dump." << std::endl;

    // 故意触发段错误
    int *p = nullptr; // 空指针
    std::cout << *p << std::endl; // 访问空指针会导致段错误

    return 0;
}
