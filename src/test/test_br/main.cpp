#include <iostream>
#include <thread>
#include <vector>
#define DO_NOT_OPTIMIZE(var) asm volatile("" : "+r,m"(var) : : "memory")

int bar(int v) {
	return v;
}

int foo(int v) {
	return v % 2 ? bar(v + 1) : bar((v << 1) + 1);
}

void thread_work() {
	for (int j = 0; j < 1000; j++)
		for (long long i = 0; i < 1000000; i++) {
			int tem = 0;
			tem = foo(i);
			DO_NOT_OPTIMIZE(tem);
		}
}

int main(int argc, char **args) {
	if (argc < 2) {
		std::cout << "usage: ./main thread_num\n";
		exit(-1);
	}

	int thread_num = atoi(args[1]);
	std::vector<std::thread> workers;
	for (int i = 0; i < thread_num; ++i) {
		workers.emplace_back(std::thread(thread_work));
	}

	for (int i = 0; i < thread_num; ++i) {
		if (workers[i].joinable())
			workers[i].join();
	}
	return 0;
}
