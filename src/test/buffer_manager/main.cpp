#include <buffer_manager.h>
#include <iostream>
#include <string.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

constexpr size_t PAYLOAD_SIZE = 1 << 10;

class MockBuffer {
public:
	void output(int fd) {
		write(fd, payload, sizeof(payload));
	}

	void reset() {
		memset(payload, 0, sizeof(payload));
	}

	void fill(uint8_t ind) {
		for (int i = 0; i < PAYLOAD_SIZE; i++) {
			payload[i] = ind;
		}
	}

private:
	uint8_t payload[PAYLOAD_SIZE] {};
};

BufferManager<MockBuffer> *BM_;

void writer(int index, int epoch) {
	// periodically write to current MockBuffer and swap buffer
	while (epoch--) {
		auto buffer = BM_->get();
		buffer->fill(index + 'a');
		// simulate the workload
		BM_->put(buffer);
	}
	std::cout << "thread " << index << " finish \n";
}

int main(int argc, char **argv) {
	int thread_cnt = atoi(argv[1]);
	int epoch = atoi(argv[2]);
	std::cout << "thread count is " << thread_cnt << " , epoch is " << epoch << std::endl;
	BM_ = new BufferManager<MockBuffer>(thread_cnt, "perf_lbr.foo");
	BM_->init();
	BM_->start_writer_thread();

	std::vector<std::thread> workers;
	for (int i = 0; i < thread_cnt; ++i) {
		workers.emplace_back(std::thread(writer, i, epoch));
	}

	for (int i = 0; i < thread_cnt; ++i) {
		if (workers[i].joinable()) {
			workers[i].join();
		}
	}
}