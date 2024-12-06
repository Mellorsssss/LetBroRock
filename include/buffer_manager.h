#ifndef BUFFER_MANAGER
#define BUFFER_MANAGER

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <fcntl.h> // for open()
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <unistd.h> // for close()
#include <vector>

// add tmp_buffers to avoid deadlock
template <class Buffer>
class BufferManager {
public:
	BufferManager(int num_threads, const std::string &output_path) : num_threads_(num_threads), stop_writer_(false) {
		stop_writer_ = false;
		output_file = open("perf_data.lbr", O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (output_file == -1) {
			perror("open");
		}

		std::ifstream b_file("ENABLE_STACK");
		enable_bolt_ = b_file.good();
	}

	~BufferManager() {
		// TODO: dead locks?
		stop_writer_thread();

		// flush all the left dirty buffers
		if (dirty_buffers_.size() > 0) {
			while (!dirty_buffers_.empty()) {
				auto buffer = dirty_buffers_.front();
				clean_buffers_.push(buffer);
				dirty_buffers_.pop();
				buffer->output(output_file);
			}
		}

		while (!clean_buffers_.empty()) {
			auto buffer = clean_buffers_.front();
			clean_buffers_.pop();
		}
		close(output_file);
	}

	void init() {
		std::unique_lock<std::mutex> lock(clean_mutex_);
		for (int i = 0; i < num_threads_ * 2; ++i) {
			clean_buffers_.push(std::make_shared<Buffer>());
		}
	}

	void destroy() {
		std::unique_lock<std::mutex> dirty_lock(dirty_mutex_);
		if (dirty_buffers_.size() > 0) {
			while (!dirty_buffers_.empty()) {
				auto buffer = dirty_buffers_.front();
				clean_buffers_.push(buffer);
				dirty_buffers_.pop();
				buffer->output(output_file);
			}
		}
		dirty_lock.unlock();
		std::unique_lock<std::mutex> clean_lock(clean_mutex_);
		while (!clean_buffers_.empty()) {
			auto buffer = clean_buffers_.front();
			clean_buffers_.pop();
		}
	}

	std::shared_ptr<Buffer> get() {
		std::unique_lock<std::mutex> lock(clean_mutex_);

		while (clean_buffers_.empty()) {
			clean_buffer_cv_.wait(lock);
		}

		std::shared_ptr<Buffer> buffer = clean_buffers_.front();
		buffer->set_enable_bolt(enable_bolt_);
		clean_buffers_.pop();

		return buffer;
	}

	void put(std::shared_ptr<Buffer> buffer) // 返回一个ditybuffer
	{
		std::unique_lock<std::mutex> lock(dirty_mutex_);
		// dead lock?
		dirty_buffers_.push(buffer);
		lock.unlock();
		dirty_buffer_cv_.notify_all();
	}

	std::shared_ptr<Buffer> swap_buffer(std::shared_ptr<Buffer> dirty_buffer) // 换出一个clean_buffer
	{
		put(dirty_buffer);
		return get();
	}

	void start_writer_thread() {
		stop_writer_ = false;
		writer_thread_ = std::thread([this]() { consume(); });
	}

	void stop_writer_thread() {
		{ stop_writer_ = true; }
		dirty_buffer_cv_.notify_all();

		if (writer_thread_.joinable()) {
			writer_thread_.join();
		}
	}

private:
	void consume() {
		while (true) {
			std::unique_lock<std::mutex> dirty_lock(dirty_mutex_);

			dirty_buffer_cv_.wait(dirty_lock, [this]() { return !dirty_buffers_.empty() || stop_writer_; });

			if (stop_writer_) {
				break;
			}

			std::shared_ptr<Buffer> buffer = dirty_buffers_.front();
			dirty_buffers_.pop();
			dirty_lock.unlock();

			buffer->output(output_file);
			buffer->reset();
			std::unique_lock<std::mutex> clean_lock(clean_mutex_);
			clean_buffers_.push(buffer);
			// clean_lock.unlock();
			clean_buffer_cv_.notify_all();
		}
	}

	int num_threads_;
	std::queue<std::shared_ptr<Buffer>> clean_buffers_;
	std::queue<std::shared_ptr<Buffer>> dirty_buffers_;
	std::mutex mutex_;
	std::mutex dirty_mutex_;
	std::mutex clean_mutex_;
	std::condition_variable clean_buffer_cv_;
	std::condition_variable dirty_buffer_cv_;

	std::thread writer_thread_;
	std::atomic<bool> stop_writer_;
	int output_file = -1;
	bool enable_bolt_{false};
};

#endif // BUFFER_MANAGER_H
