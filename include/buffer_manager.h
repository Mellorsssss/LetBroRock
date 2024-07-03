#ifndef BUFFER_MANAGER
#define BUFFER_MANAGER
#include "log.h"
#include "stack_lbr_utils.h"
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class BufferManager
{
public:
    BufferManager(int num_threads, int buffer_size, const std::string &output_path) : num_threads_(num_threads), buffer_size_(buffer_size), stop_writer_(false)
    {
        // we allocate 2 buffers for every worker thread
        for (int i = 0; i < num_threads_ * 2; ++i)
        {
            clean_buffers_.push(new StackLBRBuffer());
        }

        output_file.open(output_path);
        if (!output_file.is_open())
        {
            ERROR("fail to init the output file");
        }
    }

    ~BufferManager()
    {
        // TODO: dead locks?
        stop_writer_thread();

        // flush all the left dirty buffers
        if (dirty_buffers_.size() > 0)
        {
            INFO("there are %d dirty buffers to flush", dirty_buffers_.size());
            while (dirty_buffers_.size())
            {
                auto *buffer = dirty_buffers_.front();
                dirty_buffers_.pop();
                
                buffer->output(output_file);
            }
        }
    }

    StackLBRBuffer *get_clean_buffer()
    {
        std::unique_lock<std::mutex> lock(mutex_);

        while (clean_buffers_.empty())
        {
            clean_buffer_cv_.wait(lock);
        }

        StackLBRBuffer *buffer = clean_buffers_.front();
        clean_buffers_.pop();
        return buffer;
    }

    void return_dirty_buffer(StackLBRBuffer *buffer)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dirty_buffers_.push(buffer);
        dirty_buffer_cv_.notify_one();
    }

    StackLBRBuffer *swap_buffer(StackLBRBuffer *dirty_buffer)
    {
        return_dirty_buffer(dirty_buffer);
        return get_clean_buffer();
    }

    void start_writer_thread()
    {
        stop_writer_ = false;
        writer_thread_ = std::thread([this]()
                                     { write_dirty_buffers(); });
    }

    void stop_writer_thread()
    {
        INFO("try to terminiate the writer thread");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_writer_ = true;
        }
        dirty_buffer_cv_.notify_one();

        if (writer_thread_.joinable())
        {
            writer_thread_.join();
        }
    }

private:
    void write_dirty_buffers()
    {
        while (true)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            while (dirty_buffers_.empty() && !stop_writer_)
            {
                dirty_buffer_cv_.wait(lock);
            }

            if (stop_writer_)
            {
                break;
            }
            

            StackLBRBuffer *buffer = dirty_buffers_.front();
            dirty_buffers_.pop();
            lock.unlock();

            INFO("writer begin to write a new buffer");
            buffer->output(output_file);
            lock.lock();
            buffer->reset();
            clean_buffers_.push(buffer);
            clean_buffer_cv_.notify_one();
        }
        
        INFO("writer thread is over");
    }

    int num_threads_;
    int buffer_size_;
    std::queue<StackLBRBuffer *> clean_buffers_;
    std::queue<StackLBRBuffer *> dirty_buffers_;
    std::mutex mutex_;
    std::condition_variable clean_buffer_cv_;
    std::condition_variable dirty_buffer_cv_;

    std::thread writer_thread_;
    bool stop_writer_;
    std::ofstream output_file;
};

#endif // BUFFER_MANAGER_H
