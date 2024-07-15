#include "../../../include/buffer_manager.h"
#include "../../../include/log.h"

constexpr int STACK_SIZE = 16;
constexpr int LBR_SIZE = 16;
constexpr uint64_t FAKE_STACK = 0x7ffff7ffa000;
constexpr uint64_t FAKE_FROM_ADDR = 0x7ffffaaaa000;
constexpr uint64_t FAKE_TO_ADDR = 0x7ffffbbbb000;

thread_local StackLBRBuffer *buffer{nullptr};
thread_local StackLBREntry entry;
BufferManager *g_buffer_manger{nullptr};

void workload(int cnt)
{
  if (nullptr == (buffer = g_buffer_manger->get_clean_buffer()))
  {
    ERROR("fail to get the initial clean buffer");
  }

  entry.reset();
  for (int j = 0; j < LBR_SIZE; j++)
  {
    if (false == entry.add_branch(FAKE_FROM_ADDR, FAKE_TO_ADDR))
    {
      ERROR("fail to add new branch");
    }
  }

  uint64_t *stack_buffer = entry.get_stack_buffer();
  for (int j = 0; j < STACK_SIZE; j++)
  {
    stack_buffer[j] = FAKE_STACK;
  }

  entry.set_stack_size(STACK_SIZE);

  INFO("the entry has size %d", entry.get_total_size());

  for (int i = 0; i < cnt; ++i)
  {
    if (false == entry.serialize(buffer->get_current(), buffer->get_buffer_size()))
    {
      INFO("the buffer'size %d is less than needed size %d", buffer->get_buffer_size(), entry.get_total_size());
      buffer = g_buffer_manger->swap_buffer(buffer);
      --i;
    } else {
      INFO("write %d", i);
    }
  }
  INFO("end");
}

int main(int argc, char**argv)
{
  int thread_num = atoi(argv[1]);  
  int cnt = atoi(argv[2]);  
  g_buffer_manger = new BufferManager(thread_num, cnt, "log");
  g_buffer_manger->start_writer_thread();
  
  std::vector<std::thread> threads;
  for(int i = 0; i < thread_num; i++) {
    threads.emplace_back(std::thread(workload, cnt)); 
    INFO("create thread %d", i);
  }
  
  for(auto& t: threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  
  delete g_buffer_manger;
  return 0; 
}