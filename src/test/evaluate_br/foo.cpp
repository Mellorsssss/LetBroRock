#include <chrono>
#include <iostream>
#include <libunwind-ptrace.h>
#include <libunwind-x86_64.h>
#include <libunwind.h>
#include <unistd.h>

void print_backtrace();

auto long_for(int loop_cnt) -> int
{
  int fuck_cnt = 0;
  for (int i = 0; i < loop_cnt; i++)
  {
    // std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
    // print_backtrace();
    // // 执行需要测量时间的代码
    // std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
    // std::chrono::microseconds elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    // std::cout << "Elapsed time: " << elapsed.count() << " microseconds" << std::endl;
    if (i % 2)
    {
      fuck_cnt += 1;
      //    printf(".");
    }
    else
    {
      fuck_cnt += 2;
      //   printf("-");
    }
  }
  return fuck_cnt;
}
void print_backtrace()
{
  unw_cursor_t cursor;
  unw_context_t context;

  // 初始化 libunwind 上下文
  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  // 遍历调用栈并输出信息
  while (unw_step(&cursor) > 0)
  {
    unw_word_t offset, pc;
    char symbol[512];

    // 获取当前帧的程序计数器值（即函数地址）
    unw_get_reg(&cursor, UNW_REG_IP, &pc);

    // // 获取函数符号名和偏移量
    // if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset) == 0)
    // {
    // // printf("[%lx] %s + 0x%lx\n", (unsigned long)pc, symbol, (unsigned long)offset);

    // }
    // else
    // {
    // // printf("[%lx] <unknown>\n", (unsigned long)pc);
    // }
  }
}

void *workload(void *_)
{
  sleep(1);
  asm volatile("" : : : "memory");
  int a = long_for(10000000);
  asm volatile("" : : : "memory");
  std::cout << a << std::endl;
  exit(EXIT_SUCCESS);
  return NULL;
}

int main(int argc, char **argv)
{
  if (atoi(argv[1]) == 1)
  {
    pthread_t t;
    pthread_create(&t, NULL, workload, NULL);
    pthread_join(t, NULL);
  }
  else
  {
    workload(nullptr);
  }
  printf("foO: we get here\n");
  exit(EXIT_SUCCESS);
  return 0;
}
