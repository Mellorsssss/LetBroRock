#include <chrono>
#include <iostream>
#include <libunwind-ptrace.h>
#include <libunwind-x86_64.h>
#include <libunwind.h>
#include <thread>
#include <unistd.h>
#include <vector>

void print_backtrace();

int bar(int i)
{
  // fprintf(stderr, ".");
 // printf(".");
  return i + 1;
}

int foo(int i)
{
  // fprintf(stderr, ",");
  //printf("\b");
  return bar(i) + 2;
}

auto long_for(int loop_cnt) -> int
{
  int fuck_cnt = 0;
  for (int i = 0; i < loop_cnt; i++)
  {
    if (i % 2)
    {
      fuck_cnt += bar(i);
    }
    else
    {
      fuck_cnt += foo(i);
    }
  }
  sleep(1);
  return fuck_cnt;
}

void workload()
{
  // sleep(1);
  asm volatile("" : : : "memory");
  int a = long_for(47483647);
  asm volatile("" : : : "memory");
  std::cout << a << std::endl;
}

int main(int argc, char **argv)
{
  std::vector<std::thread> threads;

  int thread_num = atoi(argv[1]);
  while(true){
    for (int i = 0; i < 1; i++)
    {
    // workload();
      for (int i = 0; i < thread_num; i++)
    {
      threads.emplace_back(std::thread(workload));
    }

    for (int i = 0; i < thread_num; i++)
    {
      if (threads[i].joinable())
        threads[i].join();
    }
    sleep(1);
  }
  }
  

  return 0;
}
