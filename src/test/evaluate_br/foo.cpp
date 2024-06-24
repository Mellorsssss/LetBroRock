#include <iostream>
#include <unistd.h>

auto long_for(int loop_cnt) -> int
{
  int fuck_cnt = 0;
  for (int i = 0; i < loop_cnt; i++)
  {
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

void *workload(void *_)
{
  sleep(1);
  asm volatile ("" : : : "memory"); 
  int a = long_for(10000000);
  asm volatile ("" : : : "memory"); 
  std::cout<<a<<std::endl;
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
  } else {
    workload(nullptr);
  }
  printf("foO: we get here\n");
  exit(EXIT_SUCCESS);
  return 0;
}

