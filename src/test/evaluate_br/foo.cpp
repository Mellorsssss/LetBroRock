#include <iostream>
#include <unistd.h>

auto add(int a, int b) -> int
{
  return a + b;
}

void *workload(void *_)
{
  sleep(1);
  add(1, 3);
  return NULL;
}

int main()
{
  pthread_t t;
  pthread_create(&t, NULL, workload, NULL); 
  pthread_join(t, NULL);
  return 0;
}