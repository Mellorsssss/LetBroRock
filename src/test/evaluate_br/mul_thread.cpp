#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <vector>


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

void create_processes(int num_processes) {
    std::vector<pid_t> pids;

    for (int i = 0; i < num_processes; ++i) {
        pid_t pid = fork();

        if (pid == 0) { // 子进程
            pid_t child_pid = getpid();
            pid_t parent_pid = getppid();
            workload();
            std::cout << "Child Process " << i << ": PID = " << child_pid << ", Parent PID = " << parent_pid << std::endl;
            _exit(0); // 子进程正常退出
        } else if (pid > 0) { // 父进程
            pids.push_back(pid);
        } else {
            std::cerr << "Fork failed for process " << i << std::endl;
        }
    }

    // 父进程等待所有子进程结束
    for (pid_t pid : pids) {
        waitpid(pid, nullptr, 0);
    }
}

int main() {
    int num_processes = 5; // 创建 5 个子进程
    std::cout << "Parent Process: PID = " << getpid() << std::endl;
    create_processes(num_processes);
    std::cout << "All child processes have exited." << std::endl;
    return 0;
}
