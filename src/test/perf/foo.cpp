// 如果不加，则F_SETSIG未定义
#define _GNU_SOURCE 1

#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <cstdlib>

// 环形缓冲区大小，16页，即16*4kB
#define RING_BUFFER_PAGES 16

// 目前perf_event_open在glibc中没有封装，需要手工封装一下
int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// mmap共享内存的开始地址
void *rbuf;

// 环形队列中每一项元素
struct perf_my_sample
{
    struct perf_event_header header;
    uint64_t ip;
};

// 下一条采样记录的相对于环形缓冲区开头的偏移量
uint64_t next_offset = 0;
int cnt = 0;

// 采样完成后的信号处理函数
void sample_handler(int sig_num, siginfo_t *sig_info, void *context)
{
    cnt++;
    long long count;
    if (read(sig_info->si_fd, &count, sizeof(long long)) > 0) {
        printf("the count %lld from %#lx\n", count, (uint64_t)((ucontext_t*)context)->uc_mcontext.gregs[REG_RIP]);
        // exit(EXIT_FAILURE);
        // ERROR("read error:%d", info->si_fd)void*;
    }
    // 计算出最新的采样所在的位置（相对于rbuf的偏移量）
    uint64_t offset = 4096 + next_offset;
    // 指向最新的采样
    struct perf_my_sample *sample = (perf_my_sample *)((uint8_t *)rbuf + offset);
    // 过滤一下记录
    if (sample->header.type == PERF_RECORD_SAMPLE)
    {
        // 得到IP值
        printf("the ip is %#lx\n", sample->ip);
        if (cnt>=100)
        exit(EXIT_FAILURE);
    }
    // 共享内存开头是一个struct perf_event_mmap_page，提供环形缓冲区的信息
    struct perf_event_mmap_page *rinfo = (perf_event_mmap_page *)rbuf;
    // 手工wrap一下data_head值，得到下一个记录的偏移量
    next_offset = rinfo->data_head % (RING_BUFFER_PAGES * 4096);
}

// 模拟的一个负载
void workload()
{
    int i, c = 0;
    for (i = 0; i < 100000000; i++)
    {
        c += i * i;
        c -= i * 100;
        c += i * i * i / 100;
    }
}

int main()
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.size = sizeof(struct perf_event_attr);
    // 触发源为CPU时钟
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    // 每100000个CPU时钟采样一次
    attr.sample_period = 10000;
    // 采样目标是IP
    attr.sample_type = PERF_SAMPLE_IP;
    // 初始化为禁用
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    int fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0)
    {
        perror("Cannot open perf fd!");
        return 1;
    }
    // 创建1+16页共享内存，应用程序只读，读取fd产生的内容
    rbuf = mmap(0, (1 + RING_BUFFER_PAGES) * 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (rbuf == MAP_FAILED)
    {
        perror("Cannot mmap!");
        return 1;
    }
    // 这三个fcntl为何一定这么设置不明，但必须这样
    fcntl(fd, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC);
    fcntl(fd, F_SETSIG, SIGIO);
    fcntl(fd, F_SETOWN, getpid());
    // 开始设置采样完成后的信号通知
    struct sigaction sig;
    memset(&sig, 0, sizeof(struct sigaction));
    // 由sample_handler来处理采样完成事件
    sig.sa_sigaction = sample_handler;
    // 要带上siginfo_t参数（因为perf子系统会传入参数，包括fd）
    sig.sa_flags = SA_SIGINFO;
    if (sigaction(SIGIO, &sig, 0) < 0)
    {
        perror("Cannot sigaction");
        return 1;
    }
    // 开始监测
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    workload();
    // 停止监测
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    munmap(rbuf, (1 + RING_BUFFER_PAGES) * 4096);
    close(fd);
    return 0;
}