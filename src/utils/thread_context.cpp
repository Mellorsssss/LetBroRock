#include "thread_context.h"
#include <fcntl.h>
#include <linux/hw_breakpoint.h>

uint64_t get_mmap_len()
{
    return sysconf(_SC_PAGESIZE) * (1 + RINGBUFFER_SIZE);
}

void ThreadContext::open_perf_breakpoint_event(uint64_t addr)
{
    this->state_ = thread_state::BREAKPOINT;
    this->bp_addr_ = addr;

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0;
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = (uintptr_t)(addr);
    pe.bp_len = 8;
    pe.sample_period = 1; // make sure every breakpoint will cause a overflow
    pe.disabled = 1;
    pe.exclude_kernel = 1;

    assert(this->bp_fd_ == -1 && "previous breakpoint events must be closed");
    DEBUG("enter the set breakpoint, errno is %d", errno);
    if ((this->bp_fd_ = syscall(__NR_perf_event_open, &pe, tid_, -1, -1, 0)) < 0)
    {
        perror("perf_event_open");
        ERROR("no left breakpoint");
    }

    // signal(SIGIO, SIG_DFL);
    struct f_owner_ex owner;
    owner.type = F_OWNER_TID;
    owner.pid = tid_;

    if (fcntl(this->bp_fd_, F_SETOWN_EX, &owner) == -1)
    {
        perror("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->bp_fd_, F_SETSIG, SIGRTMIN+4) == -1)
    {
        perror("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    int flags = fcntl(this->bp_fd_, F_GETFL, 0);
    if (flags == -1)
    {
        perror("F_GETFL");
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->bp_fd_, F_SETFL, flags | O_ASYNC) == -1)
    {
        perror("F_SETFL");
        exit(EXIT_FAILURE);
    }

    DEBUG("successfully set breakpoint at %lx", pe.bp_addr);
    if (ioctl(this->bp_fd_, PERF_EVENT_IOC_RESET, 0) != 0)
    {
        ERROR("reset failure %d", tid_);
        perror("PERF_EVENT_IOC_RESET");
        return;
    }

    if (ioctl(this->bp_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
        perror("PERF_EVENT_IOC_ENABLE");
        return;
    }
}

void ThreadContext::open_perf_sampling_event()
{
    errno = 0;
    this->state_ = thread_state::SAMPLING;

    /**
     * precondition: open_perf_sampling_event should be called only once
     */
    if (this->sampling_fd_ != -1)
    {
        ERROR("open_perf_sampling_event is called multiple times %d", tid_);
    }

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.type = PERF_TYPE_HARDWARE;
    pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    pe.sample_period = 1000 * 5000;
    pe.disabled = 1;
    pe.mmap = 1; // it seems that the sampling mode is only enabled combined with mmap
    pe.sample_type = PERF_SAMPLE_IP;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    this->sampling_fd_ = syscall(__NR_perf_event_open, &pe, tid_, -1, -1, 0);
    if (this->sampling_fd_ < 0)
    {
        WARNING("the perf_fd is %d", this->sampling_fd_);
        perror("here :perf_event_open");
        return;
    }

    if (fcntl(this->sampling_fd_, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC) != 0)
    {
        perror("F_SETFL");
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->sampling_fd_, F_SETSIG, SIGIO) != 0)
    {
        perror("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    struct f_owner_ex owner;
    owner.type = F_OWNER_TID;
    owner.pid = this->tid_;

    if (fcntl(this->sampling_fd_, F_SETOWN_EX, &owner) != 0)
    {
        perror("F_SETOWN_EX");
        exit(EXIT_FAILURE);
    }

    DEBUG("perf_events_enable: for %d(fd: %d)", owner.pid, this->sampling_fd_);
    // open perf_event
    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_RESET, 0) != 0)
    {
        ERROR("reset failure %d", tid_);
        perror("PERF_EVENT_IOC_RESET");
        exit(EXIT_FAILURE);
    }

    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
        perror("PERF_EVENT_IOC_ENABLE");
        exit(EXIT_FAILURE);
    }

    WARNING("exit perf_events open with errno %d", errno);
    if (errno)
    {
        ERROR("fail in perf_events enable");
    }
}

bool ThreadContext::stack_lbr_entry_full()
{
    return thread_stack_lbr_entry_.is_full();
}

void ThreadContext::stack_lbr_entry_reset()
{
    DEBUG("begin to reset the lbr entry of thread %d", tid_);
    if (thread_buffer_ == nullptr)
    {
        WARNING("thread %d get null thread buffer", tid_);
    }
    else if (false == thread_stack_lbr_entry_.serialize(thread_buffer_->get_current(), thread_buffer_->get_buffer_size()))
    {
        INFO("the buffer'size %d is less than needed size %d", thread_buffer_->get_buffer_size(), thread_stack_lbr_entry_.get_total_size());
        thread_buffer_ = buffer_manager_->swap_buffer(thread_buffer_);//wait_clean_buffer
    }

    thread_stack_lbr_entry_.reset();
    DEBUG("succeed to reset the lbr entry of thread %d", tid_);
}

void ThreadContext::add_to_stack_lbr_entry()
{
    thread_stack_lbr_entry_.add_branch(cur_branch_.from_addr, cur_branch_.to_addr);
}