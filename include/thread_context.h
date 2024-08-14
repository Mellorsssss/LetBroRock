#ifndef THREAD_CONTEXT
#define THREAD_CONTEXT

#include "buffer_manager.h"
#include "consts.h"
#include "dr_api.h"
#include "dr_tools.h"
#include "log.h"
#include "stack_lbr_utils.h"
#include "unwind.h"
#include <cstdint>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

void non_perror(const std::string &s);
typedef struct _branch
{
  uintptr_t from_addr;
  uintptr_t to_addr; // if to_addr is UNKNOWN_ADDR, it means this branch needs a breakpoint
} branch;

typedef struct _perf_ip_sample
{
  struct perf_event_header header;
  uint64_t ip;
} perf_ip_sample;

uint64_t get_mmap_len();

class ThreadContext
{
public:
  ThreadContext()
  {
    tid_ = syscall(SYS_gettid);
    DEBUG("init the ThreadContext of thread %d", tid_);

    // init the dr_context
    thread_dr_context_ = dr_standalone_init();
#if defined(__x86_64__)
    if (!dr_set_isa_mode(thread_dr_context_, DR_ISA_AMD64, nullptr))
#elif defined(__aarch64__)
    if (!dr_set_isa_mode(thread_dr_context, DR_ISA_ARM_A64, nullptr))
#endif
    {
      ERROR("fail to set the isa mode.");
    }

    thread_stack_lbr_entry_.reset();
    reset_branch();
  }

  ~ThreadContext()
  {
    // TODO: uncomment the following line will cause seg fault
    dr_standalone_exit();

    destroy();
  }

  void destroy()
  {
    WARNING("destroy the ThreadContext of thread %d", tid_);
    close_perf_sampling_event();
    close_perf_breakpoint_event();
    if (thread_buffer_ != nullptr && buffer_manager_ != nullptr)
    {
      INFO("thread %d return the diry buffer", this->tid_);
      buffer_manager_->return_dirty_buffer(thread_buffer_);
    }
    reset_entry();
    thread_buffer_ = nullptr;
    // WARNING("the thread %d records %d(%d, %d) branches.", tid_, branch_static_cnt_ + branch_dyn_cnt_, branch_static_cnt_, branch_dyn_cnt_);
    WARNING("the thread %d records %d branches(drops %d branches).", tid_, branch_dyn_cnt_, drop_cnt_);
  }

  void reset() {
    stack_lbr_entry_reset();
    reset_branch();
  }

  void reset_entry()
  {
    
    drop_cnt_ += thread_stack_lbr_entry_.get_branch_size();
    thread_stack_lbr_entry_.reset();
    reset_branch();
  }

  void set_buffer_manager(BufferManager *buffer_manager)
  {
    
    buffer_manager_ = buffer_manager;
    thread_buffer_ = buffer_manager_->get_clean_buffer();
    assert(thread_buffer_ != nullptr && "buffer get can't be nullptr");
  }

  /** thread state **/
  bool is_sampling() const { return state_ == thread_state::SAMPLING; }

  bool is_breakpointing() const { return state_ == thread_state::BREAKPOINT; }

  pid_t get_tid() const { return tid_; }

  void *get_dr_context() const { return thread_dr_context_; }
  
  instr_t* get_instr() { return  d_insn_;}

  /** thread perf events state/control **/
  int get_sampling_fd() const { return sampling_fd_; }

  int get_breakpoint_fd() const { return bp_fd_; }

  uint64_t get_breakpoint_addr() const { return bp_addr_; }

  void open_perf_sampling_event();

  void enable_perf_sampling_event()
  {
    state_ = thread_state::SAMPLING;

    if (sampling_fd_ == -1)
    {
      WARNING("samping event is closed.");
      return;
    }

    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
      non_perror("PERF_EVENT_IOC_ENABLE");
      ERROR("fail to enable perf sampling event");
    }
  }

  void disable_perf_sampling_event()
  {
    if (sampling_fd_ == -1)
    {
      WARNING("samping event is closed.");
      return;
    }

    if (ioctl(sampling_fd_, PERF_EVENT_IOC_DISABLE, 0) != 0)
    {
      non_perror("ioctl(PERF_EVENT_IOC_DISABLE)");
      WARNING("fail to disable perf sampling event");
      return;
    }
  }

  void close_perf_sampling_event()
  {
    if (sampling_fd_ == -1)
    {
      WARNING("samping event is closed.");
      return;
    }

    if (close(sampling_fd_) != 0)
    {
      non_perror("close");
      WARNING("perf sampling event is closed");
      sampling_fd_ = -1;
      return;
    }

    INFO("close pef sampling event %d(%d)", tid_, sampling_fd_);
 
    sampling_fd_ = -1;
    return;
  }

  void open_perf_breakpoint_event(uint64_t addr);

  // breakpoint event is created every time, so we don't have a 'disable_perf_breakpont_event'
  void close_perf_breakpoint_event()
  {
    if (bp_fd_ == -1)
    {
      WARNING("breakpoint event is closed.");
      return;
    }
    bp_addr_ = UNKNOWN_ADDR;
    state_ = thread_state::SAMPLING;

    if (close(bp_fd_) != 0)
    {
      non_perror("close");
      WARNING("fail to close perf sampling event");
      bp_fd_ = -1;
      return;
    }

    WARNING("close perf bp event %d(fd: %d)", tid_, bp_fd_);
    bp_fd_ = -1;
    return;
  }

  /** tracing branch state **/
  branch get_branch() const { return cur_branch_; }

  // reset the traced branch as initial state
  void reset_branch()
  {
    cur_branch_.from_addr = UNKNOWN_ADDR;
    cur_branch_.to_addr = UNKNOWN_ADDR;
  }

  void set_from_addr(uint64_t from_addr) { cur_branch_.from_addr = from_addr; }

  void set_to_addr(uint64_t to_addr) { cur_branch_.to_addr = to_addr; }

  bool stack_lbr_entry_full();

  void stack_lbr_entry_reset();

  void add_to_stack_lbr_entry();

  StackLBREntry *get_entry() { return &thread_stack_lbr_entry_; }

  void reset_unwind() { thread_unwind_util_.reset(); }

  bool unwind(siginfo_t *siginfo, void *sigcontext, uint64_t *buffer, uint8_t max_frame_size, uint8_t &real_frame_size)
  {
    return thread_unwind_util_.unwind(siginfo, sigcontext, buffer, max_frame_size, real_frame_size);
  }

  /** branch tracing statistics **/
  void add_static_branch() {
	  // branch_static_cnt_++;
  }

  void add_dynamic_branch() {
	  // branch_dyn_cnt_++;
  }

private:
  pid_t tid_{0};
  typedef enum _thread_state
  {
    SAMPLING,
    BREAKPOINT,
    CLOSED,
  } thread_state;

  void *thread_dr_context_{nullptr};
  instr_t *d_insn_;

  thread_state state_{thread_state::CLOSED};

  uint64_t bp_addr_{UNKNOWN_ADDR};

  ThreadUnwind thread_unwind_util_;
  StackLBREntry thread_stack_lbr_entry_; //
  std::shared_ptr<StackLBRBuffer> thread_buffer_{nullptr};
  BufferManager *buffer_manager_{nullptr};

  // perf_events related data structure
  int sampling_fd_{-1}; // the fd of the sampling events, -1 for invalid
  int bp_fd_{-1};       // the fd of breakpoint event, -1 for invalid

  int branch_static_cnt_{0};
  int branch_dyn_cnt_{0};
  int drop_cnt_{0};
  branch cur_branch_{.from_addr = UNKNOWN_ADDR, .to_addr = UNKNOWN_ADDR};
};
#endif