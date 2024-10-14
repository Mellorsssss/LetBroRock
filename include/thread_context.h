#ifndef THREAD_CONTEXT
#define THREAD_CONTEXT

#include "buffer_manager.h"
#include "consts.h"
#include "dr_api.h"
#include "dr_tools.h"
#include "log.h"
#include "stack_lbr_utils.h"
#include "unwind.h"

#include <atomic>
#include <cstdint>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
// void ERROR(const std::string &s);
typedef struct _branch {
	uintptr_t from_addr;
	uintptr_t to_addr; // if to_addr is UNKNOWN_ADDR, it means this branch needs a breakpoint
} branch;

typedef struct _perf_ip_sample {
	struct perf_event_header header;
	uint64_t ip;
} perf_ip_sample;

uint64_t get_mmap_len();

alignas(64) class ThreadContext {
public:
	ThreadContext() : handler_num(0), start_flag(false), sampling_fd_(-1), bp_fd_(-1) {
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

	~ThreadContext() {
		// TODO: uncomment the following line will cause seg fault
		dr_standalone_exit();

		destroy();
	}

	void thread_context_init() {
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

	void thread_context_destroy() {
		dr_standalone_exit();

		destroy();
	}

	void thread_start() {
		start_flag = true;
	}

	void thread_stop() {
		start_flag = false;
		close_perf_sampling_event();
		close_perf_breakpoint_event();
	}

	void destroy() {
		WARNING("destroy the ThreadContext of thread %d", tid_);

		if (thread_buffer_ != nullptr && buffer_manager_ != nullptr) {
			INFO("thread %d return the diry buffer", this->tid_);
			buffer_manager_->put(thread_buffer_);
		}
		reset_entry();
		thread_buffer_ = nullptr;
		WARNING("the thread %d records %d branches(drops %d branches).", tid_, branch_dyn_cnt_, drop_cnt_);
	}

	void reset() {
		stack_lbr_entry_reset();
		reset_branch();
	}

	void reset_entry() {

		drop_cnt_ += thread_stack_lbr_entry_.get_branch_size();
		thread_stack_lbr_entry_.reset();
		reset_branch();
	}

	void set_buffer_manager(BufferManager<StackLBRBuffer> *buffer_manager) {

		buffer_manager_ = buffer_manager;

		thread_buffer_ = buffer_manager_->get();
		assert(thread_buffer_ != nullptr && "buffer get can't be nullptr");
	}

	/** thread state **/
	bool is_sampling() const {
		return state_ == thread_state::SAMPLING;
	}

	bool is_breakpointing() const {
		return state_ == thread_state::BREAKPOINT;
	}

	void set_tid(pid_t tid) {
		tid_ = tid;
	}

	pid_t get_tid() const {
		return tid_;
	}

	void *get_dr_context() const {
		return thread_dr_context_;
	}

	instr_t *get_instr() {
		return d_insn_;
	}

	/** thread perf events state/control **/
	int get_sampling_fd() const {
		return sampling_fd_;
	}

	int get_breakpoint_fd() const {
		return bp_fd_;
	}

	uint64_t get_breakpoint_addr() const {
		return bp_addr_;
	}

	void open_perf_sampling_event();
	// std::mutex& get_lock(){
	//   return mutex_;
	// }
	void handler_num_add() {
		handler_num++;
	}
	void handler_num_dec() {
		handler_num--;
	}
	int get_handler_num() {
		return handler_num.load();
	}
	void enable_perf_sampling_event() {
		state_ = thread_state::SAMPLING;

		if (sampling_fd_ == -1) {
			WARNING("samping event is closed.");
			return;
		}

		if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0) {
			ERROR("PERF_EVENT_IOC_ENABLE");
			ERROR("fail to enable perf sampling event");
		}
	}

	void disable_perf_sampling_event() {
		if (sampling_fd_ == -1) {
			WARNING("samping event is closed.");
			return;
		}

		if (ioctl(sampling_fd_, PERF_EVENT_IOC_DISABLE, 0) != 0) {
			ERROR("ioctl(PERF_EVENT_IOC_DISABLE)");
			WARNING("fail to disable perf sampling event");
			return;
		}
	}

	void close_perf_sampling_event() {
		if (sampling_fd_ == -1) {
			WARNING("samping event is closed.");
			return;
		}

		if (close(sampling_fd_) != 0) {
			ERROR("close");
			WARNING("perf sampling event is closed");
			sampling_fd_ = -1;
			return;
		}

		INFO("close pef sampling event %d(%d)", tid_, sampling_fd_.load());

		sampling_fd_ = -1;
		return;
	}

	void open_perf_breakpoint_event(uint64_t addr);

	// breakpoint event is created every time, so we don't have a 'disable_perf_breakpont_event'
	void close_perf_breakpoint_event() {
		if (bp_fd_ == -1) {
			WARNING("breakpoint event is closed.");
			return;
		}
		bp_addr_ = UNKNOWN_ADDR;
		state_ = thread_state::SAMPLING;

		if (close(bp_fd_) != 0) {
			ERROR("close and the bp_fd_ is %d errno is %d", bp_fd_.load(), errno); // error bp_fd_!=0
			WARNING("fail to close perf sampling event");
			bp_fd_ = -1;
			return;
		}

		WARNING("close perf bp event %d(fd: %d)", tid_, bp_fd_.load());
		bp_fd_ = -1;
		return;
	}

	/** tracing branch state **/
	branch get_branch() const {
		return cur_branch_;
	}

	// reset the traced branch as initial state
	void reset_branch() {
		cur_branch_.from_addr = UNKNOWN_ADDR;
		cur_branch_.to_addr = UNKNOWN_ADDR;
	}

	void set_from_addr(uint64_t from_addr) {
		cur_branch_.from_addr = from_addr;
	}

	void set_to_addr(uint64_t to_addr) {
		cur_branch_.to_addr = to_addr;
	}

	bool stack_lbr_entry_full();

	void stack_lbr_entry_reset();

	void add_to_stack_lbr_entry();

	StackLBREntry *get_entry() {
		return &thread_stack_lbr_entry_;
	}

	void reset_unwind() {
		thread_unwind_util_.reset();
	}

	bool unwind(siginfo_t *siginfo, void *sigcontext, uint64_t *buffer, uint8_t max_frame_size,
	            uint8_t &real_frame_size) {
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
	pid_t tid_ {0};
	typedef enum _thread_state {
		SAMPLING,
		BREAKPOINT,
		CLOSED,
	} thread_state;

	void *thread_dr_context_ {nullptr};
	instr_t *d_insn_;

	thread_state state_ {thread_state::CLOSED};

	uint64_t bp_addr_ {UNKNOWN_ADDR};
	std::atomic<int> handler_num;
	std::atomic<bool> start_flag;
	ThreadUnwind thread_unwind_util_;
	StackLBREntry thread_stack_lbr_entry_; //
	std::shared_ptr<StackLBRBuffer> thread_buffer_ {nullptr};
	BufferManager<StackLBRBuffer> *buffer_manager_ {nullptr};

	// perf_events related data structure
	std::atomic<int> sampling_fd_; // the fd of the sampling events, -1 for invalid
	std::atomic<int> bp_fd_;       // the fd of breakpoint event, -1 for invalid

	int branch_static_cnt_ {0};
	int branch_dyn_cnt_ {0};
	int drop_cnt_ {0};
	branch cur_branch_ {.from_addr = UNKNOWN_ADDR, .to_addr = UNKNOWN_ADDR};
};

#endif