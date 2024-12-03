#define _GNU_SOURCE
#include "amed.h"
#include "buffer_manager.h"
#include "executable_segments.h"
#include "utils.h"


#include <atomic>
#include <bits/siginfo-arch.h>
#include <bits/siginfo-consts.h>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>

constexpr int MAX_THREAD_NUM = 4;
#define SIGBEGIN (SIGRTMIN + 1)
#define SIGEND   (SIGBEGIN + 1)

#define unlikely(x) __builtin_expect((x), 0)

thread_local ThreadContext *thread_local_context_ = nullptr;
ThreadContext thread_context[MAX_THREAD_NUM];
ExecutableSegments *executable_segments = nullptr;
BufferManager<StackLBRBuffer> *buffer_manager = nullptr;

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

bool find_next_unresolved_branch(ThreadContext &tcontext, uint64_t pc);

void signal_prehandle(sigset_t &old_set) {
	// as the same signal will be blocked in the handler, we don't need to block it again
	return;
    sigset_t new_set;
    sigfillset(&new_set);
    sigprocmask(SIG_SETMASK, &new_set, &old_set);
}

void signal_posthandle(sigset_t &old_set) {
	return;
    sigprocmask(SIG_SETMASK, &old_set, nullptr);
}

class TimerGuard {
public:
	TimerGuard(const std::string &name) : name_(name), start_(std::chrono::high_resolution_clock::now()) {
	}

	~TimerGuard() {
		// auto end = std::chrono::high_resolution_clock::now();
		// std::chrono::duration<double, std::milli> elapsed = end - start_;
		// INFO("%s took %.2f ms", name_.c_str(), elapsed.count());
	}

private:
	std::chrono::time_point<std::chrono::high_resolution_clock> start_;
	std::string name_;
};

/**
 * iterate instructions from `pc`.
 * If instruction is not cti, keep iterating;
 * If instruction is cti
 *    If instruction can be evaluated statically(jmp, call), add to stack_lbr_entry
 *    Else return false to set a breakpoint
 * ATTENTION:
 * For the last trace, a breakpoint is set to get the call stack.
 */
bool find_next_unresolved_branch(ThreadContext &tcontext, uint64_t pc) {
	while (true) {
		int length = INT_MAX;
		// TODO: caculate the length. The length can't be too large or too small
		// int length = executable_segments->getExecutableSegmentSize(pc);
		bool found = find_next_branch(tcontext, pc, length);
		if (!found) {
			// in duckdb TPC-H benchmark, sometimes no branch is discovered
			WARNING("Fail to find a branch until the end of the code from %#lx.", pc);
			return false;
		}

		ucontext_t _ {}; // for statical evaluation, ucontext is unnecessary
		auto [target, taken] = check_branch_if_taken(tcontext, _, true, length);

		// handle the breakpoint since the branch can't be evaluated statically
		if (target == UNKNOWN_ADDR) {
			DEBUG("Should set the breakpoint");
			return true;
		}

		// branch is statically taken
		if (taken) {
			DEBUG("Branch is taken unconditionally");

			if (tcontext.stack_lbr_entry_full()) {
				ERROR("wrong!!!");
			}

			assert(!tcontext.stack_lbr_entry_full() && "it's impossible to get full stack trace here"); // last trace
			tcontext.set_to_addr(target);
			tcontext.add_to_stack_lbr_entry();
			if (tcontext.stack_lbr_entry_full()) // last trace
			{
				// when the last trace is recorded statically, we can't determine its callstack
				// see docs/design.md
				INFO("stack lbr entry is full, we set the final breakpoint for the call stack");
				return true;
			}
		}

		pc = target;
	}

	assert(0 && "never hit");
	ERROR("no more braches");
	return false;
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext) {
	// This avoids recursively hitting breakpoints in our own profiling code.
	thread_local_context_->disable_perf_breakpoint_event();
	if (thread_context->is_stop()) return;
	
	// Disable breakpoint events to prevent false triggers from libprofiler.so code execution.
	sigset_t old_set;
	signal_prehandle(old_set);

	// prevent redundant breakpoint hit(e.g., double triggering the code in libc.so)
	// race condition: the handler num is 0 and thread_context->is_stop() is true
	thread_local_context_->handler_num_inc();
	// double check, if the thread is stop, then just quit

	if (thread_context->is_stop()) {
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}
	assert(errno != EINTR && "breakpoint should not hit the syscall");
	assert(thread_local_context_->get_tid() == syscall(SYS_gettid) && "thread_local_context with wrong tid");

	/**
	 * preconditions:
	 * 1. thread is in breakpoint mode
	 * 2. fd triggering event is bp_fd_
	 * 3. address triggering event is bp_addr_
	 * 4. address triggering event must be br.from_addr
	 */
	if (!thread_local_context_->is_breakpointing()) {
		WARNING("breakpoint hit when the thread is not in breakpoint");
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	if (thread_local_context_->get_breakpoint_fd() != info->si_fd) {
		WARNING("breakpoint hit with wrong fd:%d(expected %d)", info->si_fd, thread_local_context_->get_breakpoint_fd());
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	uint64_t bp_addr = thread_local_context_->get_breakpoint_addr();
	ucontext_t *uc = (ucontext_t *)ucontext;
	uint64_t pc = get_pc(uc);
	if (pc != bp_addr) {
		WARNING("pid %d real breakpoint %#lx(fd: %d) is different from setted breakpoint addr %#lx",
		      thread_local_context_->get_tid(), pc, info->si_fd, bp_addr);
		// continue with the previous breakpoint setting, so we need to cancel the deferred
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		thread_local_context_->enable_perf_breakpoint_event();
		return;
	}

	if (bp_addr != thread_local_context_->get_branch().from_addr ||
	    !executable_segments->isAddressInExecutableSegment(pc)) {
		ERROR("pid %d with unmatched breakpoint address(%#lx vs %#lx)",
		      thread_local_context_->get_tid(), bp_addr, thread_local_context_->get_branch().from_addr);
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}
	DEBUG("Breakpoint handler: the fd is %d handled by %d", info->si_fd, thread_local_context_->get_tid());
	assert(thread_local_context_->get_tid() == syscall(SYS_gettid) &&
	       "thread_local_context check tid before check_branch_if_taken");
	// int length = executable_segments->getExecutableSegmentSize(thread_local_context_->get_branch().from_addr);
	// is it possbile to always use the max length?
	int length = INT_MAX;

	// TODO: segment fault?
	auto [target, taken] = check_branch_if_taken(*thread_local_context_, *uc, false, length);
	if (taken) {
		// try to add the new entry
		if (!thread_local_context_->stack_lbr_entry_full()) {
			thread_local_context_->set_to_addr(target);
			thread_local_context_->add_to_stack_lbr_entry();
		}

		// for the last trace, we need to record its stack(see docs/design.md)
		if (thread_local_context_->stack_lbr_entry_full()) {
			INFO("%d call stack sample check point", thread_local_context_->get_tid());

			thread_local_context_->reset_unwind();
			uint8_t real_frame_size;
			if (!thread_local_context_->unwind((siginfo_t *)info, ucontext,
			                                   thread_local_context_->get_entry()->get_stack_buffer(), MAX_FRAME_SIZE,
			                                   real_frame_size)) {
				ERROR("%d fail to get the call stack", thread_local_context_->get_tid());
			}

			thread_local_context_->get_entry()->set_stack_size(real_frame_size);
			thread_local_context_->reset();
			INFO("%d unwind %d stack frames", thread_local_context_->get_tid(), real_frame_size);
			thread_local_context_->enable_perf_sampling_event();
			thread_local_context_->handler_num_dec();
			signal_posthandle(old_set);
			return;
		}
	}

	bool ok = find_next_unresolved_branch(*thread_local_context_, target);

	uint64_t next_from_addr = thread_local_context_->get_branch().from_addr;
	if (!executable_segments->isAddressInExecutableSegment(next_from_addr)) {
		WARNING("breakpoint handler triggered at un-executable pc %lx", next_from_addr);
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	if (ok) {
		// the breakpoint is already set, no need to set it again
		thread_local_context_->change_perf_breakpoint_event(next_from_addr);
	} else {
		thread_local_context_->enable_perf_sampling_event();
	}
	thread_local_context_->handler_num_dec();
	signal_posthandle(old_set);
	if (ok) {
		thread_context->enable_perf_breakpoint_event();
	}
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext) {
	sigset_t old_set;
	signal_prehandle(old_set);
	// cache the tid to prevent syscall every time
	// to prevent sampling event hit the profiler code, disable it quickly
	if (unlikely(thread_local_context_ == nullptr) && ioctl(info->si_fd, PERF_EVENT_IOC_DISABLE, 0) != 0) {
		ERROR("ioctl(PERF_EVENT_IOC_DISABLE)");
		WARNING("fail to disable perf sampling event");
	}
	static thread_local pid_t tid = syscall(SYS_gettid);

	if (unlikely(thread_local_context_ == nullptr)) {
		for (int i = 0; i < MAX_THREAD_NUM; i++) {
			if (thread_context[i].get_tid() == tid) {
				INFO("%d get thread local context", tid);
				thread_local_context_ = &thread_context[i];
				thread_local_context_->thread_context_init(); // only once
				break;
			}
		}
		if (thread_local_context_ == nullptr) {
			ERROR("%d no thread local context", tid);
			signal_posthandle(old_set);
			return;
		}
	}
	
	if (thread_context->is_stop()) {
		signal_posthandle(old_set);
		return;
	}

	thread_local_context_->handler_num_inc();
	// double check, if the thread is stop, then just quit
	if (thread_context->is_stop()) {
		signal_posthandle(old_set);
		return;
	}
	thread_local_context_->disable_perf_sampling_event();
	ucontext_t *uc = (ucontext_t *)ucontext;
	uint64_t pc = get_pc(uc);

	if (errno == EINTR) {
		ERROR("thread %d Sampling handler mitakenly interrupt a syscall(%d, fd: %d) at %#lx, just return",
		      thread_local_context_->get_tid(), errno, info->si_fd, pc);
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	/**
	 * preconditions:
	 * 1. thread is in sampling mode
	 * 2. fd triggering event is sampling_fd_
	 */
	if (!thread_local_context_->is_sampling()) {
		WARNING("thread %d redudant sampling handler(probably from previous fd:%d), just return",
		      tid, info->si_fd);
		// TODO: why I commented the following line? Fuck.
		// thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	if (thread_local_context_->get_sampling_fd() != info->si_fd) {
		// why hit wrong
		ERROR("thread %d sampling hit with wrong fd:%d(expected %d)", thread_local_context_->get_tid(), info->si_fd,
		      thread_local_context_->get_sampling_fd());
		// thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	thread_local_context_->reset_entry();

	DEBUG("Sampling handler: the fd is %d, handled by %d", info->si_fd, tid);

	if (!executable_segments->isAddressInExecutableSegment(pc)) {
		WARNING("Sampling handler triggered at un-executable pc %lx", pc);
		thread_local_context_->enable_perf_sampling_event();
		thread_local_context_->handler_num_dec();
		signal_posthandle(old_set);
		return;
	}

	bool ok = find_next_unresolved_branch(*thread_local_context_, pc);
	if (ok) {
		thread_local_context_->change_perf_breakpoint_event(thread_local_context_->get_branch().from_addr);
	} else {
		WARNING("fail to find a unresolved branch, it's werid");
		thread_local_context_->enable_perf_sampling_event();
	}

	thread_local_context_->handler_num_dec();
	signal_posthandle(old_set);
	if (ok) {
		thread_local_context_->enable_perf_breakpoint_event();
	}
}

std::vector<pid_t> start_profiler(pid_t pid, pid_t tid) {
	// halt for second to wait for application bootstrap
	// std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	TimerGuard timer_guard("start profiler");
	std::vector<pid_t> tids = get_tids(pid, std::vector<pid_t> {tid}, MAX_THREAD_NUM);

	assert(tids.size() > 0 && "Target should has at least one thread.");
	INFO("main :%d and current %d", pid, tid);

	for (int i = 0; i < tids.size(); i++) {
		pid_t tid = tids[i];
		thread_context[i].set_tid(tid);
		thread_context[i].set_buffer_manager(buffer_manager);
		thread_context[i].thread_start();
		thread_context[i].open_perf_sampling_event();
		thread_context[i].init_perf_breakpoint_event(); // use a 

		INFO("main :%d and current %d start profiling", pid, tids[i]);
	}

	// Attention: we must start the writer thread after the calling of get_tids
	buffer_manager->start_writer_thread();
	return tids;
}

void stop_profiler(pid_t pid, std::vector<pid_t> &tids) {
	for (int i = 0; i < tids.size(); i++) {
		INFO("main :%d and current %d stop profiler", pid, tids[i]);
		thread_context[i].thread_stop();
		// wait handler over
		while (thread_context[i].get_handler_num() != 0) //
		{
			// Yield CPU to other threads to avoid busy polling while waiting for handlers to complete
			std::this_thread::yield();
			DEBUG("current handler_nums is %d", thread_context[i].get_handler_num());
		}
		// destroy
		thread_context[i].thread_context_destroy();
		INFO("main :%d and current %d stop profiler over", pid, tids[i]);
	}

	// Attention: we must stop the writer thread explicitly
	buffer_manager->stop_writer_thread();
}

/* main thread is designed to :
 * 1. spawn writer thread for writing output file
 * 2. periodically call start_profiler and stop_profiler
 */
void profiler_main_thread() {
	pid_t pid = getpid();
	pid_t tid = syscall(SYS_gettid);
	int restart_count = 0;

	while (true) {
		buffer_manager->init();
		auto tids = start_profiler(pid, tid);
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		INFO("restart the profiler %d times", restart_count++);
		stop_profiler(pid, tids);
		buffer_manager->destroy();
	}

	// the following code may cause the segment fault
	delete buffer_manager;
	return;
}

__attribute__((constructor)) void preload_main() {
	executable_segments = new ExecutableSegments(true);

	std::ifstream file("ENABLE_PROFILER");
	if (!file.good()) {
		printf("the profiler is disabled\n");
		return;
	} else {
		printf("the profiler is enabled\n");
	}

	buffer_manager = new BufferManager<StackLBRBuffer>(MAX_THREAD_NUM, "perf_data.lbr");
	initLogFile();

	// register handler of SIGIO for all threads
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_sigaction = sampling_handler;
		sa.sa_flags = SA_SIGINFO | SA_RESTART;
		sigfillset(&sa.sa_mask);
		if (sigaction(SIGIO, &sa, NULL) != 0) {
			ERROR("sigaction");
			return;
		}
	}

	// register handler of SIGTRAP for all threads
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_sigaction = breakpoint_handler;
		sa.sa_flags = SA_SIGINFO | SA_RESTART;
		sigfillset(&sa.sa_mask);
		if (sigaction(SIGRTMIN + 4, &sa, NULL) != 0) {
			ERROR("sigaction");
			return;
		}
	}
	
	std::thread t(profiler_main_thread);
	t.detach();

	atexit([]() { INFO("Just for testing :D Hooked exit function"); });
}