#ifndef UNWIND
#define UNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <log.h>
#include <string.h>
#include <ucontext.h>

class ThreadUnwind {
public:
	ThreadUnwind() {
		cursor = new unw_cursor_t;
	}

	~ThreadUnwind() {
		delete cursor;
	}

	inline void reset() {
		memset(&context_, 0, sizeof(unw_context_t));
		memset(cursor, 0, sizeof(unw_cursor_t));
	}

	inline bool unwind(siginfo_t *siginfo, void *sigcontext, uint64_t *buffer, uint8_t max_frame_size,
	                   uint8_t &real_frame_size) {
		// extract_from_context(sigcontext);
		unw_getcontext(&context_);

		real_frame_size = 0;

		int ret = unw_init_local(cursor, &context_);
		if (ret < 0) {
			return false;
		}

		do {
			unw_word_t pc;
			ret = unw_get_reg(cursor, UNW_REG_IP, &pc);
			if (ret < 0) {
				return false;
			}

			buffer[real_frame_size++] = pc;

			ret = unw_step(cursor);
			if (ret < 0) {
				return false;
			}

			if (real_frame_size >= max_frame_size) {
				break;
			}
		} while (ret > 0);

		return true;
	}

private:
	inline void extract_from_context(void *sigcontext) {
		unw_tdep_context_t *context = reinterpret_cast<unw_tdep_context_t *>(&context_);
#if defined(__aarch64__)
		const ucontext_t *uc = reinterpret_cast<const ucontext_t *>(sigcontext);
		// Copy all general purpose registers (x0-x28)
		for (int i = 0; i < 31; i++) {
			context->uc_mcontext.regs[i] = uc->uc_mcontext.regs[i];
		}
		context->uc_mcontext.sp = uc->uc_mcontext.sp; // SP
		context->uc_mcontext.pc = uc->uc_mcontext.pc; // PC
#elif defined(__x86_64__)
		const ucontext_t *uc = (const ucontext_t *)sigcontext;
		context->uc_mcontext.gregs[REG_RBP] = uc->uc_mcontext.gregs[REG_RBP];
		context->uc_mcontext.gregs[REG_RSP] = uc->uc_mcontext.gregs[REG_RSP];
		context->uc_mcontext.gregs[REG_RIP] = uc->uc_mcontext.gregs[REG_RIP];
#endif
	}

private:
	unw_context_t context_;
	unw_cursor_t *cursor;
};
#endif