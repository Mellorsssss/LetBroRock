#ifndef UNWIND
#define UNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <string.h>

#if defined(__arm__)
#if !defined(__BIONIC_HAVE_UCONTEXT_T)
// The Current version of the Android <signal.h> doesn't define ucontext_t.
#include <asm/sigcontext.h> // Ensure 'struct sigcontext' is defined.
// Machine context at the time a signal was raised.
typedef struct ucontext
{
  uint32_t uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  struct sigcontext uc_mcontext;
  uint32_t uc_sigmask;
} ucontext_t;
#endif // !__BIONIC_HAVE_UCONTEXT_T
#endif // defined(__arm__)

class ThreadUnwind
{
public:
  ThreadUnwind()
  {
    cursor = new unw_cursor_t;
  }

  ~ThreadUnwind()
  {
    delete cursor;
  }

  inline void reset()
  {
    memset(&context_, 0, sizeof(unw_context_t));
    memset(cursor, 0, sizeof(unw_cursor_t));
  }

  inline bool unwind(siginfo_t *siginfo, void *sigcontext, uint64_t *buffer, uint8_t max_frame_size, uint8_t &real_frame_size)
  {
    extract_from_context(sigcontext);

    real_frame_size = 0;

    int ret = unw_init_local(cursor, &context_);
    if (ret < 0)
    {
      return false;
    }

    do
    {
      unw_word_t pc;
      ret = unw_get_reg(cursor, UNW_REG_IP, &pc);
      /*
            unw_word_t offset;
            char symbol[512];
            if (ret < 0)
            {
              break;
            }
            if (unw_get_proc_name(cursor, symbol, sizeof(symbol), &offset) == 0)
            {
              WARNING("[%lx] %s + 0x%lx\n", (unsigned long)pc, symbol, (unsigned long)offset);
            }
            else
            {
              WARNING("[%lx] <unknown>\n", (unsigned long)pc);
            }
      */

      buffer[real_frame_size] = pc;
      ret = unw_step(cursor);
      real_frame_size++;
    } while (ret > 0 && real_frame_size < max_frame_size);

    return true;
  }

private:
  inline void extract_from_context(void *sigcontext)
  {
    unw_tdep_context_t *context = reinterpret_cast<unw_tdep_context_t *>(&context_);
#if defined(__arm__)
    const ucontext_t *uc = reinterpret_cast<const ucontext_t *>(sigcontext);
    context->regs[0] = uc->uc_mcontext.arm_r0;
    context->regs[1] = uc->uc_mcontext.arm_r1;
    context->regs[2] = uc->uc_mcontext.arm_r2;
    context->regs[3] = uc->uc_mcontext.arm_r3;
    context->regs[4] = uc->uc_mcontext.arm_r4;
    context->regs[5] = uc->uc_mcontext.arm_r5;
    context->regs[6] = uc->uc_mcontext.arm_r6;
    context->regs[7] = uc->uc_mcontext.arm_r7;
    context->regs[8] = uc->uc_mcontext.arm_r8;
    context->regs[9] = uc->uc_mcontext.arm_r9;
    context->regs[10] = uc->uc_mcontext.arm_r10;
    context->regs[11] = uc->uc_mcontext.arm_fp;
    context->regs[12] = uc->uc_mcontext.arm_ip;
    context->regs[13] = uc->uc_mcontext.arm_sp;
    context->regs[14] = uc->uc_mcontext.arm_lr;
    context->regs[15] = uc->uc_mcontext.arm_pc;
#elif defined(__x86_64__)
#include <sys/ucontext.h>
    typedef struct ucontext ucontext_t;
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