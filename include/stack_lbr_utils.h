#ifndef STACK_LBR_UTILS
#define STACK_LBR_UTILS
#include <cassert>
#include <cstdint>
#include <ostream>
#include <string.h>

constexpr int MAX_LBR_SIZE = 16;
constexpr int MAX_FRAME_SIZE = 16;
constexpr int MAX_STACK_LBR_BUFFER_SIZE = 1024; // 1KB

/**
 * StackLBREntry contains a single run of complete branch tracing and
 * call stack.
 *
 * StackLBREntry only needs to be serialized to the buffer, we will not
 * deserialize StackLBREntry.
 */
class StackLBREntry
{
public:
  StackLBREntry() = default;

  bool serialize(uint8_t *&current, int buffer_size)
  {
    if (buffer_size < get_total_size())
    {
      return false; // Buffer is too small to hold the serialized data
    }

    // Serialize stack_sz_
    memcpy(current, &stack_sz_, sizeof(stack_sz_));
    current += sizeof(stack_sz_);

    // Serialize stack_ array
    memcpy(current, stack_, stack_sz_ * sizeof(uint64_t));
    current += stack_sz_ * sizeof(uint64_t);

    // Serialize branch_sz_
    memcpy(current, &branch_sz_, sizeof(branch_sz_));
    current += sizeof(branch_sz_);

    // Serialize branch_ array
    memcpy(current, branch_, branch_sz_ * 2 * sizeof(uint64_t));
    current += branch_sz_ * 2 * sizeof(uint64_t);

    return true;
  }

  /* for simplicity, stack_ is modified by raw pointer */
  uint64_t *get_stack_buffer() { return stack_; }
  void set_stack_size(uint8_t sz) { stack_sz_ = sz; }
  uint8_t get_stack_size() const { return stack_sz_; }

  bool is_full() const
  {
    return branch_sz_ >= MAX_LBR_SIZE;
  }

  bool add_branch(uint64_t from_addr, uint64_t to_addr)
  {
    if (branch_sz_ >= MAX_LBR_SIZE)
    {
      WARNING("there is no space to add new branch");
      return false;
    }

    uint64_t ind = branch_sz_ << 1;
    branch_[ind] = from_addr;
    branch_[ind + 1] = to_addr;
    branch_sz_++;
    return true;
  }

  // get the size of all data in bytes
  int get_max_size() const
  {
    return sizeof(stack_sz_) + sizeof(branch_sz_) + sizeof(stack_) + sizeof(branch_);
  }

  int get_total_size() const
  {
    return sizeof(stack_sz_) + sizeof(branch_sz_) + sizeof(uint64_t) * stack_sz_ + sizeof(uint64_t) * branch_sz_ * 2;
  }

  void reset()
  {
    if (stack_sz_)
    {
      debug_output();
    }

    stack_sz_ = 0;
    branch_sz_ = 0;
    // for efficiency, we skip memset buffers
  }

  void debug_output()
  {
#if defined(MY_DEBUG)
    // this function is only used for debug
    assert(stack_sz_ > 0 && "call stack should at least contains one sample");
    printf("-- call stack --\n");
    for (int i = 0; i < stack_sz_; i++)
    {
      printf("%#lx\n", stack_[i]);
    }

    printf("-- branch trace --\n");
    for (int i = 0; i < branch_sz_; i++)
    {
      printf("%#lx/%#lx\n", branch_[i << 1], branch_[(i << 1) + 1]);
    }
#endif
  }

private:
  uint8_t stack_sz_{0};
  uint8_t branch_sz_{0};
  uint64_t stack_[MAX_FRAME_SIZE];     // ip of call stack
  uint64_t branch_[MAX_LBR_SIZE << 1]; // [from_addr, to_addr]
};

class StackLBRBuffer
{
public:
  StackLBRBuffer() : cap_(MAX_STACK_LBR_BUFFER_SIZE)
  {
    buffer_ = new uint8_t[cap_];
    cur_ = buffer_;
  }

  ~StackLBRBuffer()
  {
    delete[] buffer_;
    buffer_ = nullptr;
    cur_ = nullptr;
  }

  void reset()
  {
    // it's unecessary to memset the memory
    cur_ = buffer_;
  }

  uint8_t *&get_current()
  {
    return cur_;
  }

  int get_buffer_size() const
  {
    return cap_ - (cur_ - buffer_);
  }

  void output(std::ostream &os)
  {
    uint8_t *current = buffer_;
    while (current < cur_)
    {
      // Read stack_sz_
      uint8_t stack_sz = *current;
      current += sizeof(stack_sz);

      // Read stack_ array and output each element on a new line
      uint64_t *stack = reinterpret_cast<uint64_t *>(current);
      for (uint8_t i = 0; i < stack_sz; ++i)
      {
        os << std::hex << std::showbase << stack[i] << std::endl;
      }
      current += stack_sz * sizeof(uint64_t);

      // Read branch_sz_
      uint8_t branch_sz = *current;
      current += sizeof(branch_sz);

      // Read branch_ array and output each pair in the given format
      // Output the branch trace in reverse order to be compatible with output of perf
      // TODO: output all the branch trace in one line
      uint64_t *branch = reinterpret_cast<uint64_t *>(current);
      for (int i = branch_sz - 1; i >= 0; --i)
      {
        os << std::hex << std::showbase << branch[i * 2] << "/" << branch[i * 2 + 1] << "/-/-/-/1" << std::endl;
      }
      os << std::endl;
      current += branch_sz * 2 * sizeof(uint64_t);
    }
  }

private:
  uint8_t *buffer_{nullptr};
  uint8_t *cur_{nullptr}; // cur_ points to the current position of buffer_
  int cap_{0};
};
#endif