#ifndef RUNTIME_SIMULATOR
#define RUNTIME_SIMULATOR

#include "instruction_dependancy.h"

#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>
#include <log.h>
#include <memory>
#include <stdint.h>
#include <ucontext.h>

// interface for the different execution engine to adpat
class RuntimeSimulator {
public:
	// Initialize the execution engine. This method should be called only once.
	virtual int open() = 0;

	// Clean up and release resources associated with the execution engine.
	// This method should be called only during the destruction of the object.
	virtual int close() = 0;

	// Sets the runtime context for the execution engine.
	// This method allows the engine to use the provided context for execution.
	virtual int set_runtime_context(ucontext_t &uc) = 0;

	// Appends code to the execution engine at the specified address.
	// The code is provided as a block of memory with a given size.
	virtual int append_code(int *addr, size_t size) = 0;

	// Executes the code that has been appended to the execution engine.
	virtual int execute() = 0;

	// Queries the memory of the execution engine at the specified address.
	// The result is stored in the provided data buffer.
	virtual int query_mem(uint64_t addr, int *data) = 0;

	virtual uint64_t get_register(uint8_t register_no) = 0;

	virtual uint64_t get_pc() = 0;

	virtual void reset() = 0;

	virtual void set_halt_pc(uint64_t pc) = 0;
};

class MyEnvironment final : public Dynarmic::A64::UserCallbacks {
public:
	uint64_t ticks_left = 0;

	// TODO: it's interesting about sharing the memory between different threads
	std::map<uint64_t, uint8_t> memory {};

	uint64_t halt_pc = 0;

	bool should_halt = false;

	void clearMemory() {
		memory.clear();
	}

	uint8_t MemoryRead8(uint64_t vaddr) override {
		auto iter = memory.find(vaddr);
		if (iter == memory.end()) {
			// TODO: add some validation check
			// INFO("try to read unmapped memory %#lx", vaddr);
			return *(uint8_t *)(vaddr);
		}
		return memory[vaddr];
	}

	uint16_t MemoryRead16(uint64_t vaddr) override {
		return uint16_t(MemoryRead8(vaddr)) | uint16_t(MemoryRead8(vaddr + 1)) << 8;
	}

	uint32_t MemoryRead32(uint64_t vaddr) override {
		return uint32_t(MemoryRead16(vaddr)) | uint32_t(MemoryRead16(vaddr + 2)) << 16;
	}

	uint64_t MemoryRead64(uint64_t vaddr) override {
		return uint64_t(MemoryRead32(vaddr)) | uint64_t(MemoryRead32(vaddr + 4)) << 32;
	}

	std::array<uint64_t, 2> MemoryRead128(uint64_t vaddr) override {
		return {MemoryRead64(vaddr), MemoryRead64(vaddr + 8)};
	}

	void MemoryWrite8(uint64_t vaddr, uint8_t value) override {
		// INFO("MemoryWrite8: vaddr=0x%lx, value=0x%02x", vaddr, value);
		memory[vaddr] = value;
	}

	void MemoryWrite16(uint64_t vaddr, uint16_t value) override {
		MemoryWrite8(vaddr, uint8_t(value));
		MemoryWrite8(vaddr + 1, uint8_t(value >> 8));
	}

	void MemoryWrite32(uint64_t vaddr, uint32_t value) override {
		MemoryWrite16(vaddr, uint16_t(value));
		MemoryWrite16(vaddr + 2, uint16_t(value >> 16));
	}

	void MemoryWrite64(uint64_t vaddr, uint64_t value) override {
		MemoryWrite32(vaddr, uint32_t(value));
		MemoryWrite32(vaddr + 4, uint32_t(value >> 32));
	}

	void MemoryWrite128(uint64_t vaddr, std::array<uint64_t, 2> value) override {
		MemoryWrite64(vaddr, value[0]);
		MemoryWrite64(vaddr + 8, value[1]);
	}

	void InterpreterFallback(uint64_t, size_t) override {
		// This is never called in practice.
		std::terminate();
	}

	void CallSVC(uint32_t) override {
		// Do something.
	}

	void ExceptionRaised(uint64_t, Dynarmic::A64::Exception) override {
		cpu->HaltExecution();
	}

	void AddTicks(std::uint64_t ticks) override {
		if (ticks > ticks_left) {
			ticks_left = 0;
			return;
		}
		ticks_left -= ticks;
	}

	std::uint64_t GetTicksRemaining() override {
		return ticks_left;
	}

	std::uint64_t GetCNTPCT() override {
		return 0;
	}

	Dynarmic::A64::Jit *cpu;
};

class ArmRuntimeSimulator : public RuntimeSimulator {
public:
	ArmRuntimeSimulator() {
		config.callbacks = &env;
		jit = std::unique_ptr<Dynarmic::A64::Jit>(new Dynarmic::A64::Jit(config));
		env.cpu = jit.get();
	}
	~ArmRuntimeSimulator() {
		close();
	}

	int open() override {
		if (initialized) {
			return -1;
		}
		initialized = true;

		env.ticks_left = 1;
		// Append NOP instruction at address 0 to warm up
		constexpr uint32_t nop_instruction = 0xD503201F; // ARM64 NOP instruction
		// Write NOP instructions at sequential 4-byte aligned addresses
		env.MemoryWrite32(0, 0x14000004); // B #16
		jit->SetPC(0);
		jit->Run();
		return 0;
	}

	int close() override {
		if (!initialized) {
			return -1;
		}
		initialized = false;
		return 0;
	}

	int set_runtime_context(ucontext_t &uc) override {
		if (!initialized) {
			return -1;
		}
		// Set up the initial CPU state from the ucontext
		for (int i = 0; i < 31; ++i) {
			// INFO("Setting register %d to 0x%lx", i, uc.uc_mcontext.regs[i]);
			jit->SetRegister(i, uc.uc_mcontext.regs[i]);
		}

		// Set up the special registers
		// INFO("Setting PC to 0x%lx", uc.uc_mcontext.pc);
		jit->SetPC(uc.uc_mcontext.pc);
		// INFO("Setting SP to 0x%lx", uc.uc_mcontext.sp);
		jit->SetSP(uc.uc_mcontext.sp);
		// INFO("Setting PSTATE to 0x%lx", uc.uc_mcontext.pstate);
		jit->SetPstate(uc.uc_mcontext.pstate);

		return 0;
	}

	int append_code(int *addr, size_t size = 4) override {
		if (!initialized) {
			return -1;
		}

		// TODO: we assuem that one instrution corresponds to one tick
		env.ticks_left++;
		// Map the memory into the JIT's address space
		switch (size) {
		case 4: // 32-bit instruction
			env.MemoryWrite32(reinterpret_cast<uint64_t>(addr), *addr);
			break;
		case 2: // 16-bit instruction (Thumb)
			env.MemoryWrite16(reinterpret_cast<uint64_t>(addr), static_cast<uint16_t>(*addr));
			break;
		default:
			ERROR("Unsupported instruction size: %zu", size);
			return -1;
		}
		return 0;
	}

	int execute() override {
		if (!initialized) {
			return -1;
		}
		try {
			auto reason = jit->Run();
			// INFO("Execution stopped with reason: %ld", static_cast<uint64_t>(reason));
			return 0;
		} catch (const std::exception &e) {
			ERROR("Execution failed: %s", e.what());
			return -1;
		}
	}

	int query_mem(uint64_t addr, int *data) override {
		if (!initialized) {
			return -1;
		}
		try {
			*data = env.MemoryRead32(addr);
			return 0;
		} catch (const std::exception &e) {
			ERROR("Memory read failed: %s", e.what());
			return -1;
		}
	}

	virtual uint64_t get_register(uint8_t register_no) override {
		if (!initialized) {
			return 0;
		}

		try {
			return jit->GetRegister(register_no);
		} catch (const std::exception &e) {
			ERROR("Failed to get register %d: %s", register_no, e.what());
			return 0;
		}
	}

	virtual uint64_t get_pc() override {
		return jit->GetPC();
	}

	virtual void reset() override {
		// don't execute any code
		env.ticks_left = 0;

		// jit->Reset();
		// jit->ClearCache();
	}

	virtual void set_halt_pc(uint64_t pc) override {
		env.halt_pc = pc;
	}

	void print_regs() const {
		return;
		for (int i = 0; i < 31; i++) {
			INFO("X%d: %016lx", i, jit->GetRegister(i));
		}
		INFO("SP: %016lx", jit->GetRegister(31));
		INFO("PC: %016lx", jit->GetPC());
	}

private:
	std::unique_ptr<Dynarmic::A64::Jit> jit;
	MyEnvironment env;
	Dynarmic::A64::UserConfig config;
	bool initialized = false;
};
#endif