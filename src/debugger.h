#pragma once

#include <cstdint>
#include <optional>

namespace gdbstub::debugger {

// Registers in GDB's i386 order: eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs.
inline constexpr std::size_t kRegisterCount = 16;
using Registers = std::uint32_t[kRegisterCount];

void install();
void excludeThread(std::uint32_t threadId);
bool insertBreakpoint(std::uint32_t address);
bool removeBreakpoint(std::uint32_t address);
bool isStopped();
bool readRegisters(Registers& out);
bool resume(bool singleStep);
bool waitForStop(std::uint32_t timeoutMs);
bool interrupt();
bool threadInformationBlock(std::uint32_t& address);
void detach();

}  // namespace gdbstub::debugger
