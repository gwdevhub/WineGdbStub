#include "debugger.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstring>
#include <map>
#include <vector>

namespace gdbstub::debugger {

namespace {

constexpr std::uint8_t kInt3 = 0xCC;
constexpr DWORD kTrapFlag = 0x100;

struct State {
    CRITICAL_SECTION lock{};
    std::map<std::uint32_t, std::uint8_t> breakpoints;
    std::vector<HANDLE> suspended;
    std::vector<DWORD> suspendedIds;
    std::uint32_t excludedThread = 0;
    bool stopped = false;
    bool blockedInHandler = false;
    DWORD stopThreadId = 0;
    bool stepRequested = false;
    bool stepInProgress = false;
    std::uint32_t stepAddress = 0;
    CONTEXT stopContext{};
    HANDLE stopEvent = nullptr;
    HANDLE resumeEvent = nullptr;
    bool installed = false;
};

State gState;

bool readByte(std::uint32_t address, std::uint8_t& value) {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), &value, 1, &read) && read == 1;
}

bool writeByte(std::uint32_t address, std::uint8_t value) {
    SIZE_T written = 0;
    return WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)), &value, 1, &written) && written == 1;
}

void suspendOthers() {
    const DWORD self = GetCurrentThreadId();
    const DWORD process = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    THREADENTRY32 entry{sizeof entry};
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != process || entry.th32ThreadID == self || entry.th32ThreadID == gState.excludedThread) {
                continue;
            }
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
            if (thread && SuspendThread(thread) != static_cast<DWORD>(-1)) {
                gState.suspended.push_back(thread);
                gState.suspendedIds.push_back(entry.th32ThreadID);
            } else if (thread) {
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

void resumeOthers() {
    for (HANDLE thread : gState.suspended) {
        ResumeThread(thread);
        CloseHandle(thread);
    }
    gState.suspended.clear();
    gState.suspendedIds.clear();
}

void enterStop(CONTEXT* context) {
    EnterCriticalSection(&gState.lock);
    gState.stopContext = *context;
    gState.stopped = true;
    gState.stopThreadId = GetCurrentThreadId();
    gState.blockedInHandler = true;
    suspendOthers();
    SetEvent(gState.stopEvent);
    LeaveCriticalSection(&gState.lock);
    WaitForSingleObject(gState.resumeEvent, INFINITE);
}

LONG CALLBACK onException(EXCEPTION_POINTERS* info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    CONTEXT* context = info->ContextRecord;

    if (code == EXCEPTION_BREAKPOINT) {
        const auto address = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress));
        EnterCriticalSection(&gState.lock);
        const bool ours = gState.breakpoints.count(address) != 0;
        LeaveCriticalSection(&gState.lock);
        if (!ours) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        context->Eip = address;
        enterStop(context);
        EnterCriticalSection(&gState.lock);
        const bool step = gState.stepRequested;
        std::uint8_t original = 0;
        const auto found = gState.breakpoints.find(address);
        if (found != gState.breakpoints.end()) {
            original = found->second;
            writeByte(address, original);
        }
        context->EFlags |= kTrapFlag;
        gState.stepInProgress = true;
        gState.stepAddress = address;
        gState.stepRequested = step;
        LeaveCriticalSection(&gState.lock);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP && gState.stepInProgress) {
        EnterCriticalSection(&gState.lock);
        gState.stepInProgress = false;
        const std::uint32_t address = gState.stepAddress;
        if (gState.breakpoints.count(address)) {
            writeByte(address, kInt3);
        }
        context->EFlags &= ~kTrapFlag;
        const bool step = gState.stepRequested;
        LeaveCriticalSection(&gState.lock);
        if (step) {
            enterStop(context);
            EnterCriticalSection(&gState.lock);
            gState.stepRequested = false;
            LeaveCriticalSection(&gState.lock);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

void install() {
    if (gState.installed) {
        return;
    }
    InitializeCriticalSection(&gState.lock);
    gState.stopEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    gState.resumeEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    AddVectoredExceptionHandler(1, onException);
    gState.installed = true;
}

void excludeThread(std::uint32_t threadId) {
    gState.excludedThread = threadId;
}

bool insertBreakpoint(std::uint32_t address) {
    EnterCriticalSection(&gState.lock);
    bool ok = false;
    if (gState.breakpoints.count(address)) {
        ok = true;
    } else {
        std::uint8_t original = 0;
        if (readByte(address, original) && writeByte(address, kInt3)) {
            gState.breakpoints[address] = original;
            ok = true;
        }
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

bool removeBreakpoint(std::uint32_t address) {
    EnterCriticalSection(&gState.lock);
    bool ok = false;
    const auto found = gState.breakpoints.find(address);
    if (found != gState.breakpoints.end()) {
        ok = writeByte(address, found->second);
        gState.breakpoints.erase(found);
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

bool isStopped() {
    EnterCriticalSection(&gState.lock);
    const bool stopped = gState.stopped;
    LeaveCriticalSection(&gState.lock);
    return stopped;
}

bool readRegisters(Registers& out) {
    EnterCriticalSection(&gState.lock);
    const bool ok = gState.stopped;
    if (ok) {
        const CONTEXT& c = gState.stopContext;
        const std::uint32_t values[kRegisterCount] = {c.Eax, c.Ecx, c.Edx, c.Ebx, c.Esp, c.Ebp, c.Esi, c.Edi,
                                                     c.Eip, c.EFlags, c.SegCs, c.SegSs, c.SegDs, c.SegEs, c.SegFs, c.SegGs};
        std::memcpy(out, values, sizeof values);
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

bool resume(bool singleStep) {
    EnterCriticalSection(&gState.lock);
    const bool ok = gState.stopped;
    if (ok) {
        gState.stopped = false;
        gState.stepRequested = singleStep;
        const bool wakeHandler = gState.blockedInHandler;
        gState.blockedInHandler = false;
        resumeOthers();
        if (wakeHandler) {
            SetEvent(gState.resumeEvent);
        }
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

bool waitForStop(std::uint32_t timeoutMs) {
    return WaitForSingleObject(gState.stopEvent, timeoutMs) == WAIT_OBJECT_0;
}

bool interrupt() {
    EnterCriticalSection(&gState.lock);
    bool ok = gState.stopped;
    if (!ok) {
        suspendOthers();
        if (!gState.suspended.empty()) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            ok = GetThreadContext(gState.suspended.front(), &context) != 0;
            if (ok) {
                gState.stopContext = context;
                gState.stopped = true;
                gState.stopThreadId = gState.suspendedIds.front();
            }
        }
        if (!ok) {
            resumeOthers();
        }
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

bool threadInformationBlock(std::uint32_t& address) {
    EnterCriticalSection(&gState.lock);
    bool ok = false;
    if (gState.stopped && gState.stopThreadId) {
        HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, gState.stopThreadId);
        if (thread) {
            LDT_ENTRY entry{};
            if (GetThreadSelectorEntry(thread, gState.stopContext.SegFs, &entry)) {
                address = entry.BaseLow | (static_cast<std::uint32_t>(entry.HighWord.Bytes.BaseMid) << 16) |
                          (static_cast<std::uint32_t>(entry.HighWord.Bytes.BaseHi) << 24);
                ok = true;
            }
            CloseHandle(thread);
        }
    }
    LeaveCriticalSection(&gState.lock);
    return ok;
}

void detach() {
    std::vector<std::uint32_t> addresses;
    EnterCriticalSection(&gState.lock);
    for (const auto& [address, original] : gState.breakpoints) {
        addresses.push_back(address);
    }
    LeaveCriticalSection(&gState.lock);
    for (const std::uint32_t address : addresses) {
        removeBreakpoint(address);
    }
    if (isStopped()) {
        resume(false);
    }
}

}  // namespace gdbstub::debugger
