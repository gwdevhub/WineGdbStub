#include <windows.h>

#include <cstdlib>

#include "gdbstub.h"

namespace {

std::uint16_t portFromEnvironment() {
    char value[16];
    const DWORD length = GetEnvironmentVariableA("GWSTUB_PORT", value, sizeof value);
    if (length == 0 || length >= sizeof value) {
        return 2345;
    }
    return static_cast<std::uint16_t>(std::strtoul(value, nullptr, 10));
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        gdbstub::start(portFromEnvironment());
    }
    return TRUE;
}
