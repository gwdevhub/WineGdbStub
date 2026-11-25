#include <windows.h>

#include <cstdio>

extern "C" __declspec(noinline) int hitMe(int value) {
    volatile int doubled = value * 2;
    return doubled;
}

int main() {
    if (!LoadLibraryA("WineGdbStub.dll")) {
        return 1;
    }
    std::printf("hitMe=%p\n", reinterpret_cast<void*>(&hitMe));
    std::fflush(stdout);
    int total = 0;
    for (int i = 0; i < 3000; i++) {
        total += hitMe(i);
        Sleep(100);
    }
    return total == 0;
}
