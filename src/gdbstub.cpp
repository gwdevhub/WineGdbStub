#include "gdbstub.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <tlhelp32.h>

#include "debugger.h"
#include "packet.h"

namespace gdbstub {

namespace {

struct Server {
    std::uint16_t port;
};

struct Outcome {
    std::optional<std::string> reply;
    std::string output;
    bool detach = false;
    bool resumed = false;
};

bool sendAll(SOCKET socket, const std::string& data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(socket, data.data() + sent, static_cast<int>(data.size() - sent), 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

bool readMemory(std::uint64_t address, std::size_t length, std::string& out) {
    std::string bytes(length, '\0');
    SIZE_T read = 0;
    const auto start = static_cast<std::uintptr_t>(address);
    if (length == 0 || !ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(start), bytes.data(), length, &read) || read != length) {
        return false;
    }
    out = toHex(reinterpret_cast<const std::uint8_t*>(bytes.data()), length);
    return true;
}

std::optional<std::pair<std::uint64_t, std::uint64_t>> parseAddressAndLength(const std::string& text) {
    const std::size_t comma = text.find(',');
    if (comma == std::string::npos) {
        return std::nullopt;
    }
    const auto address = parseHex(text.substr(0, comma));
    const auto length = parseHex(text.substr(comma + 1));
    if (!address || !length) {
        return std::nullopt;
    }
    return std::make_pair(*address, *length);
}

std::string handleMemoryRead(const std::string& payload) {
    const auto parsed = parseAddressAndLength(payload.substr(1));
    std::string hex;
    if (!parsed || !readMemory(parsed->first, static_cast<std::size_t>(parsed->second), hex)) {
        return "E14";
    }
    return hex;
}

std::string listModules() {
    std::string out;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "module list unavailable\n";
    }
    MODULEENTRY32W entry{sizeof entry};
    if (Module32FirstW(snapshot, &entry)) {
        do {
            std::string name;
            for (const wchar_t c : std::wstring(entry.szModule)) {
                name += static_cast<char>(c < 0x80 ? c : '?');
            }
            char line[512];
            std::snprintf(line, sizeof line, "0x%08zx 0x%08zx %s\n", reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
                          static_cast<std::size_t>(entry.modBaseSize), name.c_str());
            out += line;
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return out;
}

std::optional<std::uint32_t> preferredImageBase(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    std::uint8_t header[0x400]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, header, sizeof header, &read, nullptr);
    CloseHandle(file);
    if (!ok || read < 0x100 || header[0] != 'M' || header[1] != 'Z') {
        return std::nullopt;
    }
    std::uint32_t peOffset = 0;
    std::memcpy(&peOffset, header + 0x3C, 4);
    if (peOffset + 24 + 32 > read || std::memcmp(header + peOffset, "PE\0\0", 4) != 0) {
        return std::nullopt;
    }
    std::uint32_t imageBase = 0;
    std::memcpy(&imageBase, header + peOffset + 24 + 28, 4);
    return imageBase;
}

std::string moduleName() {
    const char* configured = std::getenv("GWSTUB_MODULE");
    return configured && *configured ? configured : "GWToolboxdll.dll";
}

std::string handleOffsets() {
    const std::string wanted = moduleName();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "";
    }
    MODULEENTRY32W entry{sizeof entry};
    std::string offset;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            std::string name;
            for (const wchar_t c : std::wstring(entry.szModule)) {
                name += static_cast<char>(c < 0x80 ? c : '?');
            }
            if (_stricmp(name.c_str(), wanted.c_str()) != 0) {
                continue;
            }
            const auto base = preferredImageBase(entry.szExePath);
            if (base) {
                const auto delta = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entry.modBaseAddr)) - *base;
                char text[64];
                std::snprintf(text, sizeof text, "Text=%x;Data=%x;Bss=%x", delta, delta, delta);
                offset = text;
            }
            break;
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return offset;
}

std::string runMonitor(const std::string& command) {
    if (command == "modules") {
        return listModules();
    }
    return "unknown monitor command: " + command + "\nusage: monitor modules\n";
}

std::string handleRegisters() {
    debugger::Registers registers{};
    if (!debugger::readRegisters(registers)) {
        return "E01";
    }
    std::string out;
    for (const std::uint32_t value : registers) {
        const std::uint8_t bytes[4] = {static_cast<std::uint8_t>(value), static_cast<std::uint8_t>(value >> 8),
                                       static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)};
        out += toHex(bytes, 4);
    }
    return out;
}

std::string handleBreakpoint(const std::string& payload) {
    const bool insert = payload[0] == 'Z';
    if (payload.size() < 2 || payload[1] != '0') {
        return "";
    }
    const auto parsed = parseAddressAndLength(payload.substr(3));
    if (!parsed) {
        return "E01";
    }
    const auto address = static_cast<std::uint32_t>(parsed->first);
    const bool ok = insert ? debugger::insertBreakpoint(address) : debugger::removeBreakpoint(address);
    return ok ? "OK" : "E01";
}

Outcome handle(const std::string& payload) {
    Outcome outcome;
    if (payload == "?") outcome.reply = "S05";
    else if (payload.rfind("qSupported", 0) == 0) outcome.reply = "PacketSize=4000";
    else if (payload == "qAttached") outcome.reply = "1";
    else if (payload == "qC") outcome.reply = "QC1";
    else if (payload == "qfThreadInfo") outcome.reply = "m1";
    else if (payload == "qsThreadInfo") outcome.reply = "l";
    else if (payload.rfind("H", 0) == 0) outcome.reply = "OK";
    else if (payload == "g") outcome.reply = handleRegisters();
    else if (payload == "qOffsets") outcome.reply = handleOffsets();
    else if (payload.rfind("qGetTIBAddr", 0) == 0) {
        std::uint32_t address = 0;
        if (debugger::threadInformationBlock(address)) {
            char hex[16];
            std::snprintf(hex, sizeof hex, "%x", address);
            outcome.reply = std::string(hex);
        } else {
            outcome.reply = "E01";
        }
    }
    else if (payload.rfind("qRcmd,", 0) == 0) {
        outcome.output = runMonitor(fromHex(payload.substr(6)));
        outcome.reply = "OK";
    }
    else if (payload.rfind("m", 0) == 0) outcome.reply = handleMemoryRead(payload);
    else if (payload.rfind("Z0,", 0) == 0 || payload.rfind("z0,", 0) == 0) outcome.reply = handleBreakpoint(payload);
    else if (payload == "c") {
        if (debugger::isStopped()) {
            debugger::resume(false);
        }
        outcome.resumed = true;
    }
    else if (payload == "s") {
        outcome.resumed = debugger::resume(true);
        if (!outcome.resumed) outcome.reply = "E01";
    }
    else if (payload == "D" || payload == "k") {
        debugger::detach();
        outcome.detach = true;
    }
    else outcome.reply = std::string();
    return outcome;
}

// Waits for the next stop while the client may still send packets (such as an interrupt).
bool waitForStop(SOCKET client) {
    for (;;) {
        if (debugger::waitForStop(100)) {
            return true;
        }
        fd_set readable{};
        FD_SET(client, &readable);
        timeval zero{};
        if (select(0, &readable, nullptr, nullptr, &zero) > 0) {
            char drain[256];
            const int n = recv(client, drain, sizeof drain, 0);
            if (n <= 0) {
                return false;
            }
            if (std::memchr(drain, 0x03, static_cast<std::size_t>(n))) {
                debugger::interrupt();
                return true;
            }
        }
    }
}

void serveClient(SOCKET client) {
    debugger::interrupt();
    std::string buffer;
    char chunk[4096];
    for (;;) {
        const int received = recv(client, chunk, sizeof chunk, 0);
        if (received <= 0) {
            debugger::detach();
            return;
        }
        buffer.append(chunk, static_cast<std::size_t>(received));
        if (buffer.find('\x03') != std::string::npos) {
            buffer.erase(buffer.find('\x03'), 1);
            debugger::interrupt();
            sendAll(client, *frame("S05"));
        }
        for (;;) {
            const auto packet = nextPacket(buffer);
            if (!packet) {
                break;
            }
            buffer.erase(0, packet->consumed);
            if (!packet->valid) {
                sendAll(client, "-");
                continue;
            }
            sendAll(client, "+");
            const Outcome outcome = handle(packet->payload);
            if (outcome.detach) {
                sendAll(client, *frame("OK"));
                return;
            }
            if (!outcome.output.empty()) {
                sendAll(client, *frame("O" + toHex(reinterpret_cast<const std::uint8_t*>(outcome.output.data()), outcome.output.size())));
            }
            if (outcome.reply) {
                sendAll(client, *frame(*outcome.reply));
            }
            if (outcome.resumed) {
                if (!waitForStop(client)) {
                    debugger::detach();
                    return;
                }
                sendAll(client, *frame("S05"));
            }
        }
    }
}

DWORD WINAPI serverThread(LPVOID param) {
    debugger::excludeThread(GetCurrentThreadId());
    const auto* server = static_cast<const Server*>(param);
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        return 1;
    }
    BOOL reuse = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof reuse);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(server->port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof address) != 0 || listen(listener, 1) != 0) {
        closesocket(listener);
        return 1;
    }
    for (;;) {
        const SOCKET client = accept(listener, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }
        serveClient(client);
        closesocket(client);
    }
}

Server gServer{};

}  // namespace

void start(const std::uint16_t port) {
    debugger::install();
    gServer.port = port;
    CreateThread(nullptr, 0, serverThread, &gServer, 0, nullptr);
}

}  // namespace gdbstub
