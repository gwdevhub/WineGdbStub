#include "packet.h"

#include <array>

namespace gdbstub {

namespace {

std::uint8_t checksum(std::string_view payload) {
    std::uint8_t sum = 0;
    for (const char c : payload) {
        sum = static_cast<std::uint8_t>(sum + static_cast<std::uint8_t>(c));
    }
    return sum;
}

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

std::optional<std::string> frame(std::string_view payload) {
    constexpr std::array<char, 16> digits{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    const std::uint8_t sum = checksum(payload);
    std::string out;
    out.reserve(payload.size() + 4);
    out += '$';
    out += payload;
    out += '#';
    out += digits[sum >> 4];
    out += digits[sum & 0xF];
    return out;
}

std::optional<Received> nextPacket(std::string_view buffer) {
    const std::size_t start = buffer.find('$');
    if (start == std::string_view::npos) {
        return std::nullopt;
    }
    const std::size_t end = buffer.find('#', start);
    if (end == std::string_view::npos || buffer.size() < end + 3) {
        return std::nullopt;
    }
    const int high = hexValue(buffer[end + 1]);
    const int low = hexValue(buffer[end + 2]);
    const std::string_view payload = buffer.substr(start + 1, end - start - 1);
    const bool valid = high >= 0 && low >= 0 && checksum(payload) == static_cast<std::uint8_t>((high << 4) | low);
    return Received{std::string(payload), valid, end + 3};
}

std::string toHex(const std::uint8_t* data, std::size_t length) {
    constexpr std::array<char, 16> digits{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string out;
    out.reserve(length * 2);
    for (std::size_t i = 0; i < length; i++) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0xF];
    }
    return out;
}

std::string fromHex(std::string_view text) {
    std::string out;
    for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
        const int high = hexValue(text[i]);
        const int low = hexValue(text[i + 1]);
        if (high < 0 || low < 0) {
            break;
        }
        out += static_cast<char>((high << 4) | low);
    }
    return out;
}

std::optional<std::uint64_t> parseHex(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        const int digit = hexValue(c);
        if (digit < 0) {
            return std::nullopt;
        }
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    return value;
}

}  // namespace gdbstub
