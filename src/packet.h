#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace gdbstub {

std::optional<std::string> frame(std::string_view payload);

struct Received {
    std::string payload;
    bool valid;
    std::size_t consumed;
};

std::optional<Received> nextPacket(std::string_view buffer);

std::string toHex(const std::uint8_t* data, std::size_t length);
std::string fromHex(std::string_view text);
std::optional<std::uint64_t> parseHex(std::string_view text);

}  // namespace gdbstub
