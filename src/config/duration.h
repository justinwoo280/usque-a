#pragma once

#include <cstdint>
#include <string>

namespace usque {

// Parse a Go-style duration string to milliseconds.
// Returns default_ms on empty input or parse error.
// Supports: "ns", "us", "ms", "s", "m", "h"
// Examples: "30s" -> 30000, "10ms" -> 10, "1m" -> 60000
int64_t parse_duration_ms(const std::string &s, int64_t default_ms);

// Format milliseconds back to a Go-style duration string.
// Examples: 30000 -> "30s", 10 -> "10ms", 60000 -> "1m0s"
std::string format_duration_ms(int64_t ms);

} // namespace usque
