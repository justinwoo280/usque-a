#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>

// Access internal duration API directly
// Since tests link against usque-a, we use the C++ internal header
#include "../src/config/duration.h"

static int failures = 0;

static void check(const char *name, bool cond) {
    if (!cond) {
        std::printf("FAIL: %s\n", name);
        failures++;
    } else {
        std::printf("PASS: %s\n", name);
    }
}

int main() {
    using usque::parse_duration_ms;
    using usque::format_duration_ms;

    // Basic parsing
    check("30s = 30000ms",  parse_duration_ms("30s", 0) == 30000);
    check("10ms = 10ms",    parse_duration_ms("10ms", 0) == 10);
    check("1m = 60000ms",   parse_duration_ms("1m", 0) == 60000);
    check("1h = 3600000ms", parse_duration_ms("1h", 0) == 3600000);
    check("500us = 0ms",    parse_duration_ms("500us", 0) == 0); // sub-ms truncation
    check("100ns = 0ms",    parse_duration_ms("100ns", 0) == 0);

    // Empty and invalid
    check("empty -> default",   parse_duration_ms("", 999) == 999);
    check("invalid -> default", parse_duration_ms("abc", 42) == 42);

    // Fractional
    check("1.5s = 1500ms", parse_duration_ms("1.5s", 0) == 1500);
    check("0.5s = 500ms",  parse_duration_ms("0.5s", 0) == 500);

    // Formatting
    check("format 30000 = 30s",  format_duration_ms(30000) == "30s");
    check("format 10 = 10ms",    format_duration_ms(10) == "10ms");
    check("format 60000 = 1m",   format_duration_ms(60000) == "1m");
    check("format 0 = 0s",       format_duration_ms(0) == "0s");
    check("format 90000 = 1m30s", format_duration_ms(90000) == "1m30s");
    check("format 3661000 = 1h1m1s", format_duration_ms(3661000) == "1h1m1s");
    check("format 1005 = 1s5ms", format_duration_ms(1005) == "1s5ms");

    // Round-trip
    check("roundtrip 30s",  parse_duration_ms(format_duration_ms(30000), 0) == 30000);
    check("roundtrip 10ms", parse_duration_ms(format_duration_ms(10), 0) == 10);
    check("roundtrip 1m",   parse_duration_ms(format_duration_ms(60000), 0) == 60000);

    if (failures > 0) {
        std::printf("\n%d tests FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll duration tests passed\n");
    return 0;
}
