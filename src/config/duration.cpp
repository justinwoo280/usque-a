#include "duration.h"

#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cmath>

namespace usque {

static double parse_unit_factor(const char *s, int &consumed) {
    if (s[0] == 'n' && s[1] == 's') {
        consumed = 2;
        return 1e-6; // nanoseconds to milliseconds
    }
    if ((s[0] == 'u' || (unsigned char)s[0] == 0xC2) &&
        (s[1] == 's' || ((unsigned char)s[0] == 0xC2 && (unsigned char)s[1] == 0xB5 && s[2] == 's'))) {
        if ((unsigned char)s[0] == 0xC2) {
            consumed = 3;
        } else {
            consumed = 2;
        }
        return 1e-3; // microseconds to milliseconds
    }
    if (s[0] == 'm' && s[1] == 's') {
        consumed = 2;
        return 1.0;
    }
    if (s[0] == 's' && (s[1] == '\0' || s[1] == ' ')) {
        consumed = 1;
        return 1000.0;
    }
    if (s[0] == 'm' && (s[1] == '\0' || s[1] == ' ')) {
        consumed = 1;
        return 60000.0;
    }
    if (s[0] == 'h' && (s[1] == '\0' || s[1] == ' ')) {
        consumed = 1;
        return 3600000.0;
    }
    consumed = 0;
    return 0.0;
}

int64_t parse_duration_ms(const std::string &s, int64_t default_ms) {
    if (s.empty()) return default_ms;

    const char *p = s.c_str();
    double total_ns = 0.0;
    bool parsed_any = false;

    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        // skip leading 's' only at end
        if (*p == 's' && (p[1] == '\0' || p[1] == ' ')) {
            int consumed = 0;
            double factor = parse_unit_factor(p, consumed);
            if (consumed == 0) return default_ms;
            total_ns += 1.0 * factor; // implied 1 unit
            parsed_any = true;
            p += consumed;
            continue;
        }

        char *end = nullptr;
        double num = std::strtod(p, &end);
        if (end == p) return default_ms;

        p = end;
        while (*p == ' ') p++;

        int consumed = 0;
        double factor = parse_unit_factor(p, consumed);
        if (consumed == 0) {
            if (!parsed_any) return default_ms;
            break;
        }

        total_ns += num * factor;
        parsed_any = true;
        p += consumed;
    }

    if (!parsed_any) return default_ms;
    return static_cast<int64_t>(total_ns);
}

std::string format_duration_ms(int64_t ms) {
    if (ms <= 0) return "0s";

    std::string result;

    if (ms >= 3600000) {
        int64_t h = ms / 3600000;
        ms %= 3600000;
        result += std::to_string(h) + "h";
    }
    if (ms >= 60000) {
        int64_t m = ms / 60000;
        ms %= 60000;
        result += std::to_string(m) + "m";
    }
    if (ms >= 1000) {
        int64_t sec = ms / 1000;
        ms %= 1000;
        result += std::to_string(sec) + "s";
    }
    if (ms > 0) {
        result += std::to_string(ms) + "ms";
    }

    return result;
}

} // namespace usque
