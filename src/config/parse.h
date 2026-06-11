#pragma once

#include "config_impl.h"
#include <string>

namespace usque {

struct ParseResult {
    bool        success;
    FullConfig  config;
    std::string error;
};

ParseResult parse_json(const char *data, size_t len);
ParseResult parse_file(const char *path);

} // namespace usque
