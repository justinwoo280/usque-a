#pragma once

#include "config_impl.h"
#include <string>

namespace usque {

// Returns empty string on success, error description on failure.
std::string validate(const FullConfig &cfg);

} // namespace usque
