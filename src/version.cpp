#include "usque/version.h"

extern "C" const char* usque_version_string(void) { return USQUE_VERSION_STRING; }
extern "C" int usque_version_major(void) { return USQUE_VERSION_MAJOR; }
extern "C" int usque_version_minor(void) { return USQUE_VERSION_MINOR; }
extern "C" int usque_version_patch(void) { return USQUE_VERSION_PATCH; }
