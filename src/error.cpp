#include "usque/error.h"

extern "C" const char* usque_error_name(usque_error_t err) {
    switch (err) {
        case USQUE_OK:              return "USQUE_OK";
        case USQUE_ERR_INVALID_ARG: return "USQUE_ERR_INVALID_ARG";
        case USQUE_ERR_IO:          return "USQUE_ERR_IO";
        case USQUE_ERR_PARSE:       return "USQUE_ERR_PARSE";
        case USQUE_ERR_VALIDATE:    return "USQUE_ERR_VALIDATE";
        case USQUE_ERR_NOT_FOUND:   return "USQUE_ERR_NOT_FOUND";
        case USQUE_ERR_INTERNAL:    return "USQUE_ERR_INTERNAL";
        default:                    return "USQUE_ERR_UNKNOWN";
    }
}
