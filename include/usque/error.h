#ifndef USQUE_ERROR_H
#define USQUE_ERROR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum usque_error {
    USQUE_OK              = 0,
    USQUE_ERR_INVALID_ARG = 1,
    USQUE_ERR_IO          = 2,
    USQUE_ERR_PARSE       = 3,
    USQUE_ERR_VALIDATE    = 4,
    USQUE_ERR_NOT_FOUND   = 5,
    USQUE_ERR_INTERNAL    = 99
} usque_error_t;

const char* usque_error_name(usque_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_ERROR_H */
