#ifndef USQUE_VERSION_H
#define USQUE_VERSION_H

#define USQUE_VERSION_MAJOR 0
#define USQUE_VERSION_MINOR 1
#define USQUE_VERSION_PATCH 0
#define USQUE_VERSION_STRING "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

const char* usque_version_string(void);
int usque_version_major(void);
int usque_version_minor(void);
int usque_version_patch(void);

#ifdef __cplusplus
}
#endif

#endif /* USQUE_VERSION_H */
