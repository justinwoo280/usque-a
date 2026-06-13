# Helper: find a static library file checking both .a and .lib
function(find_static_lib RESULT_VAR DIR BASENAME)
    foreach(name "${BASENAME}.a" "${BASENAME}.lib")
        if(EXISTS "${DIR}/${name}")
            set(${RESULT_VAR} "${DIR}/${name}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    set(${RESULT_VAR} "${RESULT_VAR}-NOTFOUND" PARENT_SCOPE)
endfunction()

# External library paths — support both layouts:
#   Local dev:  ../boringssl, ../ngtcp2, ../nghttp3 (siblings)
#   CI/script:  deps/boringssl, deps/ngtcp2, deps/nghttp3 (subdirectory)
if(EXISTS "${CMAKE_SOURCE_DIR}/deps/boringssl/build")
    set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/deps/boringssl")
    set(NGTCP2_DIR "${CMAKE_SOURCE_DIR}/deps/ngtcp2")
    set(NGHTTP3_DIR "${CMAKE_SOURCE_DIR}/deps/nghttp3")
    set(LIBUV_DIR "${CMAKE_SOURCE_DIR}/deps/libuv")
else()
    set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/../boringssl")
    set(NGTCP2_DIR "${CMAKE_SOURCE_DIR}/../ngtcp2")
    set(NGHTTP3_DIR "${CMAKE_SOURCE_DIR}/../nghttp3")
    set(LIBUV_DIR "${CMAKE_SOURCE_DIR}/../libuv")
endif()

# ---- Find BoringSSL libraries (platform-aware) ----
find_static_lib(BORINGSSL_SSL_LIB "${BORINGSSL_DIR}/build" "libssl")
if(NOT BORINGSSL_SSL_LIB)
    find_static_lib(BORINGSSL_SSL_LIB "${BORINGSSL_DIR}/build" "ssl")
endif()
find_static_lib(BORINGSSL_CRYPTO_LIB "${BORINGSSL_DIR}/build" "libcrypto")
if(NOT BORINGSSL_CRYPTO_LIB)
    find_static_lib(BORINGSSL_CRYPTO_LIB "${BORINGSSL_DIR}/build" "crypto")
endif()

# ---- Find ngtcp2 libraries ----
find_static_lib(NGTCP2_LIB "${NGTCP2_DIR}/build/lib" "libngtcp2")
if(NOT NGTCP2_LIB)
    find_static_lib(NGTCP2_LIB "${NGTCP2_DIR}/build/lib" "ngtcp2")
endif()
if(NOT NGTCP2_LIB)
    # Autotools fallback
    find_static_lib(NGTCP2_LIB "${NGTCP2_DIR}/lib/.libs" "libngtcp2")
endif()
find_static_lib(NGTCP2_CRYPTO_BSSL_LIB "${NGTCP2_DIR}/build/crypto/boringssl" "libngtcp2_crypto_boringssl")
if(NOT NGTCP2_CRYPTO_BSSL_LIB)
    find_static_lib(NGTCP2_CRYPTO_BSSL_LIB "${NGTCP2_DIR}/build/crypto/boringssl" "ngtcp2_crypto_boringssl")
endif()
if(NOT NGTCP2_CRYPTO_BSSL_LIB)
    # Autotools fallback
    find_static_lib(NGTCP2_CRYPTO_BSSL_LIB "${NGTCP2_DIR}/crypto/boringssl" "libngtcp2_crypto_boringssl")
endif()

# ---- Find nghttp3 library ----
find_static_lib(NGHTTP3_LIB "${NGHTTP3_DIR}/build/lib" "libnghttp3")
if(NOT NGHTTP3_LIB)
    find_static_lib(NGHTTP3_LIB "${NGHTTP3_DIR}/build/lib" "nghttp3")
endif()
if(NOT NGHTTP3_LIB)
    # Autotools fallback (build/ is --prefix)
    find_static_lib(NGHTTP3_LIB "${NGHTTP3_DIR}/build/lib" "libnghttp3")
endif()

# ---- Find libuv ----
set(LIBUV_USE_SYSTEM FALSE)
find_static_lib(LIBUV_LIB "${LIBUV_DIR}/build" "libuv_a")
if(NOT LIBUV_LIB)
    find_static_lib(LIBUV_LIB "${LIBUV_DIR}/build" "uv_a")
endif()
if(NOT LIBUV_LIB)
    find_static_lib(LIBUV_LIB "${LIBUV_DIR}/build" "libuv")
endif()
if(NOT LIBUV_LIB)
    # Fallback to system libuv
    find_path(LIBUV_INCLUDE_DIR uv.h HINTS /opt/homebrew/include /usr/local/include /usr/include)
    find_library(LIBUV_LIB NAMES uv_a uv HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIB)
        message(FATAL_ERROR "libuv not found. Run ./deps.sh all or install libuv-dev")
    endif()
    set(LIBUV_USE_SYSTEM TRUE)
endif()

# ---- Main library ----
add_library(usque-a
    error.cpp
    version.cpp
    config/config.cpp
    config/parse.cpp
    config/duration.cpp
    config/defaults.cpp
    config/validate.cpp
    config/serialize.cpp
    connectip/connect_ip.c
    transport/tls_setup.cpp
    transport/http3_connect.cpp
    transport/quic_engine.cpp
    tunnel.cpp
    tun/dns_hijack.c
    api/https_client.cpp
    api/register.cpp
)

# Platform-specific TUN/route
if(WIN32)
    target_sources(usque-a PRIVATE tun/tun_windows.c tun/route_windows.c)
elseif(APPLE)
    target_sources(usque-a PRIVATE tun/tun_darwin.c tun/route_bsd.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    target_sources(usque-a PRIVATE tun/tun_freebsd.c tun/route_bsd.c)
else()
    target_sources(usque-a PRIVATE tun/tun_linux.c tun/route_linux.c)
endif()

# Include directories
target_include_directories(usque-a BEFORE
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${BORINGSSL_DIR}/include
        ${NGTCP2_DIR}/lib/includes
        ${NGTCP2_DIR}/crypto/includes
        ${NGTCP2_DIR}/build/lib/includes
        ${NGHTTP3_DIR}/lib/includes
        ${NGHTTP3_DIR}/build/lib/includes
)

if(LIBUV_USE_SYSTEM)
    target_include_directories(usque-a PRIVATE ${LIBUV_INCLUDE_DIR})
else()
    target_include_directories(usque-a BEFORE PRIVATE ${LIBUV_DIR}/include)
endif()

# Link libraries
target_link_libraries(usque-a PUBLIC
    rapidjson
    ${NGTCP2_LIB}
    ${NGTCP2_CRYPTO_BSSL_LIB}
    ${NGHTTP3_LIB}
    ${BORINGSSL_SSL_LIB}
    ${BORINGSSL_CRYPTO_LIB}
    ${LIBUV_LIB}
)

# Platform-specific link libraries
if(WIN32)
    target_link_libraries(usque-a PUBLIC ws2_32 psapi iphlpapi userenv crypt32)
elseif(APPLE)
    find_library(COREFOUNDATION CoreFoundation)
    find_library(SECURITY Security)
    target_link_libraries(usque-a PUBLIC ${COREFOUNDATION} ${SECURITY})
else()
    target_link_libraries(usque-a PUBLIC pthread)
endif()

set_target_properties(usque-a PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_compile_definitions(usque-a PRIVATE USQUE_BUILDING_LIBRARY)
if(WIN32)
    target_compile_definitions(usque-a PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# Main executable
add_executable(usque-a-bin main.cpp)
set_target_properties(usque-a-bin PROPERTIES OUTPUT_NAME usque-a-cli)
target_link_libraries(usque-a-bin PRIVATE usque-a rapidjson)
