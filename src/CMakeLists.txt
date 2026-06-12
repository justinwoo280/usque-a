# External library paths — support both layouts:
#   Local dev:  ../boringssl, ../ngtcp2, ../nghttp3 (siblings)
#   CI/script:  deps/boringssl, deps/ngtcp2, deps/nghttp3 (subdirectory)
if(EXISTS "${CMAKE_SOURCE_DIR}/deps/boringssl/build/libssl.a")
    set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/deps/boringssl")
    set(NGTCP2_DIR "${CMAKE_SOURCE_DIR}/deps/ngtcp2")
    set(NGHTTP3_DIR "${CMAKE_SOURCE_DIR}/deps/nghttp3")
else()
    set(BORINGSSL_DIR "${CMAKE_SOURCE_DIR}/../boringssl")
    set(NGTCP2_DIR "${CMAKE_SOURCE_DIR}/../ngtcp2")
    set(NGHTTP3_DIR "${CMAKE_SOURCE_DIR}/../nghttp3")
endif()

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
    target_link_libraries(usque-a PUBLIC ws2_32 iphlpapi)
elseif(APPLE)
    target_sources(usque-a PRIVATE tun/tun_darwin.c tun/route_bsd.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    target_sources(usque-a PRIVATE tun/tun_freebsd.c tun/route_bsd.c)
else()
    # Linux and other Unix
    target_sources(usque-a PRIVATE tun/tun_linux.c tun/route_linux.c)
endif()

# Find libev (Homebrew on macOS, libev-dev on Linux)
find_path(LIBEV_INCLUDE_DIR ev.h
    HINTS /opt/homebrew/include /usr/local/include
)
find_library(LIBEV_LIBRARY NAMES ev
    HINTS /opt/homebrew/lib /usr/local/lib
)
if(NOT LIBEV_INCLUDE_DIR OR NOT LIBEV_LIBRARY)
    message(FATAL_ERROR "libev not found. Install with: brew install libev (macOS) or apt install libev-dev (Linux)")
endif()

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
        ${LIBEV_INCLUDE_DIR}
)

target_link_libraries(usque-a PUBLIC
    rapidjson
    ${NGTCP2_DIR}/build/lib/libngtcp2.a
    ${NGTCP2_DIR}/build/crypto/boringssl/libngtcp2_crypto_boringssl.a
    ${NGHTTP3_DIR}/build/lib/libnghttp3.a
    ${BORINGSSL_DIR}/build/libssl.a
    ${BORINGSSL_DIR}/build/libcrypto.a
    ${LIBEV_LIBRARY}
    pthread
)

set_target_properties(usque-a PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_compile_definitions(usque-a PRIVATE USQUE_BUILDING_LIBRARY)

# Main executable
add_executable(usque-a-bin main.cpp)
set_target_properties(usque-a-bin PROPERTIES OUTPUT_NAME usque-a-cli)
target_link_libraries(usque-a-bin PRIVATE usque-a rapidjson)
