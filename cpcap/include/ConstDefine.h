#pragma once

#include <stdint.h>

namespace cpcap {
    constexpr uint32_t MAGIC_NUMBER = 0x123456;
    constexpr uint16_t MAJOR_VER = 0;
    constexpr uint16_t MINOR_VER = 1;

    constexpr uint32_t FILE_HEADER_SIZE = 64;

    constexpr uint8_t SUPPORT_ETH_HEADER = 0x1 << 0;
    constexpr uint8_t SUPPORT_IP_HEADER = 0x1 << 1;
    constexpr uint8_t  SUPPORT_UDP_HEADER = 0x1 << 2;
}