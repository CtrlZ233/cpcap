#pragma once

#include "ConstDefine.h"

#include <stdint.h>
#include <vector>

namespace cpcap {
    struct CompactPacket {
        timeval timestamp;
        uint32_t cap_len;
        uint32_t len;
        uint8_t flag;
        uint32_t payload_len;
        std::vector<uint8_t> data;
    };
#pragma pack(push, 1)
    struct CPackFileHeaderData {
        uint32_t magic_number;
        uint16_t major_version;
        uint16_t minor_version;
    };

    struct CPackFileHeader : public CPackFileHeaderData {
        char padding[FILE_HEADER_SIZE - sizeof(CPackFileHeaderData)];
    };

    struct CPackFileChunkHeader {
        uint32_t checksum;
        uint32_t pack_num;
        uint32_t pack_header_region_len;
        uint32_t eth_header_region_len;
        uint32_t ip_header_region_len;
        uint32_t udp_header_region_len;
        uint32_t payload_region_size;
    };

    struct CPackHeaderRegionDesc {
        uint32_t timestamp_region_len;
        uint32_t flag_region_len;
        uint32_t payload_length_region_len;
    };

//    struct CPackHeader {
//        uint64_t timestamp_interval;
//        uint8_t flag;
//        uint32_t payload_len;
//    };

    struct CPackEthHeaderRegionDesc {
        uint32_t src_address_region_len;
        uint32_t dst_address_region_len;
        uint32_t mac_type_len;
    };

//    struct CPackEthHeader {
//        char dst_mac_addr[6];
//        char src_mac_addr[6];
//        char type[2];
//    };

    struct CPackIpHeaderRegionDesc {
        uint32_t version_region_len;
        uint32_t ihl_region_len;
        uint32_t tos_region_len;
        uint32_t total_length_region_len;
        uint32_t identification_region_len;
        uint32_t flags_region_len;
        uint32_t offset_region_len;
        uint32_t ttl_region_len;
        uint32_t protocol_region_len;
        uint32_t header_checksum_region_len;
        uint32_t ip_addr_region_len;
    };
#pragma pack(pop)
}