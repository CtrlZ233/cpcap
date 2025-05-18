#include "encoder/CPackEthHeaderEncoder.h"
#include "ConstDefine.h"
#include <arpa/inet.h>

namespace cpcap {
    bool CPackEthHeaderEncoder::isSupport(const CompactPacket &pack) const {
        if (pack.len < sizeof(EthHeader)) {
            return false;
        }
        const EthHeader* eth = reinterpret_cast<const EthHeader*>(pack.data.data());
        uint16_t eth_type = ntohs(eth->type);
        return (eth_type >= 0x0600);
    }

    void CPackEthHeaderEncoder::setFlag(CompactPacket &pack) {
        pack.flag |= SUPPORT_ETH_HEADER;
    }

    unsigned int CPackEthHeaderEncoder::parse(const CompactPacket &pack) {
        const EthHeader* eth = reinterpret_cast<const EthHeader*>(pack.data.data());
        src_addrs.push_back(eth->src);
        dst_addrs.push_back(eth->dst);
        types.push_back(eth->type);
        return sizeof(EthHeader);
    }

    void CPackEthHeaderEncoder::encode(CPackFileChunkHeader &header, std::vector<uint8_t> &encoded_data) {
        CPackEthHeaderRegionDesc desc{};
        desc.src_address_region_len = src_addrs.size() * sizeof(MacAddr);
        desc.dst_address_region_len = dst_addrs.size() * sizeof(MacAddr);
        desc.mac_type_len = types.size() * sizeof(uint16_t);

        size_t total_size =
                sizeof(CPackEthHeaderEncoder) +
                desc.src_address_region_len +
                desc.dst_address_region_len +
                desc.mac_type_len;

        encoded_data.reserve(encoded_data.size() + total_size);

        auto append_data = [&](const void* data, size_t size) {
            const uint8_t* src = static_cast<const uint8_t*>(data);
            encoded_data.insert(encoded_data.end(), src, src + size);
        };

        size_t desc_size = sizeof(CPackEthHeaderRegionDesc);
        if (desc_size > 0) {
            append_data(&desc, desc_size);
        }

        size_t src_size = src_addrs.size();
        if (src_size > 0) {
            append_data(src_addrs.data(), src_size * sizeof(MacAddr));
        }

        size_t dst_size = dst_addrs.size();
        if (dst_size > 0) {
            append_data(dst_addrs.data(), dst_size * sizeof(MacAddr));
        }

        size_t types_size = types.size();
        if (types_size > 0) {
            append_data(types.data(), types_size * sizeof(uint16_t));
        }
        header.eth_header_region_len = total_size;
        src_addrs.clear();
        dst_addrs.clear();
        types.clear();
    }
}