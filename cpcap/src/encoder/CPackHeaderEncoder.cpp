#include "encoder/CPackHeaderEncoder.h"

namespace cpcap {
    bool CPackHeaderEncoder::isSupport(const cpcap::CompactPacket &) const {
        return true;
    }

    void CPackHeaderEncoder::setFlag(cpcap::CompactPacket &) {}

    unsigned int CPackHeaderEncoder::parse(const cpcap::CompactPacket &pack) {
        timestamps.push_back(
                static_cast<uint64_t>(
                        pack.timestamp.tv_sec) * 1000000ULL
                        + pack.timestamp.tv_usec
        );
        flags.push_back(pack.flag);
        payload_lens.push_back(pack.payload_len);
        return 0;
    }

    void CPackHeaderEncoder::encode(CPackFileChunkHeader &header, std::vector<uint8_t> &encoded_data) {
        CPackHeaderRegionDesc desc{};
        desc.timestamp_region_len = timestamps.size() * sizeof(uint64_t);
        desc.flag_region_len = flags.size() * sizeof(uint8_t);
        desc.payload_length_region_len = payload_lens.size() * sizeof(uint32_t);
        size_t total_size =
                sizeof(CPackHeaderRegionDesc) +
                desc.timestamp_region_len +
                desc.flag_region_len +
                desc.payload_length_region_len;

        encoded_data.reserve(encoded_data.size() + total_size);

        auto append_data = [&](const void* data, size_t size) {
            const uint8_t* src = static_cast<const uint8_t*>(data);
            encoded_data.insert(encoded_data.end(), src, src + size);
        };

        size_t desc_size = sizeof(CPackHeaderRegionDesc);
        if (desc_size > 0) {
            append_data(&desc, desc_size);
        }

        size_t ts_size = timestamps.size();
        if (ts_size > 0) {
            append_data(timestamps.data(), ts_size * sizeof(uint64_t));
        }

        size_t flags_size = flags.size();
        if (flags_size > 0) {
            append_data(flags.data(), flags_size * sizeof(uint8_t));
        }

        size_t lens_size = payload_lens.size();
        if (lens_size > 0) {
            append_data(payload_lens.data(), lens_size * sizeof(uint32_t));
        }
        header.pack_header_region_len = total_size;
        timestamps.clear();
        flags.clear();
        payload_lens.clear();
    }
}