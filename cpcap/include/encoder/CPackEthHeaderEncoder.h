#pragma once

#include "Encoder.h"

namespace cpcap {
    class CPackEthHeaderEncoder : public Encoder {
    public:
        virtual bool isSupport(const CompactPacket &) const;

        virtual void setFlag(CompactPacket &);

        virtual unsigned int parse(const CompactPacket &pack);

        virtual void encode(CPackFileChunkHeader &header, std::vector<uint8_t> &encoded_data);
    private:
#pragma pack(push, 1)
        struct MacAddr {
            uint8_t addr[6];
        };
        struct EthHeader {
            MacAddr dst;
            MacAddr src;
            uint16_t type;
        };
#pragma pack(pop)

    private:
        std::vector<MacAddr> src_addrs;
        std::vector<MacAddr> dst_addrs;
        std::vector<uint16_t> types;
    };
}