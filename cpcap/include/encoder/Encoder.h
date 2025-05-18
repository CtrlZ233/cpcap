#pragma once

#include "../CompactPacket.h"
#include <vector>

namespace cpcap {
    class Encoder {
    public:
        virtual bool isSupport(const CompactPacket &pack) const = 0;

        virtual void setFlag(CompactPacket &) = 0;

        virtual unsigned int parse(const CompactPacket &pack) = 0;

        virtual void encode(CPackFileChunkHeader &header, std::vector<uint8_t> &encoded_data) = 0;

        virtual ~Encoder() {};
    };
}
