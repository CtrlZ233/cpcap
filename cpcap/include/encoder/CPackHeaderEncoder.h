#pragma once

#include "Encoder.h"

namespace cpcap {
    class CPackHeaderEncoder : public Encoder {
    public:
        virtual bool isSupport(const CompactPacket &) const;

        virtual void setFlag(CompactPacket &);

        virtual unsigned int parse(const CompactPacket &pack);

        virtual void encode(CPackFileChunkHeader &header, std::vector<uint8_t> &encoded_data);

    private:
        std::vector<uint64_t> timestamps;
        std::vector<uint8_t> flags;
        std::vector<uint32_t> payload_lens;
    };
}