#pragma once

#include "CompactPacket.h"
#include "encoder/Encoder.h"
#include <fstream>
#include <fcntl.h>
#include <vector>
#include <memory.h>

namespace cpcap {
    class FileWriter {
    public:
        virtual FileWriter &write(CompactPacket &) = 0;
        virtual FileWriter &flush() = 0;
        virtual ~FileWriter() {};
    };

    class CompactPacketFileWriter : public FileWriter {
    public:
        CompactPacketFileWriter(const char *file_path);

        virtual FileWriter &write(CompactPacket &packet);

        virtual FileWriter &flush();

        virtual ~CompactPacketFileWriter();

    private:
        static void writeFileHeader(int fd);
        static void fileSync(int fd);
    private:
        int fd;
        std::vector<std::vector<uint8_t>> payloads;
        unsigned int payload_len;
        std::vector<std::unique_ptr<Encoder>> encoders;

    };
}
