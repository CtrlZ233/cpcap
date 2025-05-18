#include "CompactPacketFileWriter.h"
#include "encoder/CPackHeaderEncoder.h"
#include "encoder/CPackEthHeaderEncoder.h"
#include "spdlog/spdlog.h"
#include <filesystem>
#include <unistd.h>

namespace cpcap {
    namespace fs = std::filesystem;
    CompactPacketFileWriter::CompactPacketFileWriter(const char *file_path) : payload_len(0) {
        encoders.push_back(std::make_unique<CPackEthHeaderEncoder>());
        encoders.push_back(std::make_unique<CPackHeaderEncoder>());
        if (fs::exists(file_path)) {
            if (fs::is_regular_file(file_path)) {
                fs::remove(file_path);
            }
        }
        fd = open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file");
        }
        writeFileHeader(fd);
    }

    CompactPacketFileWriter::~CompactPacketFileWriter() {
        flush();
        close(fd);
    }

    void CompactPacketFileWriter::writeFileHeader(int fd) {
        CPackFileHeader header;
        header.magic_number = MAGIC_NUMBER;
        header.major_version = MAJOR_VER;
        header.minor_version = MINOR_VER;
        memset(header.padding, 0, sizeof(header.padding));
        ssize_t written = ::write(fd, &header, sizeof(header));
        if (written != sizeof(header)) {
            close(fd);
            throw std::runtime_error("Failed to write header");
        }
        fileSync(fd);
    }

    void CompactPacketFileWriter::fileSync(int fd) {
        if (fsync(fd) != 0) {
            close(fd);
            throw std::runtime_error("Failed to sync to disk");
        }
    }

    FileWriter &CompactPacketFileWriter::write(cpcap::CompactPacket &packet) {
        packet.payload_len = packet.cap_len;
        for(auto &encoder : encoders) {
            if (encoder->isSupport(packet)) {
                auto offload_len = encoder->parse(packet);
                packet.payload_len -= offload_len;
                encoder->setFlag(packet);
            }
        }
        auto payload_start = packet.data.begin() + packet.len - packet.payload_len;
        payloads.emplace_back(std::vector(payload_start, packet.data.end()));
        payload_len += packet.payload_len;
        return *this;
    }

    FileWriter &CompactPacketFileWriter::flush() {
        CPackFileChunkHeader chunk_header {};
        std::vector<uint8_t> chunk(sizeof(CPackFileChunkHeader));
        for (auto &encoder : encoders) {
            encoder->encode(chunk_header, chunk);
        }

        chunk_header.payload_region_size = payload_len;

        chunk.reserve(sizeof(CPackFileChunkHeader) + chunk_header.payload_region_size);
        for (auto payload: payloads) {
            chunk.insert(chunk.end(), payload.data(), payload.data() + payload.size());
        }


        payloads.clear();
        payload_len = 0;

        std::memcpy(chunk.data(), &chunk_header, sizeof(CPackFileChunkHeader));
        ssize_t written = ::write(fd, chunk.data(), chunk.size());
        if (written != chunk.size()) {
            close(fd);
            throw std::runtime_error("Failed to write header");
        }
        fileSync(fd);
        return *this;
    }
}