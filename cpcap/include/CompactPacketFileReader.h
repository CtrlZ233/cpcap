
#pragma once

#include "CompactPacket.h"
#include <queue>

namespace cpcap {
    class FileReader {
    public:
        virtual FileReader &next(CompactPacket &) = 0;
        virtual ~FileReader() {};
    };

    class CompactPacketFileReader : public FileReader {
    public:
        CompactPacketFileReader(const char *file_path);

        virtual FileReader &next(CompactPacket &);

        virtual ~CompactPacketFileReader();
    private:
        static bool checkFileValid(int fd);
        void parseNextChunk();
        bool isFileReady(size_t required_size);

    private:
        int fd;
        int epoll_fd;
        int inotify_fd;
        std::queue<CompactPacket> packs;
    };
}


