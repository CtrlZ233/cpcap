#include "CompactPacketFileReader.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <filesystem>

namespace cpcap {
    CompactPacketFileReader::CompactPacketFileReader(const char *file_path) {
        namespace fs = std::filesystem;
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            throw std::runtime_error("No such a file");
        }

        // init epoll handle
        inotify_fd = inotify_init();
        if (inotify_fd < 0) {
            throw std::runtime_error("Fail to create inotify fd");
        }

        if (notify_add_watch(inotify_fd, file_path, IN_MODIFY | IN_CLOSE_WRITE) < 0) {
            throw std::runtime_error("Fail to add watch file");
        }

        epoll_fd = epoll_create1(0);
        if (epoll_fd < 0) {
            throw std::runtime_error("Fail to add watch file");
        }
        epoll_event ev{};


        fd = open(file_path, O_RDONLY, 0);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file");
        }
        if (!checkFileValid(fd)) {
            throw std::runtime_error("Invalid .cpcap format");
        }
    }

    CompactPacketFileReader::~CompactPacketFileReader() {
        close(fd);
    }

    bool CompactPacketFileReader::checkFileValid(int fd) {
        CPackFileHeader header{};
        size_t read_bytes = ::read(fd, &header, sizeof(CPackFileHeader));
        if (read_bytes != sizeof(CPackFileHeader)) {
            return false;
        }
        return header.magic_number == MAGIC_NUMBER;
    }

    FileReader &CompactPacketFileReader::next(cpcap::CompactPacket &pack) {
        if (packs.empty()) {
            parseNextChunk();
        }
        pack = packs.front();
        packs.pop();
        return *this;
    }

    void CompactPacketFileReader::parseNextChunk() {

    }

    bool CompactPacketFileReader::isFileReady(size_t required_size) {
        do {
            struct stat st;
            if (fstat(fd, &st) == -1) {
                throw std::runtime_error("Fail to get file info");
            }
            off_t current_pos = lseek(fd, 0, SEEK_CUR);
            if (current_pos == -1) {
                throw std::runtime_error("Fail to get current offset");
            }
            off_t remaining_bytes = st.st_size - current_pos;
            if (remaining_bytes >= static_cast<off_t>(required_size)) {
                return true;
            }

        } while (true)
    }



}