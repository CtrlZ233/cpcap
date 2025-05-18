#include "CompactPacket.h"
#include "CompactPacketFileWriter.h"
#include "CompactPacketFileReader.h"
#include <pcap.h>
#include <stdexcept>
#include <iostream>
#include "spdlog/spdlog.h"

const char *TEST_FILE = "test.cpcap";

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }
    auto file_name = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE];
    auto handle = pcap_open_offline(file_name, err_buf);
    if (handle == nullptr) {
        throw std::runtime_error("Failed to open pcap file: " + std::string(err_buf));
    }

    auto writer = cpcap::CompactPacketFileWriter(TEST_FILE);

    struct pcap_pkthdr *header;
    const u_char *packet;
    int status;
    size_t pack_count = 0;
    while ((status = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (status == 0) {
            spdlog::info("why ?");
            continue;
        }
        pack_count += 1;

        cpcap::CompactPacket cpacket {};
        cpacket.timestamp = header->ts;
        cpacket.len = header->len;
        cpacket.cap_len = header->caplen;
        cpacket.data.assign(packet, packet + header->caplen);
        writer.write(cpacket);
    }
    spdlog::info("total pack num: {}", pack_count);
    writer.flush();
}