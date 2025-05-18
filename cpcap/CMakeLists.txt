cmake_minimum_required(VERSION 3.5)

project(cpcap_lib)

include_directories(./include)
include_directories(../spdlog/include)

set (LIB_SOURCE
        src/CompactPacketFileReader.cpp
        src/CompactPacketFileWriter.cpp
        src/encoder/CPackHeaderEncoder.cpp
        src/encoder/CPackEthHeaderEncoder.cpp
)

add_library(cpcap OBJECT ${LIB_SOURCE})