cmake_minimum_required(VERSION 3.5)

project(cpcap)

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(cpcap)

include_directories(cpcap/include)
include_directories(spdlog/include)

add_executable(
        main
        main.cpp)

target_link_libraries(
        main
        PUBLIC
        cpcap
        pcap
)

