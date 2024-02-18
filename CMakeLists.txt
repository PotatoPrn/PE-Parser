cmake_minimum_required(VERSION 3.28)
project(PEParser)

set(CMAKE_CXX_STANDARD 20)

include_directories(include)

set(EXECUTABLE_OUTPUT_PATH "../")

add_executable(PEParser main.cpp
        src/Utils.cpp
        include/Utils.h
        include/MapImage.h
        include/StringFormatting.h)
