cmake_minimum_required(VERSION 3.15)
project("RedTracerApp")

add_executable(${PROJECT_NAME}
    "include/PEInformation.hpp"
    "include/PEReader.hpp"
    "src/Main.cpp"
    "src/PEReader.cpp")

target_include_directories(${PROJECT_NAME} PRIVATE "include/")

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)