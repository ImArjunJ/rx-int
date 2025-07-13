cmake_minimum_required(VERSION 3.5.0)
project(rxint_client VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)

add_executable(rxint_client src/main.cpp src/Driver.cpp src/TUI.cpp src/Injector.cpp)

add_subdirectory(dummy)