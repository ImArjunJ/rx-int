cmake_minimum_required(VERSION 3.15)
project(rx_int_tests_target LANGUAGES CXX)

add_executable(rx_int_target_tests dummy_target.cpp)
add_library(rx_int_payload SHARED dummy_payload.cpp)

if(MSVC)
	target_compile_options(rx_int_target_tests PRIVATE /W3 /WX)
	target_compile_options(rx_int_payload PRIVATE /W3 /WX)
else()
	target_compile_options(rx_int_target_tests PRIVATE -O3)
	target_compile_options(rx_int_payload PRIVATE -O3)
endif()