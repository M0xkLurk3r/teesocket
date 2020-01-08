cmake_minimum_required(VERSION 3.0)

project(teesocket LANGUAGES C)

include_directories(./include/)

add_executable(teesocket main.c)

install(TARGETS teesocket RUNTIME DESTINATION bin)
