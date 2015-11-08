cmake_minimum_required(VERSION 2.8)

project(td_bizurado)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})

ADD_DEFINITIONS("-Wall")

include_directories(${PROJECT_SOURCE_DIR})

add_executable(simple zipcrack.c)
