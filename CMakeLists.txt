cmake_minimum_required(VERSION 3.8)
project(rightsbox_cli)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp Dispatcher.cpp Dispatcher.h RBoxMessage.cpp RBoxMessage.h RBoxInit.cpp utils/TokenUtils.cpp utils/TokenUtils.h utils/OSVersionUtils.h RBoxInit.h RBoxRun.cpp RBoxRun.h RBoxIOCPNotifs.cpp RBoxIOCPNotifs.h)
add_executable(rightsbox_cli ${SOURCE_FILES})

add_definitions(-DWIN32 -DWINDOWS -DUNICODE -D_UNICODE)

set_target_properties(rightsbox_cli PROPERTIES OUTPUT_NAME "RightsBox")

set(CMAKE_EXTRA_DEBUG_FLAGS "/MTd")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_EXTRA_DEBUG_FLAGS}")

set(CMAKE_EXTRA_RELEASE_FLAGS "/MT")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${CMAKE_EXTRA_RELEASE_FLAGS}")