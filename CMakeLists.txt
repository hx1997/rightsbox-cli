cmake_minimum_required(VERSION 3.15)
project(rightsbox_cli)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Detect architecture for suffixed output names
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(ARCH_SUFFIX "64")
else()
	set(ARCH_SUFFIX "32")
endif()

# Main executable — RightsBox.exe
set(SOURCE_FILES
    rightsbox/main.cpp
    rightsbox/Dispatcher.cpp rightsbox/Dispatcher.h
    rightsbox/RBoxMessage.cpp rightsbox/RBoxMessage.h
    rightsbox/RBoxInit.cpp rightsbox/RBoxInit.h
    rightsbox/RBoxRun.cpp rightsbox/RBoxRun.h
    rightsbox/RBoxIOCPNotifs.cpp rightsbox/RBoxIOCPNotifs.h
    utils/TokenUtils.cpp utils/TokenUtils.h
    utils/OSVersionUtils.h
    broker/Broker.cpp broker/Broker.h
    broker/BrokerPolicy.cpp broker/BrokerPolicy.h
    broker/BrokerProtocol.h
)
add_executable(rightsbox_cli ${SOURCE_FILES})

target_include_directories(rightsbox_cli PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/rightsbox
    ${CMAKE_SOURCE_DIR}/broker
    ${CMAKE_SOURCE_DIR}/utils
)

target_compile_definitions(rightsbox_cli PRIVATE WIN32 WINDOWS UNICODE _UNICODE _WIN32_WINNT=0x0600)

set_target_properties(rightsbox_cli PROPERTIES OUTPUT_NAME "RightsBox")

if (MSVC)
	set_property(TARGET rightsbox_cli PROPERTY
		MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Hook DLL — injected into sandboxed processes (arch-suffixed: RBoxHook64.dll or RBoxHook32.dll)
add_library(RBoxHook SHARED hook/RBoxHook.cpp hook/RBoxHook.h broker/BrokerProtocol.h)

target_include_directories(RBoxHook PRIVATE
    ${CMAKE_SOURCE_DIR}/hook
    ${CMAKE_SOURCE_DIR}/broker
)

target_compile_definitions(RBoxHook PRIVATE WIN32 WINDOWS UNICODE _UNICODE _WIN32_WINNT=0x0600)

set_target_properties(RBoxHook PROPERTIES OUTPUT_NAME "RBoxHook${ARCH_SUFFIX}")

if (MSVC)
	set_property(TARGET RBoxHook PROPERTY
		MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Cross-architecture injection helper (arch-suffixed: RBoxInject64.exe or RBoxInject32.exe)
add_executable(RBoxInject inject/RBoxInject.cpp)

target_compile_definitions(RBoxInject PRIVATE WIN32 WINDOWS UNICODE _UNICODE _WIN32_WINNT=0x0600)

set_target_properties(RBoxInject PROPERTIES OUTPUT_NAME "RBoxInject${ARCH_SUFFIX}")

if (MSVC)
	set_property(TARGET RBoxInject PROPERTY
		MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Sandboxed launcher — runs inside the sandbox, spawns user's target program
add_executable(RBoxRunner runner/RBoxRunner.cpp)

target_compile_definitions(RBoxRunner PRIVATE WIN32 WINDOWS UNICODE _UNICODE _WIN32_WINNT=0x0600)

set_target_properties(RBoxRunner PROPERTIES OUTPUT_NAME "RBoxRunner")

if (MSVC)
	set_property(TARGET RBoxRunner PROPERTY
		MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()