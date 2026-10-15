cmake_minimum_required(VERSION 3.27)
set(CMAKE_C_STANDARD 17)
if(NOT CMAKE_OSX_ARCHITECTURES)
    # Dopamine's supported libkrw runtime is arm64 on affected devices.
    # Avoid an arm64e slice that dyld would prefer but cannot link to libkrw.
    set(CMAKE_OSX_ARCHITECTURES "arm64")
endif()
if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET OR CMAKE_OSX_DEPLOYMENT_TARGET STREQUAL "")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")
endif()

find_program(XCRUN xcrun)
if(XCRUN AND NOT CMAKE_OSX_SYSROOT)
    execute_process(COMMAND ${XCRUN} --sdk iphoneos --show-sdk-path
            OUTPUT_VARIABLE IOS_SDK_PATH
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(IOS_SDK_PATH)
        set(CMAKE_OSX_SYSROOT "${IOS_SDK_PATH}" CACHE PATH "iOS SDK sysroot" FORCE)
    endif()
endif()

project(x8A4 C)

find_program(LDID ldid2)
if(NOT LDID)
    find_program(LDID ldid)
    if(NOT LDID)
        message(FATAL_ERROR "Please install Procursus ldid before building! (https://github.com/ProcursusTeam/ldid)")
    endif()
endif()

find_program(GIT git)
if(GIT)
    if(NOT DEFINED VERSION_COMMIT_COUNT)
        execute_process(COMMAND ${GIT} rev-list --count HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE VERSION_COMMIT_COUNT ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(NOT DEFINED VERSION_COMMIT_SHA)
        execute_process(COMMAND ${GIT} rev-parse HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE VERSION_COMMIT_SHA ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
else()
    set(VERSION_COMMIT_COUNT "0")
    set(VERSION_COMMIT_SHA "unknown")
endif()
if(NOT VERSION_COMMIT_COUNT)
    set(VERSION_COMMIT_COUNT "0")
endif()
if(NOT VERSION_COMMIT_SHA)
    set(VERSION_COMMIT_SHA "unknown")
endif()

add_library(x8A4 SHARED x8A4.c
        Logger/logger.c
        Include/x8A4/Logger/logger.h
        Kernel/slide.c
        Include/x8A4/Kernel/slide.h
        Services/services.c
        Include/x8A4/Services/services.h
        Registry/registry.c
        Include/x8A4/Registry/registry.h
        Kernel/kernel.c
        Include/x8A4/Kernel/kernel.h
        Kernel/offsets.c
        Include/x8A4/Kernel/offsets.h
        Kernel/kpf.c
        Include/x8A4/Kernel/kpf.h
        Kernel/osobject.c
        Include/x8A4/Kernel/osobject.h
        Kernel/nvram.c
        Include/x8A4/Kernel/nvram.h)

target_include_directories(x8A4 PRIVATE
        "${CMAKE_SOURCE_DIR}/Internal"
        "${CMAKE_SOURCE_DIR}/Include/choma"
        "${CMAKE_SOURCE_DIR}/Include")

# Keep the shipped library's public surface limited to the read-only x8A4 API.
# Dead stripping also drops unused writer helpers from the bundled archives.
target_compile_options(x8A4 PRIVATE -ffunction-sections -fdata-sections)
target_link_options(x8A4 PRIVATE
        "LINKER:-dead_strip"
        "LINKER:-exported_symbols_list,${CMAKE_SOURCE_DIR}/x8A4.exports")

set(RPATH "/var/jb/usr/lib")
set(RPATH2 "/usr/lib")
set_target_properties(x8A4
        PROPERTIES
#        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/lib/darwin/ -lclang_rt.asan_abi_ios -lclang_rt.asan_ios_dynamic")
        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} ")
set_target_properties(x8A4
        PROPERTIES
#        COMPILE_FLAGS "-Wall -Werror -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
        COMPILE_FLAGS "-Wall -Werror")

set(SOVERSION 1)
set_target_properties(x8A4 PROPERTIES
        SOVERSION ${SOVERSION}
        MACOSX_RPATH ON
        INSTALL_NAME_DIR "@rpath")


target_link_directories(x8A4 PRIVATE
        "${CMAKE_SOURCE_DIR}/Lib")

target_link_libraries(x8A4
        "-framework CoreFoundation"
        "-framework IOKit"
        krw
        compression
        choma
        xpf)

add_executable(x8A4_CLI x8A4_CLI.c)

add_definitions(
        -DVERSION_COMMIT_COUNT="${VERSION_COMMIT_COUNT}"
        -DVERSION_COMMIT_SHA="${VERSION_COMMIT_SHA}"
        -DSOVERSION=${SOVERSION}
        )
if(DEFINED RELEASE)
    add_definitions(-DRELEASE="1")
endif()

target_include_directories(x8A4_CLI PRIVATE "${CMAKE_SOURCE_DIR}/Include")

set(RPATH "/var/jb/usr/lib")
set(RPATH2 "/usr/lib")
set_target_properties(x8A4_CLI
        PROPERTIES
#        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2} -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/lib/darwin -lclang_rt.asan_abi_ios -lclang_rt.asan_ios_dynamic")
        LINK_FLAGS "-Wl,-rpath,${RPATH} -Wl,-rpath,${RPATH2}")
set_target_properties(x8A4_CLI
        PROPERTIES
#        COMPILE_FLAGS "-Wall -Werror -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
        COMPILE_FLAGS "-Wall -Werror")


target_link_directories(x8A4_CLI PRIVATE
        "${CMAKE_SOURCE_DIR}/Lib")

target_link_libraries(x8A4_CLI
        "x8A4")

install(TARGETS x8A4 x8A4_CLI
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

add_custom_command(TARGET x8A4 POST_BUILD
        COMMAND ${LDID} -S -Hsha256 -Cadhoc ${CMAKE_CURRENT_BINARY_DIR}/libx8A4.${SOVERSION}.dylib
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing libx8A4.${SOVERSION}.dylib..."
)

add_custom_command(TARGET x8A4_CLI POST_BUILD
        COMMAND ${LDID} -Stfp0.plist -Hsha256 -Cadhoc ${CMAKE_CURRENT_BINARY_DIR}/x8A4_CLI
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Signing x8A4_CLI"
)
#
#SET(CMAKE_EXPORT_COMPILE_COMMANDS 1)
#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()
