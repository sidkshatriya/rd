# *-* Mode: cmake; *-*

cmake_minimum_required(VERSION 3.1.0)
project(rr C CXX ASM)

# "Do not add flags to export symbols from executables without the ENABLE_EXPORTS target property."
# This avoids linking executables with -rdynamic. -rdynamic has been observed
# to cause rr_exec_stub to be linked with the dynamic linker with some
# version(s) of clang (but linked to an incorrect file name, causing
# exec of rr_exec_stub to fail).
if(POLICY CMP0065)
  cmake_policy(SET CMP0065 NEW)
endif()

# On single configuration generators, make Debug the default configuration
if(NOT CMAKE_CONFIGURATION_TYPES)
  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Whether to build in `Debug` or `Release` mode." FORCE)
  endif()
endif()

set(BUILD_SHARED_LIBS ON)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib/rr)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(FLAGS_COMMON "-msse2 -D__MMX__ -D__SSE__ -D__SSE2__ -D__USE_LARGEFILE64 -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAGS_COMMON} -Wstrict-prototypes -std=gnu11")
# Define __STDC_LIMIT_MACROS so |#include <stdint.h>| works as expected.
# Define __STDC_FORMAT_MACROS so |#include <inttypes.h>| works as expected.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++14" SUPPORTS_CXX14)
if (SUPPORTS_CXX14)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAGS_COMMON} -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS -std=c++14")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAGS_COMMON} -D__STDC_LIMIT_MACROS -D__STDC_FORMAT_MACROS -std=c++11")
endif()

# We support three build types:
# DEBUG: suitable for debugging rr
# RELEASE: suitable for using rr in production (but keeps rr debuginfo)
# OTHER: suitable for using rr in production, but honouring distro/user opt/debug settings
# (which we assume are suitable for production use)

# Base settings for debug and release/unspecified builds.
# Use -Werror for debug builds because we assume a developer is building, not a user.
set(RR_FLAGS_DEBUG "-Wall -Wextra -DDEBUG -UNDEBUG")
set(RR_FLAGS_RELEASE "-Wall -Wextra -UDEBUG -DNDEBUG")

# The folowing settings are the defaults for the OTHER build type.
# Flags used to build the preload library. MUST have debuginfo enabled. SHOULD be optimized.
set(PRELOAD_COMPILE_FLAGS "${RR_FLAGS_RELEASE} -fno-stack-protector -g3")
# Flags used to build other files. Entirely build-type-dependent.
set(RR_FLAGS ${RR_FLAGS_RELEASE})

# Now override for build type.
string(TOLOWER ${CMAKE_BUILD_TYPE} LOWERCASE_CMAKE_BUILD_TYPE)
if(LOWERCASE_CMAKE_BUILD_TYPE STREQUAL "debug")
  set(PRELOAD_COMPILE_FLAGS "${PRELOAD_COMPILE_FLAGS} -O2 -Werror")
  set(RR_FLAGS "${RR_FLAGS_DEBUG} -g3 -Werror")
elseif(LOWERCASE_CMAKE_BUILD_TYPE STREQUAL "release")
  # CMake itself will add optimization flags
  set(RR_FLAGS "${RR_FLAGS_RELEASE} -g3")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-command-line-argument")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-command-line-argument")
endif()
if (CMAKE_ASM_COMPILER_ID STREQUAL "Clang")
  set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -fno-integrated-as")
endif()

option(force32bit "Force a 32-bit rr build, rather than both 64 and 32-bit. rr will only be able to record and replay 32-bit processes.")
option(disable32bit "On a 64-bit platform, avoid requiring a 32-bit cross-compilation toolchain by not building 32-bit components. rr will be able to record 32-bit processes but not replay them.")

if(force32bit)
  set(rr_32BIT true)
  set(rr_64BIT false)
  set(rr_MBITNESS_OPTION -m32)
else()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(disable32bit)
      set(rr_32BIT false)
    else()
      set(rr_32BIT true)
    endif()
    set(rr_64BIT true)
  else()
    set(rr_32BIT true)
    set(rr_64BIT false)
  endif()
  set(rr_MBITNESS_OPTION)
endif()

# Check that compiling 32-bit code on a 64-bit target works, if required.
#if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64" AND rr_32BIT)
#  # try_compile won't accept LINK_FLAGS, so do this manually.
#  file(WRITE "${CMAKE_BINARY_DIR}/test32.c" "int main() { return 0; }")
#  execute_process(COMMAND ${CMAKE_C_COMPILER} -o ${CMAKE_BINARY_DIR}/test32 ${CMAKE_BINARY_DIR}/test32.c -m32
#			RESULT_VARIABLE COMPILER_32BIT_RESULT)
#  if(NOT (COMPILER_32BIT_RESULT EQUAL 0))
#    message(FATAL_ERROR "Your toolchain doesn't support 32-bit cross-compilation. Install the required packages or pass -Ddisable32bit=ON to cmake.")
#  endif()
#endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${rr_MBITNESS_OPTION}")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${rr_MBITNESS_OPTION}")

find_path(SECCOMP NAMES "linux/seccomp.h")
if(NOT SECCOMP)
  message(FATAL_ERROR "Couldn't find linux/seccomp.h. You may need to upgrade your kernel.")
endif()

set(Python_ADDITIONAL_VERSIONS 3 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0)
find_package(PythonInterp 3 REQUIRED)

execute_process(COMMAND "${PYTHON_EXECUTABLE}" "-c" "# nothing"
                RESULT_VARIABLE python_status)
if(python_status)
  message(FATAL_ERROR "Couldn't run python interpreter ${PYTHON_EXECUTABLE}.")
endif()

include_directories("${PROJECT_SOURCE_DIR}/include")
# We need to know where our generated files are.
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Order matters here! syscall_hook.S must be immediately before syscallbuf.c,
# breakpoint_table.S must be before overrides.c, which must be last.
set(PRELOAD_FILES
  syscall_hook.S
  syscallbuf.c
  raw_syscall.S
  breakpoint_table.S
  overrides.c
)
set(PRELOAD_SOURCE_FILES
  ${PRELOAD_FILES}
  preload_interface.h
  syscallbuf.h
)
add_library(rrpreload)
foreach(file ${PRELOAD_FILES})
  target_sources(rrpreload PUBLIC "${CMAKE_SOURCE_DIR}/src/preload/${file}")
  set_source_files_properties("${CMAKE_SOURCE_DIR}/src/preload/${file}"
                              PROPERTIES COMPILE_FLAGS ${PRELOAD_COMPILE_FLAGS})
endforeach(file)
set_target_properties(rrpreload PROPERTIES LINK_FLAGS "-nostartfiles")

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64"
                   COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py"
                   "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py")
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32"
                   COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py"
                   "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py")
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64_replay"
                   COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py"
                   "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64_replay"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py")
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32_replay"
                   COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py"
                   "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32_replay"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_rr_page.py")

# @TODO Is adding `ALL` here what we really want?
add_custom_target(Pages ALL DEPENDS
                  "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32"
                  "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64"
                  "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32_replay"
                  "${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64_replay")

function(post_build_executable target)
# grsecurity needs these. But if we add them ourselves, they may conflict
# with other flags added in other ways, and they all have to match :-(. So
# don't do this until a better solution presents itself
#  add_custom_command(TARGET ${target}
#                     POST_BUILD
#                     COMMAND setfattr ARGS -n user.pax.flags -v m $<TARGET_FILE:${target}>)
endfunction(post_build_executable)

if(UNIX)
  include(GNUInstallDirs)
else()
  set(CMAKE_INSTALL_LIBDIR "lib")
  set(CMAKE_INSTALL_BINDIR "bin")
  set(CMAKE_INSTALL_DATADIR "share")
  set(CMAKE_INSTALL_DOCDIR "${CMAKE_INSTALL_DATADIR}/doc")
  set(CMAKE_INSTALL_INCLUDEDIR "include")
endif()

target_link_libraries(rrpreload
  ${CMAKE_DL_LIBS}
)

add_executable(rr_exec_stub src/exec_stub.c)
post_build_executable(rr_exec_stub)
set_target_properties(rr_exec_stub
                      PROPERTIES LINK_FLAGS "-static -nostartfiles -nodefaultlibs")
set_source_files_properties(src/exec_stub.c
                            COMPILE_FLAGS "-fno-stack-protector")

foreach(file ${PRELOAD_SOURCE_FILES})
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                 "${CMAKE_CURRENT_BINARY_DIR}/share/rr/src/preload/${file}"
                 COPYONLY)
  install(FILES src/preload/${file}
          DESTINATION ${CMAKE_INSTALL_DATADIR}/rr/src/preload)
endforeach(file)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64
              ${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_64_replay
              ${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32
              ${CMAKE_CURRENT_BINARY_DIR}/share/rr/rr_page_32_replay
  DESTINATION ${CMAKE_INSTALL_DATADIR}/rr)

install(TARGETS ${RR_BIN} rrpreload rr_exec_stub
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)

# Build 32-bit librrpreload on 64-bit builds.
# We copy the source files into '32' subdirectories in the output
# directory, so we can set different compile options on them.
# This sucks but I can't find a better way to get CMake to build
# the same source file in two different ways.
if(rr_32BIT AND rr_64BIT)
  add_library(rrpreload_32)

  foreach(file ${PRELOAD_SOURCE_FILES})
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/preload/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                   COPYONLY)
  endforeach(file)

  foreach(file ${PRELOAD_FILES})
    target_sources(rrpreload_32 PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}")
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/preload/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 ${PRELOAD_COMPILE_FLAGS}")
  endforeach(file)

  set_target_properties(rrpreload_32 PROPERTIES LINK_FLAGS "-m32 -nostartfiles")
  target_link_libraries(rrpreload_32
    ${CMAKE_DL_LIBS}
  )

  foreach(file exec_stub.c)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/${file}"
                   "${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                   COPYONLY)
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/32/${file}"
                                PROPERTIES COMPILE_FLAGS "-m32 -fno-stack-protector")
  endforeach(file)

  add_executable(rr_exec_stub_32 32/exec_stub.c)
  post_build_executable(rr_exec_stub_32)
  set_target_properties(rr_exec_stub_32
                        PROPERTIES LINK_FLAGS "-static -nostartfiles -nodefaultlibs -m32")

  install(TARGETS rrpreload_32 rr_exec_stub_32
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/rr)
endif()

