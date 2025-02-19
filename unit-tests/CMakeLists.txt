cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for Ledger Nano application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST)

include_directories(../src)
include_directories(../deps/ledger-zxlib/include)
include_directories(../deps/jsmn/src)


add_executable(test_rlp test_rlp.c)
add_executable(test_tx_metadata test_tx_metadata.c)
add_executable(test_parser parser.c)

add_library(base58 SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32 SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
add_library(read SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(write SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)
add_library(format SHARED $ENV{BOLOS_SDK}/lib_standard_app/format.c)
add_library(varint SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
add_library(apdu_parser SHARED $ENV{BOLOS_SDK}/lib_standard_app/parser.c)
add_library(rlp ../src/rlp.c)
add_library(tx_metadata ../src/tx_metadata.c)
add_library(hexutils ../deps/ledger-zxlib/src/hexutils.c)
add_library(mocks utils/mocks.c)
add_library(parser_tx ../src/parser_tx.c)
add_library(parser_impl ../src/parser_impl.c)
add_library(json_parser ../src/json/json_parser.c)
add_library(jsmn ../deps/jsmn/src/jsmn.c)
add_library(hdpath ../src/hdpath.c)

target_link_libraries(test_rlp PUBLIC
                      cmocka
                      gcov
                      hexutils
                      rlp
                      mocks)

target_link_libraries(test_tx_metadata PUBLIC
                      cmocka
                      gcov
                      tx_metadata
                      mocks)

target_link_libraries(test_parser PUBLIC
                      cmocka
                      gcov
                      parser_tx
                      parser_impl
                      tx_metadata
                      rlp
                      json_parser
                      jsmn
                      hdpath
                      mocks)

add_test(test_rlp test_rlp)
add_test(test_tx_metadata test_tx_metadata)
add_test(test_parser test_parser)

add_definitions(-D__APPLE__)

