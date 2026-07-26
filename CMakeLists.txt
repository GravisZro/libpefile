cmake_minimum_required(VERSION 3.25)
project(libpefile VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# check for missing headers
include(CheckIncludeFileCXX)
check_include_file_cxx(format HAVE_STDFORMAT_HEADER)

if(HAVE_STDFORMAT_HEADER)
  set(EXTRA_DIRS "")
  set(EXTRA_LIBS "")
else()
  find_package(fmt)
  set(EXTRA_DIRS polyfill)
  set(EXTRA_LIBS fmt::fmt)
endif()

# ----------------------------------------------------------------------------
# Hashing backend selection (libcrypto preferred, CLI fallback)
# ----------------------------------------------------------------------------
set(PEFILE_HASH_LIB "")
set(PEFILE_HASH_DEFS "")
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    set(PEFILE_HASH_LIB OpenSSL::Crypto)
    list(APPEND PEFILE_HASH_DEFS USE_LIBCRYPTO)
else()
    find_program(MD5SUM_EXECUTABLE md5sum)
    find_program(SHA1SUM_EXECUTABLE sha1sum)
    find_program(SHA256SUM_EXECUTABLE sha256sum)
    find_program(SHA512SUM_EXECUTABLE sha512sum)
    if(MD5SUM_EXECUTABLE AND SHA1SUM_EXECUTABLE AND SHA256SUM_EXECUTABLE AND SHA512SUM_EXECUTABLE)
        list(APPEND PEFILE_HASH_DEFS USE_CLI_HASH)
        list(APPEND PEFILE_HASH_DEFS
            MD5SUM_EXECUTABLE="${MD5SUM_EXECUTABLE}"
            SHA1SUM_EXECUTABLE="${SHA1SUM_EXECUTABLE}"
            SHA256SUM_EXECUTABLE="${SHA256SUM_EXECUTABLE}"
            SHA512SUM_EXECUTABLE="${SHA512SUM_EXECUTABLE}")
    else()
        message(FATAL_ERROR
            "libpefile requires either OpenSSL or "
            "md5sum/sha1sum/sha256sum/sha512sum on PATH for hashing")
    endif()
endif()

set(HEADERS
  src/hashing.hpp
  src/ordlookup.hpp
  src/pe_constants.hpp
  src/pe_containers.hpp
  src/pefile.hpp
  src/pe_structure.hpp
  src/pe_structures.hpp
  src/pe_utils.hpp
)

set(SOURCES
  src/pefile.cpp
  src/ordlookup.cpp
  src/pe_utils.cpp
)


add_library(pefile ${HEADERS} ${SOURCES})

target_include_directories(pefile SYSTEM BEFORE PUBLIC
    ${EXTRA_DIRS}
    src
)

target_link_libraries(pefile PUBLIC ${PEFILE_HASH_LIB} ${EXTRA_LIBS})

target_compile_definitions(pefile PUBLIC ${PEFILE_HASH_DEFS})

target_compile_options(pefile PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

install(TARGETS pefile
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES src/pefile.hpp src/pe_constants.hpp src/pe_structures.hpp
              src/pe_structure.hpp src/pe_containers.hpp src/hashing.hpp
              src/ordlookup.hpp src/pe_utils.hpp
    DESTINATION include
)

enable_testing()

add_executable(test_pefile
    tests/test_pefile.cpp
    tests/pe_builder.hpp
)
target_link_libraries(test_pefile PRIVATE pefile)
target_compile_options(test_pefile PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

add_test(NAME pefile_tests COMMAND test_pefile)

add_executable(test_export
    tests/test_export.cpp
)
target_link_libraries(test_export PRIVATE pefile)
target_compile_options(test_export PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

add_test(NAME export_tests COMMAND test_export)

# ----------------------------------------------------------------------------
# Regression test target (uses real PE binaries from tests/testdata/)
# ----------------------------------------------------------------------------
add_executable(test_pefile_regression
    tests/test_pefile_regression.cpp
    tests/test_hash.hpp
)
target_link_libraries(test_pefile_regression PRIVATE pefile)
target_compile_options(test_pefile_regression PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)
target_compile_definitions(test_pefile_regression PRIVATE
    PEFILE_TESTDATA_DIR="${CMAKE_SOURCE_DIR}/tests/testdata"
)

add_test(NAME pefile_regression_tests COMMAND test_pefile_regression)
