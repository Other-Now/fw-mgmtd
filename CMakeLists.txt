cmake_minimum_required(VERSION 3.20)
project(fw-mgmtd CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(FWM_SANITIZE "ASan + UBSan" OFF)
option(FWM_HARDEN "Hardened build: FORTIFY, stack protector, CET, full RELRO, PIE" ON)
option(FWM_FUZZ "Build libFuzzer targets (clang only)" OFF)
# Where scripts/deps.sh unpacked libssh-dev when there is no sudo; empty in CI
set(FWM_DEPS_ROOT "" CACHE PATH "Extra prefix with usr/include + usr/lib")

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
if(FWM_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
  add_link_options(-fsanitize=address,undefined)
endif()
if(FWM_HARDEN AND NOT FWM_SANITIZE AND NOT FWM_FUZZ)
  add_compile_options(-D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong
                      -fstack-clash-protection -fcf-protection=full -fPIE -O2)
  add_link_options(-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)
endif()

set(LIBSSH_INC "")
set(LIBSSH_LIB ssh)
if(FWM_DEPS_ROOT)
  set(LIBSSH_INC ${FWM_DEPS_ROOT}/usr/include)
  set(LIBSSH_LIB ${FWM_DEPS_ROOT}/usr/lib/x86_64-linux-gnu/libssh.so)
endif()

# everything except main() and the SSH server: shared by daemon, tests, benches, fuzzers
add_library(fwcore STATIC
  src/util.cpp src/schema.cpp src/config.cpp src/store.cpp src/syslog.cpp
  src/license.cpp src/http.cpp src/certmgr.cpp src/cli.cpp src/lineedit.cpp src/api.cpp)
target_include_directories(fwcore PUBLIC src third_party)
target_link_libraries(fwcore PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

if(NOT FWM_FUZZ)
  add_executable(fw-mgmtd src/main.cpp src/ssh_server.cpp)
  target_include_directories(fw-mgmtd PRIVATE ${LIBSSH_INC})
  target_link_libraries(fw-mgmtd PRIVATE fwcore ${LIBSSH_LIB})

  add_executable(fw-license tools/fw-license.cpp)
  target_link_libraries(fw-license PRIVATE fwcore)

  add_executable(fwbench tools/fwbench.cpp)
  target_include_directories(fwbench PRIVATE ${LIBSSH_INC})
  target_link_libraries(fwbench PRIVATE fwcore ${LIBSSH_LIB})

  add_executable(unit_tests tests/unit_tests.cpp)
  target_link_libraries(unit_tests PRIVATE fwcore)
  enable_testing()
  add_test(NAME unit COMMAND unit_tests)
else()
  foreach(t cli config license http)
    add_executable(fuzz_${t} fuzz/fuzz_${t}.cpp)
    target_compile_options(fuzz_${t} PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer)
    target_link_libraries(fuzz_${t} PRIVATE fwcore)
  endforeach()
  target_compile_options(fwcore PRIVATE -fsanitize=fuzzer-no-link)
endif()
