cmake_minimum_required(VERSION 3.10)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD 17)
set(COMPILER_FLAGS "-Wall --std=c++17 -march=native -funroll-loops -fconstexpr-steps=134217728")
set(LINKER_FLAGS "-static-libstdc++ -static-libgcc")
set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LINKER_FLAGS}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenMP REQUIRED)

add_subdirectory(crypto)

include_directories(${CMAKE_CURRENT_LIST_DIR}/crypto)

add_executable(attack attack.cpp)
target_link_libraries(attack SPNBOX8 GF28 COMPONENT)

add_executable(attack_b attack_bench.cpp)
target_link_libraries(attack_b SPNBOX8 GF28 COMPONENT)

add_executable(attack16 attack16.cpp)
#target_link_libraries(attack16 SPNBOX16 COMPONENT -lgivaro -lgmp)
target_link_libraries(attack16 SPNBOX16 GF216 COMPONENT)
