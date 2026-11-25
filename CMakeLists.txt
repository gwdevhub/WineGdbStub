cmake_minimum_required(VERSION 3.20)
project(WineGdbStub C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(WineGdbStub SHARED src/dllmain.cpp src/debugger.cpp src/gdbstub.cpp src/packet.cpp)
set_target_properties(WineGdbStub PROPERTIES OUTPUT_NAME WineGdbStub PREFIX "")
target_link_libraries(WineGdbStub PRIVATE ws2_32)
target_link_options(WineGdbStub PRIVATE -static -stdlib=libc++ -unwindlib=libunwind -Wl,-Bstatic -lc++ -lc++abi -lunwind -Wl,-Bdynamic)

add_executable(StubTarget tests/target.cpp)
target_link_libraries(StubTarget PRIVATE user32)
