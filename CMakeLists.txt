project(lora-opcua-server)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(src SRC_LIST)
set (EXE_NAME lora-opcua-server)
add_executable(${EXE_NAME} ${SRC_LIST})
target_link_libraries(${EXE_NAME}) 

