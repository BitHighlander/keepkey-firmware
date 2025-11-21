set(sources
    pb_common.c
    pb_encode.c
    pb_decode.c)

# Use pre-generated protobuf files from lib/transport/generated/
set(protoc_c_sources_generated
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/types.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-ethereum.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-eos.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-nano.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-binance.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-cosmos.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-osmosis.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-ripple.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-tendermint.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-thorchain.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-mayachain.pb.c
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages.pb.c)

set(protoc_c_headers_generated
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/types.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-ethereum.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-eos.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-nano.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-binance.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-cosmos.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-osmosis.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-ripple.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-tendermint.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-thorchain.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages-mayachain.pb.h
    ${CMAKE_SOURCE_DIR}/lib/transport/generated/messages.pb.h)

# Copy pre-generated files to build directory
add_custom_command(
  OUTPUT
    ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/lib/transport
  COMMAND
    ${CMAKE_COMMAND} -E copy ${protoc_c_sources_generated} ${CMAKE_BINARY_DIR}/lib/transport/
  COMMAND
    ${CMAKE_COMMAND} -E copy ${protoc_c_headers_generated} ${CMAKE_BINARY_DIR}/include/
  COMMAND
    ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp
  DEPENDS
    ${protoc_c_sources_generated} ${protoc_c_headers_generated}
  COMMENT "Copying pre-generated protobuf files")

add_custom_target(kktransport.pb ALL DEPENDS ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp)

# Build the library - protobuf sources will be copied by kktransport.pb target
add_library(kktransport ${sources} ${protoc_c_sources_generated})
add_dependencies(kktransport kktransport.pb)
target_include_directories(kktransport PUBLIC ${CMAKE_BINARY_DIR}/include)
