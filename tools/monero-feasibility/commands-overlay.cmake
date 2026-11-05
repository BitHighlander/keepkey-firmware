# Explicit address-command experiment in the real firmware emulator.
function(monero_address_commands_overlay)
  if(NOT KK_EMULATOR OR NOT KK_BUILD_DYLIB OR KK_BITCOIN_ONLY OR
     NOT KK_MONERO_EMULATOR_RESEARCH)
    message(FATAL_ERROR "Monero address research requires the regular emulator and explicit opt-in")
  endif()
  set(research "${CMAKE_SOURCE_DIR}/tools/monero-feasibility/commands")
  set(generated "${CMAKE_BINARY_DIR}/monero-research")
  file(MAKE_DIRECTORY "${generated}")
  find_program(research_nanopb protoc-gen-nanopb
    HINTS "${NANOPB_DIR}/generator" REQUIRED)
  add_custom_command(
    OUTPUT "${generated}/messages-monero-research.pb.c"
           "${generated}/messages-monero-research.pb.h"
    COMMAND "${PROTOC_BINARY}" "-I${research}"
      "--plugin=protoc-gen-nanopb=${research_nanopb}"
      "--nanopb_out=-f${research}/messages-monero-research.options:${generated}"
      "${research}/messages-monero-research.proto"
    DEPENDS "${research}/messages-monero-research.proto"
            "${research}/messages-monero-research.options"
    VERBATIM)
  add_custom_target(monero-research.pb
    DEPENDS "${generated}/messages-monero-research.pb.c"
            "${generated}/messages-monero-research.pb.h")
  set_source_files_properties("${generated}/messages-monero-research.pb.c"
    TARGET_DIRECTORY kktransport PROPERTIES GENERATED TRUE)
  target_sources(kktransport PRIVATE "${generated}/messages-monero-research.pb.c")
  target_include_directories(kktransport PRIVATE "${generated}")
  add_dependencies(kktransport monero-research.pb)
  add_dependencies(kkfirmware monero-research.pb)
  target_include_directories(kkfirmware PRIVATE "${research}" "${generated}")
  target_compile_definitions(kkfirmware PRIVATE KK_MONERO_EMULATOR_RESEARCH=1)
  target_sources(kkfirmware PRIVATE "${research}/monero_research.c" "${research}/watch-key.c")
  set_source_files_properties("${research}/monero_research.c" "${research}/watch-key.c"
    TARGET_DIRECTORY kkfirmware
    PROPERTIES COMPILE_OPTIONS "-UUSE_MONERO;-DUSE_MONERO=1")
  if(KK_MONERO_KEY_IMAGE_PROTOCOL)
    target_compile_definitions(kkfirmware PRIVATE KK_MONERO_KEY_IMAGE_PROTOCOL=1)
    target_sources(kkfirmware PRIVATE "${research}/key-image.c")
    set_source_files_properties("${research}/key-image.c"
      TARGET_DIRECTORY kkfirmware
      PROPERTIES COMPILE_OPTIONS "-UUSE_MONERO;-DUSE_MONERO=1;-U__SSE__;-U__MMX__")
  endif()
  if(KK_MONERO_CORE_SIGNING)
    if(NOT EXISTS "${KK_MONERO_CORE_LINK_CMAKE}")
      message(FATAL_ERROR "Core signing requires the pinned engine's generated core-link.cmake")
    endif()
    include("${KK_MONERO_CORE_LINK_CMAKE}")
    target_compile_definitions(kkfirmware PRIVATE KK_MONERO_CORE_SIGNING=1)
    target_sources(kkfirmware PRIVATE "${research}/signing-plan.c")
    # The engine is a native-only shared dependency. Its C API accepts the
    # private node inside this process and exports only a signed transaction.
    target_link_libraries(kkemulator_dylib monero_core_signing)
  endif()
  target_compile_options(trezorcrypto PRIVATE -UUSE_MONERO -DUSE_MONERO=1)
  target_sources(trezorcrypto PRIVATE
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/xmr.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/serialize.c"
    "${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/monero/base58.c")
endfunction()
cmake_language(DEFER CALL monero_address_commands_overlay)
