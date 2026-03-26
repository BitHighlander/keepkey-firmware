# CMake generated Testfile for 
# Source directory: /Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware
# Build directory: /Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/build-emu
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test-firmware "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/build-emu/bin/firmware-unit")
set_tests_properties(test-firmware PROPERTIES  _BACKTRACE_TRIPLES "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;174;add_test;/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;0;")
add_test(test-board "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/build-emu/bin/board-unit")
set_tests_properties(test-board PROPERTIES  _BACKTRACE_TRIPLES "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;175;add_test;/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;0;")
add_test(test-crypto "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/build-emu/bin/crypto-unit")
set_tests_properties(test-crypto PROPERTIES  _BACKTRACE_TRIPLES "/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;176;add_test;/Users/highlander/WebstormProjects/keepkey-stack/projects/keepkey-firmware/CMakeLists.txt;0;")
subdirs("lib")
subdirs("tools")
subdirs("deps/crypto")
subdirs("deps/qrenc")
subdirs("deps/sca-hardening")
subdirs("deps/googletest")
subdirs("unittests")
