FROM kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2

WORKDIR /kkemu
COPY ./ /kkemu

ARG coinsupport=""

# KK_CLEARSIGN_TEST_ROOT compiles the TEST clear-signing root key in. The
# emulator is never a hardware release and the unit tests run inside this
# image, so this is the one build that gets a root at all -- ARM builds do not
# pass it and ship an all-zero root, leaving the suppression branch
# unreachable. See lib/firmware/clearsign_root.c.
RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Debug \
    ${coinsupport} \
    -DCMAKE_COLOR_MAKEFILE=ON \
    -DKK_CLEARSIGN_TEST_ROOT=ON

RUN make -j

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]
