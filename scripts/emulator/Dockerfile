FROM kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2

WORKDIR /kkemu
COPY ./ /kkemu

ARG coinsupport=""

# The emulator and unit suite exercise the same hardware-held alpha root as the
# alpha ARM artifact. Production builds still default to no root.
RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    ${coinsupport} \
    -DCMAKE_COLOR_MAKEFILE=ON \
    -DKK_CLEARSIGN_ALPHA_ROOT=ON

RUN make -j

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]
