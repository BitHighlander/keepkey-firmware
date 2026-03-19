FROM kktech/firmware:v15

WORKDIR /kkemu
COPY ./ /kkemu

ARG coinsupport=""
RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Debug \
    ${coinsupport} \
    -DCMAKE_COLOR_MAKEFILE=ON

RUN make -j

# Screen zoo deps (Pillow for OLED capture, pytest for test runner)
RUN pip3 install Pillow pytest 2>/dev/null || \
    (apt-get update -qq && apt-get install -y -qq python3-pip python3-pil && pip3 install pytest) || true

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]

