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

# Screen zoo: Pillow for OLED capture (pytest already in base image)
# Base image is Alpine-based, so use apk for native deps then pip for Pillow
RUN apk add --no-cache py3-pillow 2>/dev/null || \
    (apk add --no-cache python3-dev zlib-dev jpeg-dev gcc musl-dev && pip3 install Pillow) 2>/dev/null || \
    echo "WARNING: Pillow not installed — screen zoo will be empty"

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]

