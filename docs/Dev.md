
## Build for dev

### Clone the Source

The sources can be obtained from github:

```
$ git clone git@github.com:keepkey/keepkey-firmware.git
$ git submodule update --init --recursive
```

### Build

To build the firmware using the docker container, use the provided script:

```
$ ./scripts/build/docker/device/debug.sh
```
