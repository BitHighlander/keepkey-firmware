"""Execute the reviewed wrapper with fake Docker/compiler tools; never builds or publishes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
source = Path(sys.argv[1]).resolve() / 'scripts/build/docker/device/release.sh'
with tempfile.TemporaryDirectory(prefix='p01-release-') as directory:
    root = Path(directory)
    checkout = root / 'checkout with spaces'
    wrapper = checkout / 'scripts/build/docker/device/release.sh'
    wrapper.parent.mkdir(parents=True)
    shutil.copyfile(source, wrapper)
    stub = root / 'stub'
    stub.mkdir()
    calls = root / 'calls.jsonl'
    cmake_log = root / 'cmake.json'
    scripts = {'docker': "#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['P01_CALLS'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n", 'cmake': "#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['P01_CMAKE'],'w') as f:json.dump(sys.argv[1:],f)\n", 'make': '#!/bin/sh\nmkdir -p bin\ntouch bin/fixture.bin bin/fixture.elf\n', 'chown': '#!/bin/sh\nexit 0\n', 'stat': '#!/bin/sh\nprintf "0:0\\n"\n'}
    for name, body in scripts.items():
        p = stub / name
        p.write_text(body)
        p.chmod(493)
    env = dict(os.environ, PATH=str(stub) + os.pathsep + os.environ['PATH'], P01_CALLS=str(calls), P01_CMAKE=str(cmake_log))
    for arguments in ([], ['-DKK_BITCOIN_ONLY=ON', '-DCMAKE_C_FLAGS=-O2 -g', '-DP01_LITERAL=$(echo must-remain-literal)']):
        calls.write_text('')
        subprocess.run(['bash', '-e', str(wrapper), *arguments], env=env, check=True)
        run = next((c for c in map(json.loads, calls.read_text().splitlines()) if c[0] == 'run'))
        assert run[run.index('-v') + 1] == str(checkout.resolve()) + ':/root/keepkey-firmware:z'
        index = run.index('-c')
        inner = run[index + 1]
        positional = run[index + 2:]
        container = root / 'container'
        container.mkdir(exist_ok=True)
        inner = inner.replace('/root/', str(container) + '/')
        (container / 'keepkey-firmware').mkdir(exist_ok=True)
        subprocess.run(['/bin/sh', '-c', inner, *positional], env=env, check=True)
        actual = json.loads(cmake_log.read_text())
        assert actual[5:] == arguments, (actual, arguments)
        shutil.rmtree(container)
        print('PASS: checkout spaces and', len(arguments), 'CMake arguments preserved through container shell')
