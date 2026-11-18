// Oracle: @ton/core 0.63.1, independently serializes WalletV4R2 transfers.
// Usage: node ton_vectors_gen.js /path/to/node_modules/@ton/core firmware-root
// Regenerates both native and wire fixtures; npm install --ignore-scripts
// --prefix /tmp/ton-oracle @ton/core@0.63.1 supplies the pinned oracle.
const fs = require('fs');
const path = require('path');
const { Address, beginCell, internal, storeMessageRelaxed, comment } = require(process.argv[2]);
const root = process.argv[3];
const vectors = [];
for (const amount of [0n, 1000000000n, 18446744073709551615n])
  for (const n of [0, 70, 71, 72, 73, 74, 75, 120])
    for (const workchain of [0, -1])
      for (const bounce of [true, false]) {
        const address = new Address(workchain, Buffer.alloc(32, 170));
        const memo = 'A'.repeat(n), seqno = 17, expiry = 1900000000;
        const transfer = beginCell().store(storeMessageRelaxed(internal({
          to: address, value: amount, bounce, body: memo ? comment(memo) : undefined,
        }))).endCell();
        const wallet = beginCell().storeUint(698983191, 32).storeUint(expiry, 32)
          .storeUint(seqno, 32).storeUint(0, 8).storeUint(3, 8).storeRef(transfer).endCell();
        vectors.push({ address: address.toString({ bounceable: bounce, urlSafe: true }),
          amount: amount.toString(), seqno, expiry, bounce, memo, workchain, hash: wallet.hash().toString('hex') });
      }
const cpp = 'static const TonVector TON_VECTORS[] = {\n' + vectors.map(v =>
  `{${JSON.stringify(v.address)}, UINT64_C(${v.amount}), ${v.seqno}, ${v.expiry}, ${v.bounce}, ${JSON.stringify(v.memo)}, ${v.workchain}, ${JSON.stringify(v.hash)}}`
).join(',\n') + '\n};\n';
fs.writeFileSync(path.join(root, 'unittests/firmware/ton_vectors.h'), cpp);
fs.writeFileSync(path.join(root, 'deps/python-keepkey/tests/ton_transfer_vectors.json'), JSON.stringify(vectors, null, 2) + '\n');
