/* A real NU6.3 Orchard bundle built by the orchard 0.16.0 crate
 * (Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v3(),
 * Flags::CROSS_ADDRESS_DISABLED, anchor) then build_for_pczt) for the
 * "all x12" seed, account 0: one 100000-zat spend from the external address
 * at index 0 and a 90000-zat change output to the internal address at index
 * 0, fee 10000. With cross-address transfers disabled the builder pairs the
 * spend with a fabricated zero-valued output to the spent note's receiver
 * whose enc_ciphertext is random bytes (ZIP 326), and the change with a
 * fabricated zero-valued wallet spend. Flags byte 0x03. Both spends are
 * wallet-controlled (no dummy_sk), so the device signs both. Hex,
 * little-endian encodings as on the wire. */
#ifndef KEEPKEY_UNITTESTS_ZCASH_FABRICATED_VECTORS_H
#define KEEPKEY_UNITTESTS_ZCASH_FABRICATED_VECTORS_H

#include <stdint.h>

typedef struct {
  uint64_t spend_value;
  const char* nullifier; /* the spend's nf, the output note's rho */
  const char* rk;
  const char* alpha;
  const char* cv_net;
  const char* cmx;
  const char* epk;
  const char* enc; /* compact(52) || memo(512) || tag(16) */
  const char* out;
  const char* recipient; /* d(11) || pk_d(32) */
  uint64_t value;
  const char* rseed;
} ZcashFabricatedAction;

static const ZcashFabricatedAction kZcashFabricatedBundle[] = {
    {/* spend_value */ UINT64_C(100000),
     /* nullifier */
     "aed05ebddc392dda842311207fbc3fa84fb454f43fcfac292d87a3e8300ee112",
     /* rk */
     "2c1b8779ac1aca3abec73dfe9b8635be2fae970dfe76237495042fed96c3849f",
     /* alpha */
     "f081a5920a807a9189bc48f6ef5916b48effd77745c905def34316c2af87290c",
     /* cv_net */
     "e80cb524dfe437bebaaeffec6c4543a7f64f48fa4bfa03e1847641b184c3da1d",
     /* cmx */
     "6685ca96b57a11cae02c5c562b3f999713d06fadc697444e4c34f022a1df752a",
     /* epk */
     "e56229ea7072ff2dac9e9d0d3545bc13511e55b849089d3244e3d6667466872c",
     /* enc */
     "8807db653fc5d70f3382f580c2283ed388a87134aec35d3f1108efea6df55ef0"
     "b61eaa33b79f8d53b6a3fb791c83b75876186f6e404ca22e3246bd3d6ee956f6"
     "983d2f7efb6cbb27571832127afd4f48136bdab4ebc68bc2a7c667a4ab231030"
     "19ecd43212a1b6e47307949de23f82998fb33d3f3d15abefaa8052026b17d172"
     "1a508d8af11baa74df8f2f67c3be1a92bea530039b4920a0efedc8ee934485b2"
     "aecd88b5af781c8614d968236504d40d58d64875a808aae0995bb14577c89a26"
     "564f7be2d8a8e871ca8caaeb04c7af0023b25d6930745b0fce3d1b01575d68b9"
     "8965500c6de13f84b14052e24cca3bbe8aa0570ca4196b18a4b2cada1ddd039c"
     "4d6038c809426d1eed7674efb6990b040035cc1b92952dae4d642f9c4c613572"
     "59dc961c5f208a14387b7d8f9b4f5e502a09aa1d292d33e72b489bb5e5cf4ede"
     "7e239d96d07139f9270ec5a3305da1013f0a5b6de6860af11a212c77fe5c1cb9"
     "73888cbc1100e0e07423e879e40365844c2ca9a75b16ed4d032127470ca0e0bd"
     "5de907a32b3aea36512929f5b83863bc1d63b40fce26dc4d58472ec15f2fadd2"
     "24c16985bd5ab01e388502dd22596fe85012a9f74e2ea6c9b9aca2b7bc2298ed"
     "779c61285753e6ba92f0a1a963f33750c105122c7e5ec92d95e2f454e0556682"
     "25ebf956231f22a139c3c31fdb7e4a4a214d296765353e0e45269cef2eebdbf7"
     "e53e3743c4266eb705d30ea2cb567e370eda979b44f33ee2f6233dc8e1f5e844"
     "ff66891d37165675e63b2a10722381a55a92b006dd793ca832010a002d3021ab"
     "5e526af9",
     /* out */
     "a5fe4a96ac820c57db11db73741c6fee879c90635e16c5fd60967be70c58f27d"
     "85e4a135ac87ecc858d88b34df846b2af6035683c138b97876c373328076e8ce"
     "f61c5989e4fee41ed2334b932f947f82",
     /* recipient */
     "da973031634a8938ad1c480f978780693ec7709ba5caf58d8a7eb945586cbed6"
     "45520f17387437bcfdc216",
     /* value */ UINT64_C(0),
     /* rseed */
     "c29d5ab216448f6ebf6388a6251160e7c9fe2413c85ac1cd2340363807ba8840"},
    {/* spend_value */ UINT64_C(0),
     /* nullifier */
     "31aafc80063db2af87ffdee21267ccd1f8a6eda982f7c5816b8f1d99ee580217",
     /* rk */
     "defbdcf42d021aa013d14a391b3cefa8ce94ac9cac96481bfddecab3f2065e06",
     /* alpha */
     "a16c066adf9a10e1696c4fa884a67f93b24d858e8cf06743304ad6cae69a1b06",
     /* cv_net */
     "fd260057cb02e71c9d37554c7fb496b48d5412c1c2707fcf0c8601946dd04c12",
     /* cmx */
     "e35568cf21a2befafa3d8bbd2bf6a19bcdbfe6b6234c303004ba38ba76afed3f",
     /* epk */
     "9b9efea983df2470cfc8d28bcf8c5bfd4f714e6bc08b0a15ab3611b0c7b56101",
     /* enc */
     "b82f1b13e501868055a3f88433481172ee1173402227637b46be3e63cd3fa939"
     "93af3074450b558a4d6ff8ee65bdb04962077060b5c258b3d0f7bc21ec7df69a"
     "a0898c47b6d913186a13fa21c420f0da48e72d167bc3e08bffa1f16d99a11aad"
     "65cf98cc0a0ce37ec679c03dc7c6f1fe9feb619b4eca0c5823f6d413c7a5be12"
     "2aee48f070770d163fde8ad4862df692d4433afe053e6b9e1a50e6cc8cbd37aa"
     "54ce3e014e3dd342496855226cd65896442300161e242a8c4d7b2c19c83df04f"
     "f3ab7c7afcb9fb486d28bda503260b758ac473b618cce25b9d0daf8bafbe64ee"
     "3d52f804c33ee78e25fe5bd6a105d4a1cde143e2d047f0fee8e9cb3645964688"
     "2eb5ade60a1ff79284b81ee817d638ad5e1da8052266171b320a8bf4ec337df3"
     "ebcf087de768b46404f45a23208c8358c644e626152d67cf4e2efa94ff9ac2dd"
     "b8e3c670360523c238f1cc3b961dedade8e90de90927841745c5398f140ac053"
     "8d48561bb372a367933147d239c500c238cf294d05e93c473378f59708f5aefb"
     "375d23df2d0fc1a8f0de90c8fdb6cbb0036eef778c1bdca2731c7fe23a0331ee"
     "4ceb357a52ce552ca0626891f5362c1983fb2656f91b372f0559de8943a9e555"
     "30bc009ede7c222f8748ade9762270f937725a25401ad5a4fdc01a3f1f100289"
     "c5a291b9bfc3bc696e0af71e7199f6555b53ed875aa7ebdfeba1cd3f8c711190"
     "c6d5c64059483983834faf47283ca15682c4966070425d0f305cad882901d70f"
     "d222a8bfeb2077541449b73ce56a8d08aa623c06aa8b38e675eb17fd162b862d"
     "5f777396",
     /* out */
     "28c960f201269936a006ae1cc2cd358b29f981dc52d10448a3c02479855bf89c"
     "ff2a654493f29035ff20daf3ce97d13d514bca41d0d298d0c40834248d1f617f"
     "3db9516428eeca01be53af1da897071e",
     /* recipient */
     "ddae703de8aee25d4e439b8a646b2a5a86f57f802890996e2b3c1f41ff2348a0"
     "f0bb27c032b2e7718c962e",
     /* value */ UINT64_C(90000),
     /* rseed */
     "c53e0dc6ce5562fbf35fd57698514207df3cb42161093b070ba16bffcb93fdd9"},
};

#endif
