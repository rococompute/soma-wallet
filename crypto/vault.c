/* TEST-ONLY envelope foundation; no RNG, persistence, imports or real-key seal.
 * All crypto primitives are pinned Monocypher, never implemented here.
 * Call serially inside the signer: begin -> stage -> seal/open -> read -> lock.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "monocypher.h"
#define EXPORT(name) __attribute__((export_name(#name))) unsigned name
#define HEADER 52
#define ENVELOPE 100
#define BLOCKS 64
#define PASSES 3
static uint64_t work[BLOCKS * 128];
static uint8_t password[128], secret[32], envelope[ENVELOPE], plain[32], derived[32];
static uint8_t seen_password[128], seen_secret[32], seen_envelope[ENVELOPE];
static unsigned pass_length, begun, have_envelope, have_plain;
/* Header: 'SWVT', version=1, KDF=1 (Argon2id13), AEAD=1 (XChaCha20-Poly1305),
 * lanes=1, memory KiB LE16=64, passes=3, reserved=0, salt16, nonce24.
 * All 52 header bytes are authenticated. ciphertext32 follows, then tag16. */
static const uint8_t prefix[12] = {'S','W','V','T',1,1,1,1,64,0,3,0};
static void wipe_inputs(void) {
    crypto_wipe(password,sizeof(password)); crypto_wipe(secret,sizeof(secret));
    crypto_wipe(derived,sizeof(derived)); crypto_wipe(work,sizeof(work));
    crypto_wipe(seen_password,sizeof(seen_password));
    crypto_wipe(seen_secret,sizeof(seen_secret));
    crypto_wipe(seen_envelope,sizeof(seen_envelope));
    pass_length=begun=0;
}
static void wipe_outputs(void) {
    crypto_wipe(envelope,sizeof(envelope)); crypto_wipe(plain,sizeof(plain));
    have_envelope=have_plain=0;
}
static void prod_wipe(void);
EXPORT(vault_lock)(unsigned token) {
    (void)token; wipe_inputs(); wipe_outputs(); prod_wipe(); return 1;
}
static unsigned fail(unsigned code) {vault_lock(0); return code;}
EXPORT(vault_begin)(unsigned length) {
    vault_lock(0);
    if (length < 1 || length > sizeof(password)) return 2;
    pass_length=length; begun=1; return 1;
}
/* Slots: password=0, scalar=1, envelope/header=2. No generic secret reader. */
EXPORT(vault_put)(unsigned slot, unsigned index, unsigned byte) {
    if (!begun) return fail(3);
    if (byte>255) return fail(4);
    uint8_t *target, *seen; unsigned size;
    switch(slot) {
    case 0: target=password;seen=seen_password;size=pass_length;break;
    case 1: target=secret;seen=seen_secret;size=32;break;
    case 2: target=envelope;seen=seen_envelope;size=ENVELOPE;break;
    default:return fail(5);
    }
    if(index>=size) return fail(5);
    target[index]=(uint8_t)byte; seen[index]=1; return 1;
}
static unsigned complete(const uint8_t *seen,unsigned count) {
    unsigned missing=0; for(unsigned i=0;i<count;i++) missing |= seen[i]^1;
    return missing==0;
}
static void kdf(void) {
    crypto_argon2_config config={CRYPTO_ARGON2_ID,BLOCKS,PASSES,1};
    crypto_argon2_inputs inputs={password,envelope+12,pass_length,16};
    crypto_argon2(derived,32,work,config,inputs,crypto_argon2_no_extras);
}
/* Deliberately named test-only: accepts PUBLIC salt/nonce supplied by tests.
 * Rejects missing inputs; no random values are invented or reused internally. */
EXPORT(vault_test_seal)(unsigned token) {
    (void)token;
    if(!begun) return fail(3);
    if(!complete(seen_password,pass_length) || !complete(seen_secret,32) ||
       !complete(seen_envelope+12,40)) return fail(6);
    memcpy(envelope,prefix,sizeof(prefix));
    kdf();
    crypto_aead_lock(envelope+HEADER,envelope+HEADER+32,derived,envelope+28,
                     envelope,HEADER,secret,32);
    wipe_inputs(); crypto_wipe(plain,sizeof(plain));
    have_plain=0;have_envelope=1; return 1;
}
EXPORT(vault_open)(unsigned length) {
    if(!begun) return fail(3);
    if(length!=ENVELOPE) return fail(2);
    if(!complete(seen_password,pass_length) || !complete(seen_envelope,ENVELOPE)) return fail(6);
    /* Fixed parameters checked BEFORE allocation/KDF; rejects downgrade/DoS. */
    if(memcmp(envelope,prefix,sizeof(prefix))!=0) return fail(7);
    kdf();
    if(crypto_aead_unlock(plain,envelope+HEADER+32,derived,envelope+28,
                          envelope,HEADER,envelope+HEADER,32)) return fail(8);
    wipe_inputs(); crypto_wipe(envelope,sizeof(envelope));
    have_envelope=0;have_plain=1;return 1;
}
EXPORT(vault_envelope_byte)(unsigned index) {
    return !have_envelope ? 256 : index<ENVELOPE ? envelope[index] : 257;
}
/* EXPLICIT signer-internal open path, never exposed to browser/logs. */
EXPORT(vault_opened_byte)(unsigned index) {
    return !have_plain ? 256 : index<32 ? plain[index] : 257;
}
EXPORT(vault_inputs_cleared)(unsigned token) {
    (void)token; unsigned residue=begun|pass_length;
    for(unsigned i=0;i<sizeof(password);i++) residue|=password[i]|seen_password[i];
    for(unsigned i=0;i<32;i++) residue|=secret[i]|derived[i]|seen_secret[i];
    for(unsigned i=0;i<ENVELOPE;i++) residue|=seen_envelope[i];
    for(unsigned i=0;i<sizeof(work)/sizeof(work[0]);i++) residue|=(work[i]!=0);
    return residue==0;
}
/* No production seal entry: lack of a verified signer RNG is a hard blocker. */
EXPORT(vault_seal)(unsigned token) {(void)token;return fail(9);}
/* Boolean lock audit, including the explicit open output; exposes no bytes. */
EXPORT(vault_locked)(unsigned token) {
    unsigned residue=have_plain|have_envelope;
    for(unsigned i=0;i<32;i++) residue|=plain[i];
    for(unsigned i=0;i<ENVELOPE;i++) residue|=envelope[i];
    return !residue && vault_inputs_cleared(token);
}

/* ---- SWVP v1 production envelope primitives (wallet_vault_format.soma). ----
 * Exactly the merged RFC 9106 profile: Argon2id v19, 65536 KiB, 3 passes,
 * 4 lanes, 32-byte key; XChaCha20-Poly1305 with the complete 64-byte header as
 * associated data. Salt and nonce are CALLER-SUPPLIED in this step: nothing
 * here generates randomness. The 64 MiB Argon2 workspace is obtained with
 * memory.grow on first use (so SWVT users keep the small initial memory) and is
 * wiped after every KDF by the pinned library itself (see p_kdf). Slots: password=0, key=1, envelope=2 (salt at 24 and
 * nonce at 40 for sealing, all 112 bytes for opening). Status codes as above. */
#define P_HEADER 64
#define P_ENVELOPE 112
#define P_BLOCKS 65536
#define P_PASSES 3
#define P_LANES 4
static const uint8_t p_prefix[24] = {'S','W','V','P',1,1,19,1,0,4,64,0,
    0x00,0x00,0x01,0x00, 3,0,0,0, 32,0,16,24};
static uint8_t p_password[128], p_secret[32], p_envelope[P_ENVELOPE], p_plain[32], p_derived[32];
static uint8_t p_seen_password[128], p_seen_secret[32], p_seen_envelope[P_ENVELOPE];
static unsigned p_pass_length, p_begun, p_have_envelope, p_have_plain;
static uint8_t *p_work;   /* 64 MiB, grown once */
/* Private: 1 from before Argon2 starts until its guaranteed wipe has returned.
 * Fresh memory.grow pages are zero (WASM spec), so a new workspace is clean.
 * Any dirty workspace (e.g. an interrupted KDF) is still swept by prod_wipe. */
static unsigned p_work_dirty;
static void prod_wipe(void) {
    crypto_wipe(p_password,sizeof(p_password)); crypto_wipe(p_secret,sizeof(p_secret));
    crypto_wipe(p_envelope,sizeof(p_envelope)); crypto_wipe(p_plain,sizeof(p_plain));
    crypto_wipe(p_derived,sizeof(p_derived));
    crypto_wipe(p_seen_password,sizeof(p_seen_password));
    crypto_wipe(p_seen_secret,sizeof(p_seen_secret));
    crypto_wipe(p_seen_envelope,sizeof(p_seen_envelope));
    if (p_work && p_work_dirty) { crypto_wipe(p_work,(size_t)P_BLOCKS*1024); p_work_dirty=0; }
    p_pass_length=p_begun=p_have_envelope=p_have_plain=0;
}
static unsigned p_fail(unsigned code) { prod_wipe(); return code; }
static int p_workspace(void) {
    if (p_work) return 1;
    long old = __builtin_wasm_memory_grow(0, (P_BLOCKS*1024)/65536);
    if (old < 0) return 0;
    p_work = (uint8_t *)((uintptr_t)old * 65536u); return 1;
}
static void p_kdf(void) {
    crypto_argon2_config config={CRYPTO_ARGON2_ID,P_BLOCKS,P_PASSES,P_LANES};
    crypto_argon2_inputs inputs={p_password,p_envelope+24,p_pass_length,16};
    p_work_dirty=1;
    crypto_argon2(p_derived,32,p_work,config,inputs,crypto_argon2_no_extras);
    /* Pinned Monocypher 4.0.3 crypto_argon2 ends with a volatile ZERO of
     * 128*nb_blocks u64 words of work_area (= P_BLOCKS*1024 bytes, the whole
     * workspace) before returning, so a second full sweep here is redundant.
     * tests/vault-workspace-check.mjs inspects the actual memory region. */
    p_work_dirty=0;
}
EXPORT(vault_prod_begin)(unsigned length) {
    prod_wipe();
    if (length < 1 || length > sizeof(p_password)) return 2;
    p_pass_length=length; p_begun=1; return 1;
}
EXPORT(vault_prod_put)(unsigned slot, unsigned index, unsigned byte) {
    if (!p_begun) return p_fail(3);
    if (byte>255) return p_fail(4);
    uint8_t *target, *seen; unsigned size;
    switch(slot) {
    case 0: target=p_password;seen=p_seen_password;size=p_pass_length;break;
    case 1: target=p_secret;seen=p_seen_secret;size=32;break;
    case 2: target=p_envelope;seen=p_seen_envelope;size=P_ENVELOPE;break;
    default:return p_fail(5);
    }
    if(index>=size) return p_fail(5);
    target[index]=(uint8_t)byte; seen[index]=1; return 1;
}
/* Seal with caller-supplied salt/nonce (no entropy is generated here). */
EXPORT(vault_prod_seal)(unsigned token) {
    (void)token;
    if(!p_begun) return p_fail(3);
    if(!complete(p_seen_password,p_pass_length) || !complete(p_seen_secret,32) ||
       !complete(p_seen_envelope+24,40)) return p_fail(6);
    for(unsigned i=0;i<24;i++) if(p_seen_envelope[i]) return p_fail(6);
    if(!p_workspace()) return p_fail(10);
    memcpy(p_envelope,p_prefix,sizeof(p_prefix));
    p_kdf();
    crypto_aead_lock(p_envelope+P_HEADER,p_envelope+P_HEADER+32,p_derived,p_envelope+40,
                     p_envelope,P_HEADER,p_secret,32);
    uint8_t out[P_ENVELOPE]; memcpy(out,p_envelope,sizeof(out));
    prod_wipe(); memcpy(p_envelope,out,sizeof(out)); crypto_wipe(out,sizeof(out));
    p_have_envelope=1; return 1;
}
EXPORT(vault_prod_open)(unsigned length) {
    if(!p_begun) return p_fail(3);
    if(length!=P_ENVELOPE) return p_fail(2);
    if(!complete(p_seen_password,p_pass_length) || !complete(p_seen_envelope,P_ENVELOPE)) return p_fail(6);
    /* Exact profile and framing checked BEFORE workspace growth or the KDF. */
    if(memcmp(p_envelope,p_prefix,sizeof(p_prefix))!=0) return p_fail(7);
    if(!p_workspace()) return p_fail(10);
    p_kdf();
    uint8_t plain[32];
    if(crypto_aead_unlock(plain,p_envelope+P_HEADER+32,p_derived,p_envelope+40,
                          p_envelope,P_HEADER,p_envelope+P_HEADER,32)) {
        crypto_wipe(plain,sizeof(plain)); return p_fail(8);
    }
    prod_wipe(); memcpy(p_plain,plain,32); crypto_wipe(plain,sizeof(plain));
    p_have_plain=1; return 1;
}
EXPORT(vault_prod_envelope_byte)(unsigned index) {
    return !p_have_envelope ? 256 : index<P_ENVELOPE ? p_envelope[index] : 257;
}
/* EXPLICIT signer-internal open path, never exposed to browser/logs. */
EXPORT(vault_prod_opened_byte)(unsigned index) {
    return !p_have_plain ? 256 : index<32 ? p_plain[index] : 257;
}
/* Boolean audit: production staging, derived key, workspace and outputs. */
EXPORT(vault_prod_cleared)(unsigned token) {
    (void)token; unsigned residue=p_begun|p_pass_length|p_have_envelope|p_have_plain;
    for(unsigned i=0;i<sizeof(p_password);i++) residue|=p_password[i]|p_seen_password[i];
    for(unsigned i=0;i<32;i++) residue|=p_secret[i]|p_seen_secret[i]|p_derived[i]|p_plain[i];
    for(unsigned i=0;i<P_ENVELOPE;i++) residue|=p_envelope[i]|p_seen_envelope[i];
    if(p_work) for(size_t i=0;i<(size_t)P_BLOCKS*1024;i+=1) residue|=p_work[i];
    return residue==0;
}
