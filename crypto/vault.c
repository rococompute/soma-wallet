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
EXPORT(vault_lock)(unsigned token) {
    (void)token; wipe_inputs(); wipe_outputs(); return 1;
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
