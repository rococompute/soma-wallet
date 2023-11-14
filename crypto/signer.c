/* Runtime-only testnet/regtest signing primitive. No key constants, IO or imports.
 * API transactions are serial: begin -> set bytes -> derive/sign -> read public
 * outputs. Each operation consumes and wipes inputs, including failure paths. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#define EXPORT(name) __attribute__((export_name(#name))) unsigned name

enum { OK=1, BAD_INDEX=2, BAD_BYTE=3, KEY_INCOMPLETE=4,
       DIGEST_INCOMPLETE=5, INVALID_KEY=6, CRYPTO_ERROR=7,
       NOT_BEGUN=8, BAD_LENGTH=9, NO_OUTPUT=256, OUTPUT_INDEX=257 };
static unsigned char workspace[65536] __attribute__((aligned(64)));
static unsigned char key[32], digest[32], public_key[33], compact[64], der[72];
static uint32_t key_mask, digest_mask;
static unsigned begun, have_public, have_signature, der_size;

/* Volatile stores cannot be removed as dead stores by the optimizer. */
static void wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}
static void wipe_inputs(void) {
    wipe(key, sizeof(key)); wipe(digest, sizeof(digest));
    key_mask = digest_mask = begun = 0;
}
static void wipe_outputs(void) {
    wipe(public_key, sizeof(public_key)); wipe(compact, sizeof(compact));
    wipe(der, sizeof(der)); have_public = have_signature = der_size = 0;
}
static unsigned fail(unsigned code) {
    wipe_inputs(); wipe_outputs(); return code;
}
void secp256k1_default_illegal_callback_fn(const char *s, void *d) {
    (void)s; (void)d; wipe_inputs(); wipe_outputs(); __builtin_trap();
}
void secp256k1_default_error_callback_fn(const char *s, void *d) {
    (void)s; (void)d; wipe_inputs(); wipe_outputs(); __builtin_trap();
}
EXPORT(bridge_clear)(unsigned unused) {
    (void)unused; wipe_inputs(); wipe_outputs(); wipe(workspace,sizeof(workspace)); return OK;
}
EXPORT(bridge_begin)(unsigned key_length, unsigned digest_length) {
    bridge_clear(0);
    if (key_length != 32 || digest_length != 32) return BAD_LENGTH;
    begun = 1; return OK;
}
EXPORT(bridge_key_byte)(unsigned index, unsigned byte) {
    if (!begun) return fail(NOT_BEGUN);
    if (index >= 32) return fail(BAD_INDEX);
    if (byte > 255) return fail(BAD_BYTE);
    key[index] = (unsigned char)byte; key_mask |= UINT32_C(1) << index; return OK;
}
EXPORT(bridge_digest_byte)(unsigned index, unsigned byte) {
    if (!begun) return fail(NOT_BEGUN);
    if (index >= 32) return fail(BAD_INDEX);
    if (byte > 255) return fail(BAD_BYTE);
    digest[index] = (unsigned char)byte; digest_mask |= UINT32_C(1) << index; return OK;
}
static unsigned operate(unsigned signing) {
    secp256k1_context *ctx = NULL;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    unsigned result = CRYPTO_ERROR;
    size_t length = sizeof(public_key), encoded_size = sizeof(der);
    wipe_outputs();
    if (!begun) return fail(NOT_BEGUN);
    if (key_mask != UINT32_MAX) return fail(KEY_INCOMPLETE);
    if (signing && digest_mask != UINT32_MAX) return fail(DIGEST_INCOMPLETE);
    if (secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) > sizeof(workspace))
        return fail(CRYPTO_ERROR);
    ctx = secp256k1_context_preallocated_create(workspace,SECP256K1_CONTEXT_NONE);
    if (!secp256k1_ec_seckey_verify(ctx,key)) { result = INVALID_KEY; goto cleanup; }
    if (!secp256k1_ec_pubkey_create(ctx,&pk,key) ||
        !secp256k1_ec_pubkey_serialize(ctx,public_key,&length,&pk,SECP256K1_EC_COMPRESSED) ||
        length != sizeof(public_key)) goto cleanup;
    if (signing) {
        /* NULL selects libsecp256k1's RFC6979 nonce function; no extra entropy. */
        if (!secp256k1_ecdsa_sign(ctx,&sig,digest,key,NULL,NULL)) goto cleanup;
        secp256k1_ecdsa_signature_normalize(ctx,&sig,&sig);
        if (!secp256k1_ecdsa_verify(ctx,&sig,digest,&pk) ||
            !secp256k1_ecdsa_signature_serialize_compact(ctx,compact,&sig) ||
            !secp256k1_ecdsa_signature_serialize_der(ctx,der,&encoded_size,&sig)) goto cleanup;
        der_size = (unsigned)encoded_size; have_signature = 1;
    }
    have_public = 1; result = OK;
cleanup:
    secp256k1_context_preallocated_destroy(ctx);
    wipe(workspace,sizeof(workspace)); wipe_inputs();
    wipe(&pk,sizeof(pk)); wipe(&sig,sizeof(sig));
    if (result != OK) wipe_outputs();
    return result;
}
EXPORT(bridge_derive)(unsigned unused) { (void)unused; return operate(0); }
EXPORT(bridge_sign)(unsigned unused) { (void)unused; return operate(1); }
EXPORT(bridge_public_byte)(unsigned index) {
    if (!have_public) return NO_OUTPUT;
    return index < sizeof(public_key) ? public_key[index] : OUTPUT_INDEX;
}
EXPORT(bridge_compact_byte)(unsigned index) {
    if (!have_signature) return NO_OUTPUT;
    return index < sizeof(compact) ? compact[index] : OUTPUT_INDEX;
}
EXPORT(bridge_der_byte)(unsigned index) {
    if (!have_signature) return NO_OUTPUT;
    return index < der_size ? der[index] : OUTPUT_INDEX;
}
EXPORT(bridge_der_size)(unsigned unused) { (void)unused; return have_signature ? der_size : NO_OUTPUT; }
/* Boolean audit of input staging only; never exposes input bytes. */
EXPORT(bridge_inputs_cleared)(unsigned unused) {
    (void)unused; unsigned residue = begun | key_mask | digest_mask;
    for (unsigned i=0;i<32;i++) residue |= key[i] | digest[i];
    return residue == 0;
}
