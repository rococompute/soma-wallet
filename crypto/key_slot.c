/* One signer-local volatile key slot. PUBLIC test keys only in this build.
 * Separate from the legacy primitive: existing APIs are unchanged.
 * Internal numeric handles identify a key, never consent to sign. Serialize all
 * operations inside one signer. No secret reader, entropy, storage or host IO.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#define EXPORT(name) __attribute__((export_name(#name))) unsigned name
#define LAST_GENERATION UINT32_C(65535)
enum { OK=1, BAD_INDEX=2, BAD_BYTE=3, KEY_INCOMPLETE=4,
       DIGEST_INCOMPLETE=5, INVALID_KEY=6, CRYPTO_ERROR=7,
       NOT_BEGUN=8, BAD_LENGTH=9, STALE_HANDLE=10, EXHAUSTED=11,
       NO_OUTPUT=256, OUTPUT_INDEX=257 };
static unsigned char workspace[65536] __attribute__((aligned(64)));
static unsigned char retained[32], staged[32], digest[32], pub[33], der[72];
static uint32_t generation, active_handle, pending_handle, key_mask, digest_mask;
static unsigned mode, have_public, have_signature, der_size;
static void wipe(void *p,size_t size) {
    volatile unsigned char *b=(volatile unsigned char *)p;
    while(size--) *b++=0;
}
static void wipe_staging(void) {
    wipe(staged,sizeof(staged));wipe(digest,sizeof(digest));
    wipe(workspace,sizeof(workspace));
    key_mask=digest_mask=pending_handle=mode=0;
}
static void wipe_outputs(void) {
    wipe(pub,sizeof(pub));wipe(der,sizeof(der));
    have_public=have_signature=der_size=0;
}
static void erase_slot(void) {wipe(retained,sizeof(retained));active_handle=0;}
EXPORT(slot_clear_transient)(unsigned token) {
    (void)token;wipe_staging();wipe_outputs();return OK;
}
EXPORT(slot_lock)(unsigned token) {
    erase_slot();return slot_clear_transient(token);
}
static unsigned fail(unsigned code,unsigned erase) {
    if(erase) erase_slot();
    slot_clear_transient(0);return code;
}
void secp256k1_default_illegal_callback_fn(const char *s,void *d) {
    (void)s;(void)d;slot_lock(0);__builtin_trap();
}
void secp256k1_default_error_callback_fn(const char *s,void *d) {
    (void)s;(void)d;slot_lock(0);__builtin_trap();
}
/* Every import attempt invalidates the previous slot before any validation.
 * Reserve one generation even for failed attempts. Lock NEVER resets the
 * counter, and exhaustion permanently disables import in this WASM instance.
 * 16-bit handles also avoid signed i32 / arbitrary-N ABI narrowing aliases. */
EXPORT(slot_begin_import)(unsigned length) {
    slot_lock(0);
    if(generation==LAST_GENERATION) return EXHAUSTED;
    ++generation;
    if(length!=32) return BAD_LENGTH;
    mode=1;return OK;
}
EXPORT(slot_key_byte)(unsigned index,unsigned byte) {
    if(mode!=1) return fail(NOT_BEGUN,1);
    if(index>=32) return fail(BAD_INDEX,1);
    if(byte>255) return fail(BAD_BYTE,1);
    staged[index]=(unsigned char)byte;key_mask|=UINT32_C(1)<<index;return OK;
}
EXPORT(slot_commit_import)(unsigned token) {
    (void)token;
    if(mode!=1) return fail(NOT_BEGUN,1);
    if(key_mask!=UINT32_MAX) return fail(KEY_INCOMPLETE,1);
    if(secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE)>sizeof(workspace))
        return fail(CRYPTO_ERROR,1);
    secp256k1_context *ctx=secp256k1_context_preallocated_create(workspace,SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pk;
    size_t length=sizeof(pub);
    unsigned result=CRYPTO_ERROR;
    if(!secp256k1_ec_seckey_verify(ctx,staged)) result=INVALID_KEY;
    else if(secp256k1_ec_pubkey_create(ctx,&pk,staged) &&
        secp256k1_ec_pubkey_serialize(ctx,pub,&length,&pk,SECP256K1_EC_COMPRESSED) && length==sizeof(pub)) {
        memcpy(retained,staged,sizeof(retained));active_handle=generation;
        have_public=1;result=OK;
    }
    secp256k1_context_preallocated_destroy(ctx);wipe(&pk,sizeof(pk));wipe_staging();
    if(result!=OK) return fail(result,1);
    return result;
}
/* Public metadata only. Handle zero always means no retained key. */
EXPORT(slot_handle)(unsigned token) {(void)token;return active_handle;}
EXPORT(slot_begin_digest)(unsigned handle,unsigned length) {
    slot_clear_transient(0);
    if(!handle || handle!=active_handle) return STALE_HANDLE;
    if(length!=32) return BAD_LENGTH;
    pending_handle=handle;mode=2;return OK;
}
EXPORT(slot_digest_byte)(unsigned index,unsigned byte) {
    if(mode!=2) return fail(NOT_BEGUN,0);
    if(index>=32) return fail(BAD_INDEX,0);
    if(byte>255) return fail(BAD_BYTE,0);
    digest[index]=(unsigned char)byte;digest_mask|=UINT32_C(1)<<index;return OK;
}
EXPORT(slot_sign)(unsigned handle) {
    if(!handle || handle!=active_handle) return fail(STALE_HANDLE,0);
    if(mode!=2 || handle!=pending_handle) return fail(NOT_BEGUN,0);
    if(digest_mask!=UINT32_MAX) return fail(DIGEST_INCOMPLETE,0);
    if(secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE)>sizeof(workspace))
        return fail(CRYPTO_ERROR,1);
    wipe_outputs();
    secp256k1_context *ctx=secp256k1_context_preallocated_create(workspace,SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pk;secp256k1_ecdsa_signature sig;
    size_t length=sizeof(pub),size=sizeof(der);
    unsigned result=CRYPTO_ERROR;
    if(secp256k1_ec_seckey_verify(ctx,retained) &&
       secp256k1_ec_pubkey_create(ctx,&pk,retained) &&
       secp256k1_ec_pubkey_serialize(ctx,pub,&length,&pk,SECP256K1_EC_COMPRESSED) && length==sizeof(pub) &&
       secp256k1_ecdsa_sign(ctx,&sig,digest,retained,NULL,NULL)) {
        secp256k1_ecdsa_signature_normalize(ctx,&sig,&sig);
        if(secp256k1_ecdsa_verify(ctx,&sig,digest,&pk) &&
           secp256k1_ecdsa_signature_serialize_der(ctx,der,&size,&sig)) {
            der_size=(unsigned)size;have_public=have_signature=1;result=OK;
        }
    }
    secp256k1_context_preallocated_destroy(ctx);
    wipe(&pk,sizeof(pk));wipe(&sig,sizeof(sig));wipe_staging();
    if(result!=OK) return fail(result,1);
    return result;
}
EXPORT(slot_public_byte)(unsigned index) {
    return !have_public ? NO_OUTPUT : index<sizeof(pub) ? pub[index] : OUTPUT_INDEX;
}
EXPORT(slot_der_byte)(unsigned index) {
    return !have_signature ? NO_OUTPUT : index<der_size ? der[index] : OUTPUT_INDEX;
}
EXPORT(slot_der_size)(unsigned token) {(void)token;return have_signature ? der_size : NO_OUTPUT;}
/* Boolean audits, never byte readers for retained or staged secrets. */
EXPORT(slot_inputs_cleared)(unsigned token) {
    (void)token;unsigned residue=key_mask|digest_mask|pending_handle|mode;
    for(unsigned i=0;i<32;i++) residue|=staged[i]|digest[i];
    for(unsigned i=0;i<sizeof(workspace);i++) residue|=workspace[i];
    return residue==0;
}
EXPORT(slot_locked)(unsigned token) {
    unsigned residue=active_handle|have_public|have_signature|der_size;
    for(unsigned i=0;i<32;i++) residue|=retained[i];
    for(unsigned i=0;i<sizeof(pub);i++) residue|=pub[i];
    for(unsigned i=0;i<sizeof(der);i++) residue|=der[i];
    return residue==0 && slot_inputs_cleared(token);
}
