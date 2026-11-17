#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
void secp256k1_default_illegal_callback_fn(const char *str, void *data) { (void)str; (void)data; __builtin_trap(); }
void secp256k1_default_error_callback_fn(const char *str, void *data) { (void)str; (void)data; __builtin_trap(); }
static unsigned char workspace[65536] __attribute__((aligned(64)));
__attribute__((export_name("probe"))) unsigned probe(unsigned key_byte, unsigned digest_byte) {
    unsigned char key[32] = {0}, digest[32], pub[33], compact[64];
    key[31] = key_byte & 255;
    memset(digest, digest_byte & 255, sizeof(digest));
    if (secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) > sizeof(workspace)) return 0;
    secp256k1_context *ctx = secp256k1_context_preallocated_create(workspace, SECP256K1_CONTEXT_NONE);
    if (!secp256k1_ec_seckey_verify(ctx, key)) { secp256k1_context_preallocated_destroy(ctx); return 0; }
    secp256k1_pubkey pk; secp256k1_ecdsa_signature signature, corrupt;
    unsigned result = 1;
    if (secp256k1_ec_pubkey_create(ctx, &pk, key)) result |= 2;
    size_t pub_size = sizeof(pub);
    static const unsigned char generator[33] = {0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    if (secp256k1_ec_pubkey_serialize(ctx,pub,&pub_size,&pk,SECP256K1_EC_COMPRESSED) && pub_size==33 && key_byte==1 && memcmp(pub,generator,33)==0) result |= 4;
    if (secp256k1_ecdsa_sign(ctx,&signature,digest,key,NULL,NULL) && secp256k1_ecdsa_verify(ctx,&signature,digest,&pk)) result |= 8;
    secp256k1_ecdsa_signature_serialize_compact(ctx,compact,&signature);compact[0] ^= 1;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx,&corrupt,compact) || !secp256k1_ecdsa_verify(ctx,&corrupt,digest,&pk)) result |= 16;
    memset(key,0,sizeof(key));secp256k1_context_preallocated_destroy(ctx);return result;
}
