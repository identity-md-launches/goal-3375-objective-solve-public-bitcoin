/* Test-only bridge. The driver signs deterministic public SYNTHETIC fixtures. */
#include <stddef.h>
#include "secp256k1.h"

void *oracle_open(void)
{
    secp256k1_selftest();
    return secp256k1_context_create(SECP256K1_CONTEXT_NONE);
}

void oracle_close(void *ctx)
{
    secp256k1_context_destroy(ctx);
}

int oracle_point(const void *ctx, const unsigned char scalar[32],
                 unsigned char compressed[33], unsigned char uncompressed[65])
{
    secp256k1_pubkey point;
    size_t compressed_size = 33;
    size_t uncompressed_size = 65;

    return secp256k1_ec_pubkey_create(ctx, &point, scalar)
        && secp256k1_ec_pubkey_serialize(ctx, compressed, &compressed_size,
                                        &point, SECP256K1_EC_COMPRESSED)
        && secp256k1_ec_pubkey_serialize(ctx, uncompressed, &uncompressed_size,
                                        &point, SECP256K1_EC_UNCOMPRESSED)
        && compressed_size == 33 && uncompressed_size == 65;
}

int oracle_parse(const void *ctx, const unsigned char *sec, size_t size,
                 unsigned char compressed[33])
{
    secp256k1_pubkey point;
    size_t compressed_size = 33;

    return secp256k1_ec_pubkey_parse(ctx, &point, sec, size)
        && secp256k1_ec_pubkey_serialize(ctx, compressed, &compressed_size,
                                        &point, SECP256K1_EC_COMPRESSED)
        && compressed_size == 33;
}

int oracle_sign(const void *ctx, const unsigned char scalar[32],
                const unsigned char digest[32], unsigned char compact[64])
{
    secp256k1_ecdsa_signature sig;

    return secp256k1_ecdsa_sign(ctx, &sig, digest, scalar,
                                secp256k1_nonce_function_rfc6979, NULL)
        && secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &sig);
}

int oracle_verify(const void *ctx, const unsigned char *sec, size_t size,
                  const unsigned char digest[32], const unsigned char compact[64])
{
    secp256k1_pubkey point;
    secp256k1_ecdsa_signature sig;

    return secp256k1_ec_pubkey_parse(ctx, &point, sec, size)
        && secp256k1_ecdsa_signature_parse_compact(ctx, &sig, compact)
        && secp256k1_ecdsa_verify(ctx, &sig, digest, &point);
}
