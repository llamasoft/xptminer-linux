#include "global.h"

#define HASHES_PER_PASS ( 16 )

void metiscoin_process(minerMetiscoinBlock_t* block)
{
    // Initial states.  Calculate once, copy on each pass
    
    // keckack512
    // The first (80 - 4) bytes will be the same each time, so pre-calculate
    //   the state after feeding 76 bytes.  The last 4 bytes is the nonce.
    sph_keccak512_context ctx_keccak_init;
    sph_keccak512_init(&ctx_keccak_init);
    sph_keccak512(&ctx_keccak_init, &block->version, 80 - 4);
    
    // shavite512
    sph_shavite512_context ctx_shavite_init;
    sph_shavite512_init(&ctx_shavite_init);
    
    // metis512
    sph_metis512_context ctx_metis_init;
    sph_metis512_init(&ctx_metis_init);
    
    
    // "Working" sets
    sph_keccak512_context   ctx_keccak;
    sph_shavite512_context  ctx_shavite;
    sph_metis512_context    ctx_metis;
    
    uint32 cur_nonce = 0;
    uint32 target = *(uint32*)(block->targetShare+28);
    uint64 hash_temp[HASHES_PER_PASS][8];
    
    for(uint32 n = 0; n < 0x1000; n++)
    {
        if( block->height != monitorCurrentBlockHeight ) { break; }
        
        for(uint32 f = 0; f < 0x8000; f += HASHES_PER_PASS)
        {
            // Hash order = keccak512 -> shavite512 -> metis512
            for (uint32 pass = 0; pass < HASHES_PER_PASS; ++pass) {
                memcpy(&ctx_keccak,  &ctx_keccak_init,  sizeof(sph_keccak512_context) );
                sph_keccak512(&ctx_keccak, &cur_nonce, 4);
                sph_keccak512_close(&ctx_keccak, hash_temp[pass]);
                
                ++cur_nonce;
            }
            
            for (uint32 pass = 0; pass < HASHES_PER_PASS; ++pass) {
                memcpy(&ctx_shavite, &ctx_shavite_init, sizeof(sph_shavite512_context));
                sph_shavite512(&ctx_shavite, hash_temp[pass], 64);
                sph_shavite512_close(&ctx_shavite, hash_temp[pass]);
            }
            
            for (uint32 pass = 0; pass < HASHES_PER_PASS; ++pass) {
                memcpy(&ctx_metis,   &ctx_metis_init,   sizeof(sph_metis512_context)  );
                sph_metis512(&ctx_metis, hash_temp[pass], 64);
                sph_metis512_close(&ctx_metis, hash_temp[pass]);
                
                if( *(uint32*)((uint8*)hash_temp[pass]+28) <= target )
                {
                    totalShareCount++;
                    block->nonce = cur_nonce - HASHES_PER_PASS + pass;
                    xptMiner_submitShare(block);
                }
            }
        }
        
        totalCollisionCount += 0x8000;
    }
}