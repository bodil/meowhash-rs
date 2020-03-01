// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdio.h>
#include "meow_hash_x64_aesni.h"

meow_state *meow_begin(void *seed128)
{
    meow_state *state = malloc(sizeof(struct meow_state));
    if (!state)
    {
        return state;
    }
    MeowBegin(state, seed128);
    return state;
}

void meow_free(meow_state *state)
{
    free(state);
}

void meow_absorb(meow_state *state, meow_umm len, void *source)
{
    MeowAbsorb(state, len, source);
}

void meow_end(meow_state *state, meow_u8 *store128)
{
    MeowEnd(state, store128);
}

meow_u128 meow_hash(void *seed, meow_umm len, void *source)
{
    return MeowHash(seed, len, source);
}

void meow_expand_seed(meow_umm len, void *input, meow_u8 *result)
{
    MeowExpandSeed(len, input, result);
}
