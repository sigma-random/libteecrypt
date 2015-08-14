/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <mpa.h>

/*
 * Remove the #undef if you like debug print outs and assertions
 * for this file.
 */
/*#undef DEBUG_ME */
#include <mpa_debug.h>
#include <mpa_assert.h>

/* This function ends to the real RNG of the platform
 * Depending where the libmpa is used:
 * - kernel side: the implementation is found in the TEECore
 * - user side: the implementation is found in libutee
 */

/*
static unsigned long mpa_prng_next = 1;  

int _rand(void) {  
    mpa_prng_next = mpa_prng_next * 1103515245 + 12345;  
    return((unsigned)(mpa_prng_next/65536) % MPA_RAND_MAX);  
}  
  
void _srand(unsigned seed) {  
    mpa_prng_next = seed;  
}  
*/


static uint8_t value = 1;
static uint32_t ite = 0;	/* 0 is the initial value */

int get_rng_array(void *buf, size_t blen) 
{

    int res = 0;
    char *buf_char = buf;
    int i;

    if (buf_char == NULL)
    {
        res = -1;
        goto _ret_;
    }
    for (i = 0; i < blen; i++)
    {
     	ite++;
    	mpa_srand(ite);
    	buf_char[i] = (256 * ((double)mpa_rand() / MPA_RAND_MAX));
    }

_ret_:
    return res;

}


static uint8_t get_random_byte(void)
{
	uint8_t buf;
	while (get_rng_array(&buf, 1) == -1);

	return buf;
}

/*------------------------------------------------------------
 *
 *  mpa_get_random
 *
 */
void mpa_get_random(mpanum dest, mpanum limit)
{
	int done = 0;

	mpa_wipe(dest);
	if (__mpanum_alloced(dest) < __mpanum_size(limit))
		dest->size = __mpanum_alloced(dest);
	else
		dest->size = __mpanum_size(limit);
	while (!done) {
		for (int idx = 0; idx < dest->size; idx++) {
			mpa_word_t w = 0;
			for (int j = 0; j < BYTES_PER_WORD; j++)
				w = (w << 8) ^ get_random_byte();
			dest->d[idx] = w;
		}
		if (dest->size < __mpanum_size(limit)) {
			done = 1;
		} else {
			mpa_word_t hbi =
			    (mpa_word_t) mpa_highest_bit_index(limit);
			/* 1 <= hbi <= WORD_SIZE */
			hbi = (hbi % WORD_SIZE) + 1;
			if (hbi < WORD_SIZE) {
				hbi = (1 << hbi) - 1;
				dest->d[dest->size - 1] &= hbi;
			}
			done = (mpa_cmp(dest, limit) < 0) ? 1 : 0;
		}
	}
}
