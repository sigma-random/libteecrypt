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

/*************************************************************
 *
 *   GLOBAL CONSTANTS
 *
 *************************************************************/

const mpa_num_base const_largest_deci_base = {
	1, 1, {LARGEST_DECIMAL_BASE_IN_WORD} };
const mpa_num_base Const_1_LShift_Base = { 2, 2, {0, 1} };
const mpa_num_base const_one = { 1, 1, {1} };

/*************************************************************
 *
 *   HELPERS
 *
 *************************************************************/

/*  --------------------------------------------------------------------
 *  Function:   __mpa_set_unused_digits_to_zero
 *
 *
 */
void __mpa_set_unused_digits_to_zero(mpanum n)
{
	int i;

	/*
	 * Pointer arithmetics on *mpa_word_t will put the
	 * pointer at the right place.
	 */
	i = __mpanum_size(n);
	mpa_memset((n->d) + i, 0, (n->alloc - i) * BYTES_PER_WORD);
}

/*************************************************************
 *
 *   LIB FUNCTIONS
 *
 *************************************************************/

/*------------------------------------------------------------
 *
 *  mpa_wipe
 *
 *  fills the digits with zero and set size = 0;
 *
 */
void mpa_wipe(mpanum var)
{
	mpa_memset(var->d, 0, var->alloc * BYTES_PER_WORD);
	var->size = 0;
}

/*------------------------------------------------------------
 *
 *  mpa_copy
 *
 *  Copies src to dest.
 *
 *  Doesn't check if src fits into dest
 *
 */
void mpa_copy(mpanum dest, const mpanum src)
{
	if (dest == src)
		return;

	mpa_memcpy(dest->d, src->d, __mpanum_size(src) * BYTES_PER_WORD);
	dest->size = src->size;
}

/*  --------------------------------------------------------------------
 *  Function:  mpa_abs
 *  Computes the absolut value of src and puts it in dest
 *  dest and src can be the same mpanum
 */
void mpa_abs(mpanum dest, const mpanum src)
{
	mpa_copy(dest, src);
	__mpanum_set_sign(dest, MPA_POS_SIGN);
}

/*  --------------------------------------------------------------------
 *  Function:  mpa_highest_bit_index
 *  Returns the index of the highest 1 in |src|.
 *  The index starts at 0 for the least significant bit.
 *  If src == zero, it will return -1
 *
 */
int mpa_highest_bit_index(const mpanum src)
{
	mpa_word_t w;
	mpa_word_t b;

	if (__mpanum_is_zero(src))
		return -1;

	w = __mpanum_msw(src);

	for (b = 0; b < WORD_SIZE; b++) {
		w >>= 1;
		if (w == 0)
			break;
	}
	return (int)(__mpanum_size(src) - 1) * WORD_SIZE + b;
}

/*------------------------------------------------------------
 *
 *  mpa_get_bit
 *
 *  Returns the value of the idx:th bit in src.
 *  if idx is larger than the number of bits in src,
 *  it returns zero.
 *
 */
uint32_t mpa_get_bit(const mpanum src, uint32_t idx)
{
	mpa_word_t w;		/* word of bitIndex */
	unsigned long b;	/* bit number in that word */

	w = idx >> LOG_OF_WORD_SIZE;
	b = idx & (WORD_SIZE - 1);

	if (w > __mpanum_size(src))
		return 0;
	b = (1 << b);
	return ((src->d[w] & b) != 0);
}

/*------------------------------------------------------------
 *
 *  mpa_CanHold
 *
 *  returns 1 if dest can hold src without overflowing, 0 otherwise
 */
int mpa_can_hold(mpanum dest, const mpanum src)
{
	return (__mpanum_alloced(dest) >= __mpanum_size(src) ? 1 : 0);
}

/*------------------------------------------------------------
 *
 *  mpa_parity
 *
 */
int mpa_parity(const mpanum src)
{
	return (((__mpanum_lsw(src) & 0x01) ==
		 0) ? MPA_EVEN_PARITY : MPA_ODD_PARITY);
}

/*------------------------------------------------------------
 *
 *  mpa_constant_one
 *
 */
mpanum mpa_constant_one(void)
{
	return (mpanum)&const_one;
}
