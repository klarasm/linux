/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SHA-256 optimized for x86_64
 *
 * Copyright 2025 Google LLC
 */
#include <asm/fpu/api.h>
#include <crypto/internal/simd.h>
#include <linux/static_call.h>

asmlinkage void sha256_transform_ssse3(struct sha256_block_state *state,
				       const u8 *data, size_t nblocks);
asmlinkage void sha256_transform_avx(struct sha256_block_state *state,
				     const u8 *data, size_t nblocks);
asmlinkage void sha256_transform_rorx(struct sha256_block_state *state,
				      const u8 *data, size_t nblocks);
asmlinkage void sha256_ni_transform(struct sha256_block_state *state,
				    const u8 *data, size_t nblocks);

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_sha256_x86);

DEFINE_STATIC_CALL(sha256_blocks_x86, sha256_transform_ssse3);

static void sha256_blocks(struct sha256_block_state *state,
			  const u8 *data, size_t nblocks)
{
	if (static_branch_likely(&have_sha256_x86) && crypto_simd_usable()) {
		kernel_fpu_begin();
		static_call(sha256_blocks_x86)(state, data, nblocks);
		kernel_fpu_end();
	} else {
		sha256_blocks_generic(state, data, nblocks);
	}
}

#define sha256_mod_init_arch sha256_mod_init_arch
static inline void sha256_mod_init_arch(void)
{
	if (boot_cpu_has(X86_FEATURE_SHA_NI)) {
		static_call_update(sha256_blocks_x86, sha256_ni_transform);
	} else if (cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM,
				     NULL) &&
		   boot_cpu_has(X86_FEATURE_AVX)) {
		if (boot_cpu_has(X86_FEATURE_AVX2) &&
		    boot_cpu_has(X86_FEATURE_BMI2))
			static_call_update(sha256_blocks_x86,
					   sha256_transform_rorx);
		else
			static_call_update(sha256_blocks_x86,
					   sha256_transform_avx);
	} else if (!boot_cpu_has(X86_FEATURE_SSSE3)) {
		return;
	}
	static_branch_enable(&have_sha256_x86);
}
