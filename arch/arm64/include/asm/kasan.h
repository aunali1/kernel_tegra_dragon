#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#ifndef LINKER_SCRIPT
#ifdef CONFIG_KASAN

#ifdef __ASSEMBLY__

#include <asm/asm-offsets.h>
#include <asm/thread_info.h>

	/*
	 * Remove stale shadow posion for the stack left over from a prior
	 * hot-unplug or idle exit, covering up to offset bytes above the
	 * current stack pointer. Shadow poison above this is preserved.
	 */
	.macro kasan_unpoison_stack offset=0
	add	x1, sp, #\offset
	and	x0, x1, #~(THREAD_SIZE - 1)
	add	x0, x0, #THREAD_INFO_SIZE
	and	x1, x1, #(THREAD_SIZE - 1)
	sub	x1, x1, #THREAD_INFO_SIZE
	bl	kasan_unpoison_shadow
	.endm

#else /* __ASSEMBLY__ */

#include <linux/linkage.h>
#include <asm/memory.h>

/*
 * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
 * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/8 of kernel virtual addresses.
 */
#define KASAN_SHADOW_START      (VA_START)
#define KASAN_SHADOW_END        (KASAN_SHADOW_START + (1UL << (VA_BITS - 3)))

/*
 * This value is used to map an address to the corresponding shadow
 * address by the following formula:
 *     shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
 *
 * (1 << 61) shadow addresses - [KASAN_SHADOW_OFFSET,KASAN_SHADOW_END]
 * cover all 64-bits of virtual addresses. So KASAN_SHADOW_OFFSET
 * should satisfy the following equation:
 *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END - (1ULL << 61)
 */
#define KASAN_SHADOW_OFFSET     (KASAN_SHADOW_END - (1ULL << (64 - 3)))

void kasan_init(void);
asmlinkage void kasan_early_init(void);

#endif /* __ASSEMBLY__ */

#else /* CONFIG_KASAN */

#ifdef __ASSEMBLY__
	.macro kasan_unpoison_stack offset
	.endm
#else /* __ASSEMBLY */
static inline void kasan_init(void) { }
#endif /* __ASSEMBLY__ */

#endif /* CONFIG_KASAN */
#endif /* LINKER_SCRIPT */
#endif /* __ASM_KASAN_H */
