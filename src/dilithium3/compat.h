#ifndef PQCLEAN_COMPAT_H
#define PQCLEAN_COMPAT_H

#include <stdint.h>
#include <stddef.h>

// Compatibility macros
#if defined(_MSC_VER)
#define PQCLEAN_INLINE __inline
#else
#define PQCLEAN_INLINE inline
#endif

#if defined(_MSC_VER)
#define PQCLEAN_ALIGN(x) __declspec(align(x))
#else
#define PQCLEAN_ALIGN(x) __attribute__((aligned(x)))
#endif

#if defined(_MSC_VER)
#define PQCLEAN_RESTRICT __restrict
#else
#define PQCLEAN_RESTRICT restrict
#endif

#endif /* PQCLEAN_COMPAT_H */
