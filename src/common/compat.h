#ifndef PQCLEAN_COMPAT_H
#define PQCLEAN_COMPAT_H

#include <stdint.h>
#include <stddef.h>

// Compatibility macros for cross-platform development

// Inline keyword
#if defined(_MSC_VER)
#define PQCLEAN_INLINE __inline
#else
#define PQCLEAN_INLINE inline
#endif

// Alignment
#if defined(_MSC_VER)
#define PQCLEAN_ALIGN(x) __declspec(align(x))
#else
#define PQCLEAN_ALIGN(x) __attribute__((aligned(x)))
#endif

// Restrict keyword
#if defined(_MSC_VER)
#define PQCLEAN_RESTRICT __restrict
#else
#define PQCLEAN_RESTRICT restrict
#endif

// Branch prediction hints (not supported on MSVC)
#if defined(__GNUC__) || defined(__clang__)
#define PQCLEAN_LIKELY(x) __builtin_expect(!!(x), 1)
#define PQCLEAN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define PQCLEAN_LIKELY(x) (x)
#define PQCLEAN_UNLIKELY(x) (x)
#endif

// Constant time operations
#if defined(_MSC_VER)
#define PQCLEAN_CT_SELECT(cond, a, b) ((-(cond) & ((a) ^ (b))) ^ (b))
#else
#define PQCLEAN_CT_SELECT(cond, a, b) ((-(cond) & ((a) ^ (b))) ^ (b))
#endif

// Branch prediction prevention (empty macro for compatibility)
#define PQCLEAN_PREVENT_BRANCH_HACK(x) (x)

#endif /* PQCLEAN_COMPAT_H */