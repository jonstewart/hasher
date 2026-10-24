#pragma once

#include <cstdint>

// In-code probe instrumentation. Array-touch and comparison counters compiled
// in ONLY under -DHASHER_PROBE; otherwise every macro is a no-op and these
// accessors return 0, so the instrumented build and the shipped build are the
// same source. Used by the eval harness as a machine-independent cross-check
// against perf counters (disagreement is itself a red flag).

#ifdef HASHER_PROBE

extern uint64_t g_hasher_probe_touches;
extern uint64_t g_hasher_probe_cmps;

#define HASHER_PROBE_TOUCH(addr) (++g_hasher_probe_touches, (void)(addr))
#define HASHER_PROBE_CMP()       (++g_hasher_probe_cmps)

inline void hasher_probe_reset() { g_hasher_probe_touches = 0; g_hasher_probe_cmps = 0; }
inline uint64_t hasher_probe_touches() { return g_hasher_probe_touches; }
inline uint64_t hasher_probe_cmps() { return g_hasher_probe_cmps; }

#else

#define HASHER_PROBE_TOUCH(addr) ((void)0)
#define HASHER_PROBE_CMP()       ((void)0)

inline void hasher_probe_reset() {}
inline uint64_t hasher_probe_touches() { return 0; }
inline uint64_t hasher_probe_cmps() { return 0; }

#endif
