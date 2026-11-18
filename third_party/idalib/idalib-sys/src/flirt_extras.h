#pragma once

#include "pro.h"
#include "funcs.hpp"

// FLIRT signature application helpers (capa-rs local patch).
// `fname` must be a short file name (no directory part); IDA resolves it
// against its sig directories (`$IDADIR/sig/<proc>`, `$IDAUSR/sig/<proc>`).

// Returns 0 on failure, otherwise the number of planned (and applied) signatures.
int idalib_plan_to_apply_idasgn(const char *fname) {
  return fname ? plan_to_apply_idasgn(fname) : 0;
}

// Returns a LIBFUNC_* code.
int idalib_apply_idasgn_to(const char *signame, unsigned long long ea,
                           bool is_startup) {
  return signame ? apply_idasgn_to(signame, (ea_t)ea, is_startup) : 1;
}

int idalib_get_idasgn_qty() { return get_idasgn_qty(); }

// Returns an IDASGN_* code (IDASGN_APPLIED == 2 once the signature has run).
int idalib_calc_idasgn_state(int n) { return calc_idasgn_state(n); }

// Number of modules recognised with the n-th signature, or -1 for a bad index.
int idalib_get_idasgn_matches(int n) {
  return (int)get_idasgn_desc(nullptr, nullptr, n);
}
