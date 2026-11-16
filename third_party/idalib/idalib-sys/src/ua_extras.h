#pragma once

#include "pro.h"
#include "ua.hpp"
#include "lines.hpp"

#include "cxx.h"

rust::String idalib_print_insn_mnem(ea_t ea) {
  auto out = qstring();

  if (print_insn_mnem(&out, ea)) {
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}

rust::String idalib_generate_disasm_line(ea_t ea, int flags) {
  auto out = qstring();
  generate_disasm_line(&out, ea, flags);
  tag_remove(&out);
  return rust::String(out.c_str());
}

rust::String idalib_print_operand(ea_t ea, int n) {
  auto out = qstring();
  if (print_operand(&out, ea, n)) {
    tag_remove(&out);
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}

int idalib_insn_segpref(ea_t ea) {
  insn_t insn;
  if (decode_insn(&insn, ea) <= 0) {
    return -1;
  }
  return insn.segpref;
}
