# Checks the S_LOCAL records that `cvdump -s` prints against the variable locations that
# `llvm-objdump -d --debug-vars=ascii` prints for the object file the image was linked from.
#
# usage: awk -v want='<proc>:<var> ...' -f check-locals.awk <objdump> <objdump> <cvdump>
#
# The objdump output is read twice: the first pass finds the column of the variable display.
# Every instruction an S_DEFRANGE record covers must be one at which the DWARF gives the
# variable a location, and where that location is a plain register or memory operand, the
# record must describe the whole variable in that same place. Each <proc>:<var> in `want`
# must have a record that covers an instruction. Procedures are matched by name, with the dots
# of Go names written as `@` as cv2pdb does.
#
# The LiveElementPrinter of llvm-objdump looks up a location list entry that it does not show yet
# by the start address of an instruction, so it never shows an entry that starts inside an
# instruction, and the addresses of such an entry count as having no location.

function fail(msg) {
  if (++bad <= 20)
    print msg
}

function canon(r) {
  r = tolower(r)
  if (arm) {
    if (r ~ /^[wx]([0-9]|[12][0-9]|30)$/)
      return "x" substr(r, 2)
    if (r == "wsp")
      return "sp"
    if (r == "fp")
      return "x29"
    if (r == "lr")
      return "x30"
    return r
  }
  if (r in x64)
    return x64[r]
  if (r ~ /^r([89]|1[0-5])[dwb]$/)
    return substr(r, 1, length(r) - 1)
  return r
}

function plain(t,   m) {
  if (t ~ /^[A-Z][A-Z0-9]*$/)
    return canon(t)
  if (match(t, /^\[([A-Z][A-Z0-9]*)([+-][0-9]+)?\]$/, m))
    return "[" canon(m[1]) "+" (m[2] + 0) "]"
  return ""
}

function columns(s,   p, np, i, n) {
  np = split(s, p, "\t")
  n = length(p[1])
  # formatted_raw_ostream counts a tab as advancing to the next multiple of 8, and a tab that
  # is already at a multiple of 8 as advancing by nothing.
  for (i = 2; i <= np; i++)
    n += (8 - n % 8) % 8 + (i < np ? length(p[i]) : 0)
  if (indent - n < 1 || substr(p[np], indent - n, 1) != " ")
    return "\001"
  return substr(p[np], indent - n + 1)
}

BEGIN {
  split("rax eax ax al rbx ebx bx bl rcx ecx cx cl rdx edx dx dl rsi esi si sil rdi edi di dil rbp ebp bp bpl rsp esp sp spl", t)
  for (i = 1; i <= 32; i += 4)
    for (j = 0; j < 4; j++)
      x64[t[i + j]] = t[i]
  indent = -1
}

FNR == 1 { file++ }

file == 1 {
  if ($0 !~ /^ *[0-9a-f]+:/ && match($0, /[\/|]- [^ ]+ = /) && (indent < 0 || RSTART - 1 < indent))
    indent = RSTART - 1
  next
}

file == 2 && /file format coff-arm64/ { arm = 1 }

file == 2 && match($0, /^[0-9a-f]+ <(.+)>:$/, m) {
  fn = m[1]
  gsub(/\./, "@", fn)
  base = strtonum("0x" $1)
  seen[fn] = 1
  delete col
  next
}

file == 2 && /^ *[0-9a-f]+:/ {
  rel = strtonum("0x" substr($1, 1, length($1) - 1)) - base
  ins[fn, nins[fn]++] = rel
  isins[fn, rel] = 1
  tail = columns($0)
  if (tail == "\001")
    fail("the instruction text overlaps the variable columns: " $0)
  for (k = 0; 2 * k < length(tail); k++) {
    c = substr(tail, 2 * k + 1, 1)
    if (c != "|" && c != "v")
      continue
    if (!(k in col)) {
      fail("no variable label for column " k ": " $0)
      continue
    }
    key = fn SUBSEP col[k] SUBSEP rel
    live[key] = (key in live ? live[key] "\n" : "") loc[k]
  }
  next
}

file == 2 && match($0, /[\/|]- /) {
  k = (RSTART - 1 - indent) / 2
  if (k != int(k) || k < 0) {
    fail("a variable label is not in a column: " $0)
    next
  }
  rest = substr($0, RSTART + 3)
  i = index(rest, " = ")
  col[k] = substr(rest, 1, i - 1)
  loc[k] = substr(rest, i + 3)
  sub(/[ |]*$/, "", loc[k])
  next
}

file == 2 { next }

$2 == "S_GPROC32:" {
  proc = $NF
  split($3, a, /[:\]]/)
  lo = strtonum("0x" a[2])
  hi = lo + strtonum("0x" substr($5, 1, 8))
  inproc = proc in seen
  depth = 0
  var = ""
  next
}

!inproc { next }

$2 == "S_BLOCK32:" { depth++ }

$2 == "S_END" {
  if (depth)
    depth--
  else
    inproc = 0
}

$2 == "S_LOCAL:" {
  var = $NF
  next
}

$2 ~ /^S_DEFRANGE_/ && var != "" {
  whole = 0
  where = ""
  if ($2 == "S_DEFRANGE_REGISTER:") {
    whole = 1
    where = canon($3)
  } else if ($2 == "S_DEFRANGE_REGISTER_REL:") {
    whole = !/spilledUdtMember/
    off = strtonum("0x" $5)
    if (off >= 2 ^ 31)
      off -= 2 ^ 32
    where = "[" canon(substr($3, 2)) "+" off "]"
  }
  next
}

$1 == "Range:" && var != "" {
  split($2, s, /[:\]]/)
  split($4, e, /[:\]]/)
  rs = strtonum("0x" s[2])
  re = strtonum("0x" e[2])
  if (rs < lo || re > hi || re <= rs || re - rs > 61440)
    fail(proc " " var ": range empty, outside the procedure or longer than F000: " $0)
  n++
  rproc[n] = proc
  rvar[n] = var
  rlo[n] = rs - lo
  rhi[n] = re - lo
  rwhole[n] = whole
  rwhere[n] = where
  rgaps[n] = ""
  ge = 0
  for (i = 9; i < NF; i += 2) {
    gs = $i
    gl = $(i + 1)
    gsub(/[(),]/, "", gs)
    gsub(/[(),]/, "", gl)
    gs = strtonum("0x" gs)
    gl = strtonum("0x" gl)
    if (gs < ge || gs + gl > re - rs)
      fail(proc " " var ": gaps out of order or outside the range: " $0)
    ge = gs + gl
    rgaps[n] = rgaps[n] " " gs " " ge
  }
  records[proc, var]++
  next
}

$2 ~ /^S_/ && $2 !~ /^S_DEFRANGE_/ { var = "" }

END {
  if (indent < 0)
    fail("llvm-objdump shows no variables")
  for (r = 1; r <= n; r++) {
    p = rproc[r]
    gn = split(rgaps[r], g, " ")
    gi = 1
    for (i = 0; i < nins[p]; i++) {
      x = ins[p, i]
      if (x < rlo[r] || x >= rhi[r])
        continue
      while (gi < gn && x - rlo[r] >= g[gi + 1])
        gi += 2
      if (gi < gn && x - rlo[r] >= g[gi])
        continue
      checked[p, rvar[r]]++
      key = p SUBSEP rvar[r] SUBSEP x
      if (!(key in live)) {
        fail(sprintf("%s %s: %s covers offset %X, where the DWARF has no location%s", p, rvar[r],
                     rwhole[r] ? rwhere[r] : "a part record", x,
                     (p SUBSEP rlo[r]) in isins ? "" : " (the range starts inside an instruction)"))
        continue
      }
      ln = split(live[key], l, "\n")
      want_where = ""
      for (j = 1; j <= ln; j++)
        if ((w = plain(l[j])) != "") {
          want_where = want_where " " w
          if (rwhole[r] && w == rwhere[r])
            break
        }
      if (want_where != "" && j > ln)
        fail(sprintf("%s %s: %s at offset %X, where the DWARF has%s", p, rvar[r], rwhole[r] ? rwhere[r] : "a part record", x, want_where))
    }
  }
  nw = split(want, wv, " ")
  for (i = 1; i <= nw; i++) {
    split(wv[i], pv, ":")
    if (!records[pv[1], pv[2]] || !checked[pv[1], pv[2]])
      fail("no S_DEFRANGE record of " pv[2] " in " pv[1] " covers an instruction")
  }
  for (k in checked)
    total += checked[k]
  printf "checked %d instruction addresses of %d ranges, %d failures\n", total, n, bad
  exit bad > 0
}
