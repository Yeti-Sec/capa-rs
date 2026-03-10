# Dotscope Patches for rust-bindiff

Tracking document for local patches applied to dotscope for malware analysis
compatibility with rust-bindiff. These patches need to be re-applied after
rebasing or updating dotscope from upstream.

## Patch 1: Lenient CLR Flags Validation

**File:** `src/metadata/cor20header.rs` (line ~282)

**Problem:** dotscope rejects .NET assemblies with undefined CLR flag bits,
returning `Err(malformed_error!(...))`. Malware and obfuscators commonly set
undefined bits (e.g., `0x00020003` has bit `0x20000` set). The .NET runtime
and dnlib both silently ignore unknown flag bits.

**Fix:** Changed from `return Err(...)` to a warning log. The flags value is
still read and stored; only the strict rejection is removed.

**Before:**
```rust
if flags & !VALID_FLAGS != 0 {
    return Err(malformed_error!(
        "Cor20Header: invalid CLR flags: 0x{:08X} contains undefined bits",
        flags
    ));
}
```

**After:**
```rust
if flags & !VALID_FLAGS != 0 {
    #[cfg(feature = "logging")]
    log::warn!(
        "Cor20Header: CLR flags 0x{:08X} contain undefined bits, ignoring",
        flags
    );
}
```

**Test sample:** `cca62534201d187235527715f648522a29d6cfdbf8ba26952267734762d0b83f`
(CLR flags `0x00020003`)

---

## Patch 2: Truncated Table Row Count Data

**File:** `src/metadata/tables/types/common/info.rs` (line ~226)

**Problem:** When iterating metadata table IDs to read row counts from the `#~`
stream, dotscope returns `Err(out_of_bounds_error!())` if the data is shorter
than expected. Malware/obfuscators may declare tables in the valid bitmask but
truncate the row count area. dnlib handles this by silently stopping iteration.

**Fix:** Changed bounds check from `return Err(...)` to `break`. Also moved the
valid-bitvec check before the bounds check so we skip non-declared tables first.

**Before:**
```rust
for table_id in TableId::iter() {
    if data.len() < next_row_offset {
        return Err(out_of_bounds_error!());
    }
    if (valid_bitvec & (1 << table_id as usize)) == 0 {
        continue;
    }
    // ...
}
```

**After:**
```rust
for table_id in TableId::iter() {
    if (valid_bitvec & (1 << table_id as usize)) == 0 {
        continue;
    }
    if next_row_offset + 4 > data.len() {
        break;
    }
    // ...
}
```

---

## Patch 3: Truncated Table Data in TablesHeader

**File:** `src/metadata/streams/tablesheader.rs` (line ~1038)

**Problem:** When iterating tables to create `MetadataTable` wrappers, dotscope
returns `Err(out_of_bounds_error!())` if `current_offset > data.len()`. If a
table's declared row count exceeds available data, the offset advances past the
end and the next iteration fails. dnlib truncates gracefully.

**Fix:** Changed from `return Err(...)` to `break`.

**Before:**
```rust
if current_offset > data.len() {
    return Err(out_of_bounds_error!());
}
```

**After:**
```rust
if current_offset >= data.len() {
    break;
}
```

---

## Patch 4: Malformed FieldMarshal Blob Handling

**File:** `src/metadata/tables/fieldmarshal/loader.rs` (line ~75)

**Problem:** The FieldMarshal table loader calls `row.to_owned()` which parses
a marshalling descriptor from the `#Blob` heap. Malware often has truncated or
corrupted blob entries. The parser calls `read_compressed_uint` on a 1-byte
blob, causing an OOB error that propagates up and fails the entire assembly load.

**Fix:** Wrapped `row.to_owned()` in a match to skip malformed rows instead of
failing the entire load. Also wrapped `res.apply()` with `let _ =` to ignore
application errors on partially-valid rows.

**Before:**
```rust
table.par_iter().try_for_each(|row| {
    let res = row.to_owned(|coded_index| context.get_ref(coded_index), blob)?;
    res.apply()?;
    context.field_marshal.insert(row.token, res);
    Ok(())
})?;
```

**After:**
```rust
table.par_iter().try_for_each(|row| {
    let res = match row.to_owned(|coded_index| context.get_ref(coded_index), blob) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    let _ = res.apply();
    context.field_marshal.insert(row.token, res);
    Ok(())
})?;
```

**Test sample:** `d6b6d08dff66c29c4ea572c525fe9db25e880104b2ff63afac31cf2263930f51`
(truncated marshalling descriptor blob, offset=1, data_len=1)

---

## Patch 5: TypeDef Loader Skip on Failure

**File:** `src/metadata/tables/typedef/loader.rs` (line ~127)

**Problem:** The TypeDef loader uses `try_for_each` which aborts ALL type loading
when any single type fails `to_owned()`. Malware with invalid MethodPtr/FieldPtr
entries in any type causes the entire type registry to be empty, losing all methods.

**Fix:** Wrap `to_owned()` in a match and return `Ok(())` on error to skip the
bad type while continuing to load valid ones.

**Before:**
```rust
table.par_iter().try_for_each(|row| -> Result<()> {
    let type_def = row.to_owned(...)?;
    context.types.insert(&type_def);
    Ok(())
})?;
```

**After:**
```rust
table.par_iter().try_for_each(|row| {
    let type_def = match row.to_owned(...) {
        Ok(td) => td,
        Err(_) => return Ok(()),
    };
    context.types.insert(&type_def);
    Ok(())
})?;
```

**Test sample:** `d5b703f4ada157ef1ac7cb8789c901c8634512e3049320db1f11c6f0e439f5a3`
(XClient — had 0 methods before patch, 4882 after)

---

## Patch 6: TypeDef::to_owned Skip Invalid Ptr/Member Entries

**Files:**
- `src/metadata/tables/typedef/raw.rs` (lines ~191-283)
- `src/metadata/tables/eventmap/raw.rs` (lines ~157-200)
- `src/metadata/tables/propertymap/raw.rs` (lines ~126-175)
- `src/metadata/tables/methoddef/raw.rs` (lines ~269-316)
- `src/metadata/tables/nestedclass/raw.rs` (lines ~120-143)

**Problem:** When iterating field/method/event/property/param ranges in `to_owned()`
methods, a single invalid pointer table entry (FieldPtr, MethodPtr, EventPtr,
PropertyPtr, ParamPtr) or unresolvable member causes `return Err(malformed_error!(...))`
which aborts the entire type. dnlib silently skips invalid entries via `continue`.

**Fix:** Changed all `return Err(malformed_error!(...))` inside these loops to
`continue`, and changed `map_err(|_| malformed_error!(...))?.` to
`match ... { Ok(v) => v, Err(_) => continue }`.

**Affected patterns (4 per file — Ptr lookup, Ptr overflow, member lookup, member overflow):**
```rust
// Before:
None => { return Err(malformed_error!("Failed to resolve MethodPtr - {}",  ...)) }
None => { return Err(malformed_error!("Failed to resolve method - {}",  ...)) }

// After:
None => continue,
None => continue,
```

**Test sample:** `d5b703f4ada157ef1ac7cb8789c901c8634512e3049320db1f11c6f0e439f5a3`
(XClient — MethodPtr resolution failure at token 0x09000001)

---

## Re-applying Patches

After updating dotscope from upstream:

1. Check if upstream has addressed any of these issues natively
2. For each remaining patch, search for the original code pattern (the "Before"
   block) and apply the "After" replacement
3. Test with the malware samples listed above to verify

## Design Philosophy

These patches follow dnlib's "never-throw" approach to malware parsing:
- Return null/empty/skip instead of erroring on malformed data
- Accept unknown flags and metadata values via masking
- Truncate gracefully when data is shorter than declared
- Core bounds checking (`read_le_at`) is preserved for memory safety
