//! Building `.hset` files from records.

use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::format::{self, Document, FORMAT_VERSION, FieldDescriptor, HashsetIn, RecordsIn};
use crate::hash_type::HashType;
use crate::hex;
use crate::key::key64_dyn;
use crate::lookup::{self, BitsPolicy, HintSpec};
use crate::tlsh::cells::{cell_index, cell_table};
use crate::tlsh::ivf::{IvfBuildOptions, build_tlsh_ivf};
use crate::tlsh::{CELL_HINT_TAG, DIGEST_LENGTH as TLSH_LENGTH, TlshDigest};

/// `tlsh_options` bit: write the TIVF index (C `SFHASH_HSET_TLSH_INDEX`).
pub const TLSH_OPTION_INDEX: u32 = 2;

/// `tlsh_options` bit: a merge writes the index iff its inputs have one
/// (C `SFHASH_HSET_TLSH_INHERIT`); ignored by [`BuildOptions::tlsh_options`].
pub const TLSH_OPTION_INHERIT: u32 = 4;

/// `tlsh_options` bit: build the index by float k-means (C
/// `SFHASH_HSET_TLSH_INDEX_KMEANS`), which Rust does not support.
pub const TLSH_OPTION_INDEX_KMEANS: u32 = 8;

/// Options controlling how a file is written.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildOptions {
    pub name: String,
    pub desc: String,
    /// ISO-8601 UTC timestamp; `None` means "now".
    pub timestamp: Option<String>,
    /// Write `RHDR`/`RDAT` (the records) and per-hash record indices.
    pub with_records: bool,
    /// Write one sorted hash section per field.
    pub with_hashsets: bool,
    /// Hint to build for each digest section. Use `bits: u8::MAX` (hull) or
    /// `bits: 0` (block) to let `bits_policy` pick the block count. A TLSH
    /// section always gets the `0x7400` cell index instead, as in C++,
    /// even with [`HintSpec::None`].
    pub hint: HintSpec,
    pub bits_policy: BitsPolicy,
    /// Write the `TIVF` kNN index of every TLSH section, built over the
    /// section's rows by [`build_tlsh_ivf`] (default true, as the C++
    /// builder's default `SFHASH_HSET_TLSH_INDEX`). The cell hint is
    /// written either way. Other sections never get one.
    pub tlsh_index: bool,
    /// The BISECT build's options for the `TIVF` index (default
    /// [`IvfBuildOptions::default`], C++'s: target list size 32, seed
    /// `"query"`; the thread count never changes the bytes).
    pub tlsh_ivf: IvfBuildOptions,
}

impl BuildOptions {
    /// Records plus hash sets with automatically sized hull hints.
    pub fn new(name: impl Into<String>, desc: impl Into<String>) -> Self {
        BuildOptions {
            name: name.into(),
            desc: desc.into(),
            timestamp: None,
            with_records: true,
            with_hashsets: true,
            hint: HintSpec::Hull { bits: u8::MAX },
            bits_policy: BitsPolicy::default(),
            tlsh_index: true,
            tlsh_ivf: IvfBuildOptions::default(),
        }
    }

    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    pub fn records(mut self, yes: bool) -> Self {
        self.with_records = yes;
        self
    }

    pub fn hashsets(mut self, yes: bool) -> Self {
        self.with_hashsets = yes;
        self
    }

    pub fn hint(mut self, hint: HintSpec) -> Self {
        self.hint = hint;
        self
    }

    pub fn bits_policy(mut self, policy: BitsPolicy) -> Self {
        self.bits_policy = policy;
        self
    }

    /// Set [`tlsh_index`](Self::tlsh_index).
    pub fn tlsh_index(mut self, yes: bool) -> Self {
        self.tlsh_index = yes;
        self
    }

    /// Set [`tlsh_ivf`](Self::tlsh_ivf).
    pub fn tlsh_ivf(mut self, ivf: IvfBuildOptions) -> Self {
        self.tlsh_ivf = ivf;
        self
    }

    /// Set [`tlsh_index`](Self::tlsh_index) from the C++ `tlsh_options`
    /// bits (`SFHASH_HSET_TLSH_*`, `HSET_TLSH_OPTIONS` of `mkhashset`), as
    /// the C++ builder reads them (`wants_tivf`):
    ///
    /// * `2` (`INDEX`): write the TIVF index; without it, none is written.
    /// * `1` (once `VECTORS`, now reserved) is ignored.
    /// * `4` (`INHERIT`) is ignored: it selects a merge's index policy
    ///   ([`crate::merge`]) and means nothing to a builder, which the C++
    ///   builder ignores too.
    /// * `8` (`INDEX_KMEANS`) is an [`Error::Input`]: the float k-means
    ///   build is not ported (controller ruling 4); C++ builds with it.
    /// * any other bit is an [`Error::Input`] (C++ ignores them).
    ///
    /// [`tlsh_ivf`](Self::tlsh_ivf) is left as it is.
    pub fn tlsh_options(mut self, bits: u32) -> Result<Self> {
        const IGNORED: u32 = 1 | TLSH_OPTION_INHERIT;
        if bits & TLSH_OPTION_INDEX_KMEANS != 0 {
            return Err(Error::input(
                "TLSH option 8 (INDEX_KMEANS, the k-means index build) is not supported",
            ));
        }
        let unknown = bits & !(IGNORED | TLSH_OPTION_INDEX);
        if unknown != 0 {
            return Err(Error::input(format!(
                "unknown TLSH option bits 0x{unknown:x} in {bits}"
            )));
        }
        self.tlsh_index = bits & TLSH_OPTION_INDEX != 0;
        Ok(self)
    }
}

/// Accumulates records and writes them as an `.hset`.
///
/// A record is one fixed-width row: for every field, a presence byte (`1` if
/// the value is present, else `0`) followed by the value bytes (zero if
/// absent).
#[derive(Debug, Clone)]
pub struct Builder {
    fields: Vec<FieldDescriptor>,
    record_length: usize,
    records: Vec<u8>,
}

impl Builder {
    /// A builder whose records contain the given types, in order.
    pub fn new(types: &[HashType]) -> Result<Self> {
        if types.is_empty() {
            return Err(Error::input("at least one hash type is required"));
        }
        let mut fields = Vec::with_capacity(types.len());
        for (i, &t) in types.iter().enumerate() {
            if types[..i].contains(&t) {
                return Err(Error::input(format!("duplicate hash type {t}")));
            }
            let f = FieldDescriptor::for_type(t).ok_or_else(|| {
                Error::input(format!("{t} values cannot be stored in a hash set"))
            })?;
            fields.push(f);
        }
        Ok(Self::with_fields(fields))
    }

    /// A builder with explicit field descriptors (names and lengths preserved).
    pub fn with_fields(fields: Vec<FieldDescriptor>) -> Self {
        let record_length = fields.iter().map(FieldDescriptor::stride).sum();
        Builder {
            fields,
            record_length,
            records: Vec::new(),
        }
    }

    pub fn fields(&self) -> &[FieldDescriptor] {
        &self.fields
    }

    pub fn types(&self) -> Vec<HashType> {
        self.fields.iter().map(|f| f.htype).collect()
    }

    pub fn record_length(&self) -> usize {
        self.record_length
    }

    pub fn record_count(&self) -> usize {
        self.records.len() / self.record_length
    }

    /// Add a record given one optional value per field.
    ///
    /// A TLSH value is checked with [`TlshDigest::from_bytes`]: a non-zero
    /// reserved byte (offset 35) is an [`Error::Input`], and the null
    /// digest (36 zero bytes) is stored as an absent value, since a null
    /// digest has no row (C++ copies raw TLSH values unchecked).
    pub fn add_record(&mut self, values: &[Option<&[u8]>]) -> Result<()> {
        if values.len() != self.fields.len() {
            return Err(Error::input(format!(
                "expected {} values, got {}",
                self.fields.len(),
                values.len()
            )));
        }
        let start = self.records.len();
        for (f, v) in self.fields.iter().zip(values) {
            match v {
                Some(bytes) => {
                    if bytes.len() != f.length as usize {
                        self.records.truncate(start);
                        return Err(Error::input(format!(
                            "{} value has {} bytes, expected {}",
                            f.htype,
                            bytes.len(),
                            f.length
                        )));
                    }
                    self.records.push(1);
                    self.records.extend_from_slice(bytes);
                }
                None => self.records.resize(self.records.len() + f.stride(), 0),
            }
        }
        self.check_tlsh_values(start)
    }

    /// Add a record already laid out as `record_length` bytes.
    ///
    /// Present TLSH values are checked as in [`add_record`](Self::add_record):
    /// a non-zero reserved byte is an [`Error::Input`], and a present null
    /// digest is stored absent (its presence byte cleared).
    pub fn add_raw_record(&mut self, rec: &[u8]) -> Result<()> {
        if rec.len() != self.record_length {
            return Err(Error::input(format!(
                "raw record has {} bytes, expected {}",
                rec.len(),
                self.record_length
            )));
        }
        let start = self.records.len();
        self.records.extend_from_slice(rec);
        self.check_tlsh_values(start)
    }

    /// Check the present TLSH values of the record just appended at
    /// `start`: a null digest becomes absent (its value bytes are already
    /// zero), and a non-zero reserved byte removes the record again and is
    /// an [`Error::Input`].
    fn check_tlsh_values(&mut self, start: usize) -> Result<()> {
        let mut off = start;
        for f in &self.fields {
            if is_tlsh(f) && self.records[off] == 1 {
                let value: &[u8; TLSH_LENGTH] = self.records[off + 1..off + f.stride()]
                    .try_into()
                    .expect("a TLSH field is 36 bytes");
                match TlshDigest::from_bytes(value) {
                    Ok(d) if d.is_null() => self.records[off] = 0,
                    Ok(_) => {}
                    Err(e) => {
                        self.records.truncate(start);
                        return Err(e);
                    }
                }
            }
            off += f.stride();
        }
        Ok(())
    }

    /// Add a record from a line of text: one space-separated column per
    /// field, hex for digests, the `T1` hex form for TLSH (see
    /// [`parse_value`]) and a decimal integer for sizes. An empty column
    /// means the value is absent, as does `"TNULL"` or any other null
    /// digest in a TLSH column; blank lines are ignored. One line
    /// ending (`"\n"`, `"\r\n"` or a lone `'\r'`) is stripped; any further
    /// `'\r'` is part of the last column. Called directly, this is the
    /// whole rule; through [`add_text`](Self::add_text) or the CLI,
    /// `BufRead::lines()`/`str::lines()` already strip a `"\r\n"` or `"\n"`
    /// line terminator first, so a line ending in `"\r\r\n"` keeps one
    /// `'\r'` going in and that one is stripped here too, making the whole
    /// `"\r\r\n"` disappear rather than leaving a `'\r'` in the last
    /// column.
    pub fn add_text_line(&mut self, line: &str) -> Result<()> {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return Ok(());
        }
        let cols: Vec<&str> = line.split(' ').collect();
        if cols.len() != self.fields.len() {
            return Err(Error::input(format!(
                "expected {} columns, found {}",
                self.fields.len(),
                cols.len()
            )));
        }
        let mut buf: Vec<Vec<u8>> = Vec::with_capacity(cols.len());
        for (f, col) in self.fields.iter().zip(&cols) {
            if col.is_empty() {
                buf.push(Vec::new());
                continue;
            }
            buf.push(parse_value(f, col)?);
        }
        let values: Vec<Option<&[u8]>> = buf
            .iter()
            .map(|v| (!v.is_empty()).then_some(v.as_slice()))
            .collect();
        self.add_record(&values)
    }

    /// Add every non-blank line of `text`.
    pub fn add_text(&mut self, text: &str) -> Result<usize> {
        let mut n = 0;
        for (lineno, line) in text.lines().enumerate() {
            self.add_text_line(line)
                .map_err(|e| Error::input(format!("line {}: {e}", lineno + 1)))?;
            n += 1;
        }
        Ok(n)
    }

    /// Produce the complete file image.
    ///
    /// Each TLSH section gets the `0x7400` cell hint and, with
    /// [`BuildOptions::tlsh_index`], a `TIVF` index over its sorted rows
    /// (duplicates included in a records file), written after its `HDAT`
    /// and `RIDX`.
    ///
    /// # Errors
    ///
    /// [`Error::Input`] when neither records nor hash sets are to be
    /// written, or the index cannot be built with
    /// [`BuildOptions::tlsh_ivf`] (a target list size of 0).
    pub fn build(&self, opts: &BuildOptions) -> Result<Vec<u8>> {
        if !opts.with_records && !opts.with_hashsets {
            return Err(Error::input(
                "at least one of records and hash sets must be written",
            ));
        }
        // fields are found by type, and the reader rejects an RHDR naming a
        // type twice (with_fields does not check, so check here)
        if let Some(t) = FieldDescriptor::repeated_type(&self.fields) {
            return Err(Error::input(format!("duplicate hash type {t}")));
        }
        let rl = self.record_length;
        let records = sorted_rows(&self.records, rl, true);
        let record_count = records.len() / rl;
        let time = match &opts.timestamp {
            Some(t) => t.clone(),
            None => now_utc(),
        };

        struct Prepared {
            htype: HashType,
            name: String,
            hlen: usize,
            data: Vec<u8>,
            ridx: Option<Vec<u8>>,
            hint: Option<(u16, Vec<u8>)>,
            tivf: Option<Vec<u8>>,
        }

        let mut prepared: Vec<Prepared> = Vec::new();
        if opts.with_hashsets {
            let mut off = 0usize;
            for f in &self.fields {
                let hlen = f.length as usize;
                // Record indices of the present values, sorted by hash, and
                // equal hashes by descending record index: the C++ encoder
                // sorts (hash, index) pairs with `HashRecordProxy::cmp`
                // (record_iterator.h), which orders equal hashes that way
                // for every type, so the RIDX payloads match.
                let mut idx: Vec<u32> = (0..record_count)
                    .filter(|&r| records[r * rl + off] == 1)
                    .map(|r| r as u32)
                    .collect();
                let hash_of =
                    |r: u32| &records[r as usize * rl + off + 1..r as usize * rl + off + 1 + hlen];
                idx.sort_unstable_by(|&a, &b| hash_of(a).cmp(hash_of(b)).then(b.cmp(&a)));
                if !opts.with_records {
                    idx.dedup_by(|a, b| hash_of(*a) == hash_of(*b));
                }
                let mut data = Vec::with_capacity(idx.len() * hlen);
                let mut ridx = opts.with_records.then(|| Vec::with_capacity(idx.len() * 8));
                for &r in &idx {
                    data.extend_from_slice(hash_of(r));
                    if let Some(ri) = ridx.as_mut() {
                        ri.extend_from_slice(&u64::from(r).to_le_bytes());
                    }
                }
                let mut tivf = None;
                let hint = if is_tlsh(f) {
                    // C++ writes the cell index on every TLSH section,
                    // whatever hint the other sections get. The cell
                    // index and the TIVF index are both built over the
                    // sorted rows in `data`, duplicates included in a
                    // records file, which are exactly the HDAT rows.
                    let (rows, _) = data.as_chunks::<TLSH_LENGTH>();
                    if opts.tlsh_index {
                        tivf = Some(build_tlsh_ivf(rows, &opts.tlsh_ivf)?.to_bytes());
                    }
                    Some((CELL_HINT_TAG, cell_table(&cell_index(rows)?)))
                } else if f.htype.is_digest() {
                    let spec = lookup::resolve_bits(opts.hint, idx.len(), hlen, &opts.bits_policy);
                    lookup::build_hint(hlen, &data, spec)?
                } else {
                    None
                };
                prepared.push(Prepared {
                    htype: f.htype,
                    name: f.name.clone(),
                    hlen,
                    data,
                    ridx,
                    hint,
                    tivf,
                });
                off += f.stride();
            }
        }

        let doc = Document {
            version: FORMAT_VERSION,
            name: &opts.name,
            desc: &opts.desc,
            time: &time,
            records: opts.with_records.then_some(RecordsIn {
                fields: &self.fields,
                record_length: rl,
                data: &records,
            }),
            hashsets: prepared
                .iter()
                .map(|p| HashsetIn {
                    htype: p.htype,
                    name: &p.name,
                    hash_length: p.hlen,
                    data: &p.data,
                    hint: p.hint.as_ref().map(|(t, b)| (*t, b.as_slice())),
                    ridx: p.ridx.as_deref(),
                    tivf: p.tivf.as_deref(),
                })
                .collect(),
        };
        format::encode(&doc)
    }

    /// Build and write to `path`, returning the file size.
    pub fn write_to(&self, path: impl AsRef<Path>, opts: &BuildOptions) -> Result<u64> {
        let bytes = self.build(opts)?;
        std::fs::write(path, &bytes)?;
        Ok(bytes.len() as u64)
    }
}

/// True for a field that holds canonical 36-byte TLSH digests. A `Tlsh`
/// field of any other length (possible only through
/// [`Builder::with_fields`]) is opaque bytes: hex text, no cell hint.
fn is_tlsh(field: &FieldDescriptor) -> bool {
    field.htype == HashType::Tlsh && field.length == TLSH_LENGTH as u64
}

/// A 36-byte TLSH value as a digest, if its reserved byte is zero.
fn tlsh_digest(value: &[u8]) -> Option<TlshDigest> {
    let bytes: &[u8; TLSH_LENGTH] = value.try_into().ok()?;
    TlshDigest::from_bytes(bytes).ok()
}

/// Parse one text column for `field`.
///
/// A TLSH field takes the `T1` hex form ([`TlshDigest::from_hex`]: `"T1"`
/// and 70 hex digits, or the digits alone, nothing else in the column) and
/// returns the 36 canonical bytes; `"TNULL"` returns the null digest, which
/// [`Builder::add_record`] stores as an absent value.
pub fn parse_value(field: &FieldDescriptor, col: &str) -> Result<Vec<u8>> {
    if is_tlsh(field) {
        return Ok(TlshDigest::from_hex(col)?.as_bytes().to_vec());
    }
    match field.htype {
        HashType::Size => {
            let v: u64 = col
                .parse()
                .map_err(|_| Error::input(format!("'{col}' is not a non-negative integer")))?;
            Ok(v.to_le_bytes().to_vec())
        }
        HashType::Entropy => {
            let v: f64 = col
                .parse()
                .map_err(|_| Error::input(format!("'{col}' is not a number")))?;
            Ok(v.to_le_bytes().to_vec())
        }
        _ => {
            let mut out = vec![0u8; field.length as usize];
            hex::decode_into(col, &mut out)?;
            Ok(out)
        }
    }
}

/// Write a field value as text to `w` without allocating (see
/// [`format_value`] for the `String`-returning form).
pub fn write_value<W: io::Write + ?Sized>(
    field: &FieldDescriptor,
    value: &[u8],
    w: &mut W,
) -> io::Result<()> {
    if is_tlsh(field)
        && let Some(d) = tlsh_digest(value)
    {
        return d.write_hex(w);
    }
    match field.htype {
        HashType::Size if value.len() == 8 => {
            write!(w, "{}", u64::from_le_bytes(value.try_into().unwrap()))
        }
        HashType::Entropy if value.len() == 8 => {
            write!(w, "{}", f64::from_le_bytes(value.try_into().unwrap()))
        }
        _ => hex::encode_to_writer(value, w),
    }
}

/// Render a field value as text (inverse of [`parse_value`]).
///
/// A TLSH value prints in the `T1` hex form (`"TNULL"` for the null
/// digest). One the hex form cannot carry, a non-zero reserved byte or a
/// length other than 36, prints as plain hex of its bytes, as do the
/// numeric types at a width other than 8.
pub fn format_value(field: &FieldDescriptor, value: &[u8]) -> String {
    if is_tlsh(field)
        && let Some(d) = tlsh_digest(value)
    {
        return d.to_hex();
    }
    match field.htype {
        HashType::Size if value.len() == 8 => {
            u64::from_le_bytes(value.try_into().unwrap()).to_string()
        }
        HashType::Entropy if value.len() == 8 => {
            f64::from_le_bytes(value.try_into().unwrap()).to_string()
        }
        _ => hex::encode(value),
    }
}

/// Lexicographically sort fixed-width rows (optionally dropping duplicates),
/// returning the new buffer. Uses a key-prefix sort so comparisons rarely
/// touch the full rows.
pub fn sorted_rows(data: &[u8], width: usize, dedup: bool) -> Vec<u8> {
    assert!(width > 0 && data.len().is_multiple_of(width));
    let n = data.len() / width;
    let row = |i: u32| &data[i as usize * width..(i as usize + 1) * width];
    let mut keys: Vec<(u64, u32)> = (0..n as u32).map(|i| (key64_dyn(row(i)), i)).collect();
    keys.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| row(a.1).cmp(row(b.1))));
    let mut out = Vec::with_capacity(data.len());
    let mut prev: Option<&[u8]> = None;
    for &(_, i) in &keys {
        let r = row(i);
        if dedup && prev == Some(r) {
            continue;
        }
        out.extend_from_slice(r);
        prev = Some(r);
    }
    out
}

/// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

/// Format seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::decode;

    #[test]
    fn build_refuses_fields_that_repeat_a_type() {
        // the reader rejects such an RHDR, so the writer must not produce one
        let md5 = |name: &str| FieldDescriptor {
            htype: HashType::Md5,
            name: name.into(),
            length: 16,
        };
        let b = Builder::with_fields(vec![md5("a"), md5("b")]);
        for with_hashsets in [false, true] {
            let opts = BuildOptions::new("", "").hashsets(with_hashsets);
            let e = b.build(&opts).unwrap_err();
            assert!(matches!(e, Error::Input(_)), "{e}");
            assert!(e.to_string().contains("duplicate hash type MD5"), "{e}");
        }
    }

    #[test]
    fn timestamp_formatting() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_673_283_738), "2023-01-09T17:02:18Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert!(now_utc().ends_with('Z'));
    }

    #[test]
    fn timestamp_formatting_across_months_centuries_and_eras() {
        // March to December (month index below 10), a century year, the
        // first and last day of a 400-year era (2000-03-01 is day 0 of
        // one, 2400-02-29 the last day of the next).
        assert_eq!(format_utc(1_721_046_896), "2024-07-15T12:34:56Z");
        assert_eq!(format_utc(951_868_800), "2000-03-01T00:00:00Z");
        assert_eq!(format_utc(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(format_utc(13_569_465_599), "2399-12-31T23:59:59Z");
        assert_eq!(format_utc(13_574_649_599), "2400-02-29T23:59:59Z");
    }

    #[test]
    fn values_render_as_numbers_only_at_eight_bytes() {
        let fd = |htype, length| FieldDescriptor {
            htype,
            name: String::new(),
            length,
        };
        let size = fd(HashType::Size, 8);
        let entropy = fd(HashType::Entropy, 8);
        let cases: [(&FieldDescriptor, Vec<u8>, &str); 5] = [
            (&size, 42u64.to_le_bytes().to_vec(), "42"),
            (&entropy, 1.5f64.to_le_bytes().to_vec(), "1.5"),
            // A value of any other width falls back to hex.
            (&size, vec![1, 2, 3, 4], "01020304"),
            (&entropy, vec![0xab, 0xcd], "abcd"),
            (
                &fd(HashType::Md5, 16),
                vec![0x0f; 16],
                "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            ),
        ];
        for (f, v, want) in cases {
            assert_eq!(format_value(f, &v), want, "{:?}", f.htype);
            let mut w = Vec::new();
            write_value(f, &v, &mut w).unwrap();
            assert_eq!(String::from_utf8(w).unwrap(), want, "{:?}", f.htype);
        }
    }

    #[test]
    fn builder_reports_types_line_count_and_file_size() {
        let mut b = Builder::new(&[HashType::Md5, HashType::Size]).unwrap();
        assert_eq!(b.types(), [HashType::Md5, HashType::Size]);
        let n = b
            .add_text(
                "00112233445566778899aabbccddeeff 1\n 2\nffeeddccbbaa99887766554433221100 3\n",
            )
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(b.record_count(), 3);
        let opts = BuildOptions::new("n", "d").timestamp("2024-01-01T00:00:00Z");
        let path = std::env::temp_dir().join(format!("hset-write-to-{}.hset", std::process::id()));
        let size = b.write_to(&path, &opts).unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(size, written.len() as u64);
        assert_eq!(written, b.build(&opts).unwrap());
    }

    #[test]
    fn sorted_rows_sorts_and_dedups() {
        let data = [3u8, 0, 1, 0, 2, 0, 1, 0];
        assert_eq!(sorted_rows(&data, 2, true), vec![1, 0, 2, 0, 3, 0]);
        assert_eq!(sorted_rows(&data, 2, false), vec![1, 0, 1, 0, 2, 0, 3, 0]);
        let wide: Vec<u8> = (0..60).rev().collect();
        let s = sorted_rows(&wide, 20, true);
        assert_eq!(&s[..20], &wide[40..]);
    }

    #[test]
    fn builder_validates_input() {
        assert!(Builder::new(&[]).is_err());
        assert!(Builder::new(&[HashType::Md5, HashType::Md5]).is_err());
        assert!(Builder::new(&[HashType::Fuzzy]).is_err());
        let mut b = Builder::new(&[HashType::Md5, HashType::Size]).unwrap();
        assert_eq!(b.record_length(), 17 + 9);
        assert!(b.add_text_line("abcd 12").is_err());
        assert!(b.add_text_line("00112233445566778899aabbccddeeff").is_err());
        assert!(
            b.add_text_line("00112233445566778899aabbccddeeff -1")
                .is_err()
        );
        assert!(b.add_record(&[Some(&[0u8; 15]), None]).is_err());
        assert_eq!(b.record_count(), 0);
        b.add_text_line("00112233445566778899aabbccddeeff 42")
            .unwrap();
        b.add_text_line(" 7").unwrap();
        b.add_text_line("").unwrap();
        assert_eq!(b.record_count(), 2);
        let opts = BuildOptions::new("n", "d").records(false).hashsets(false);
        assert!(b.build(&opts).is_err());
    }

    #[test]
    fn build_dedups_records_and_indexes_hashes() {
        let mut b = Builder::new(&[HashType::Md5, HashType::Sha1]).unwrap();
        let md5 = "081d3d40b257d8bbc5858345ad186beb";
        let sha = "0af8e028c7048ad772ddec2200ec7e0e4d58b0c3";
        b.add_text_line(&format!("{md5} {sha}")).unwrap();
        b.add_text_line(&format!("{md5} {sha}")).unwrap();
        b.add_text_line(&format!("{md5} ")).unwrap();
        b.add_text_line(&format!(" {sha}")).unwrap();
        let bytes = b
            .build(&BuildOptions::new("n", "d").timestamp("2020-01-01T00:00:00Z"))
            .unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.record_count(), 3);
        assert_eq!(f.sections.len(), 2);
        let md5s = &f.sections[0];
        assert_eq!(md5s.len(), 2); // md5 present in two distinct records
        // Records sort bytewise, so the record with an absent md5 (presence
        // byte 0) is record 0; the two md5-bearing records are 1 and 2,
        // and equal hashes list their records in descending order, as the
        // C++ encoder's `HashRecordProxy::cmp` sorts them.
        assert_eq!(md5s.record_index(0), Some(2));
        assert_eq!(md5s.record_index(1), Some(1));
        assert!(md5s.hint.is_some());
        let shas = &f.sections[1];
        assert_eq!(shas.len(), 2);
        // Records are sorted bytewise: the record with absent md5 (presence
        // 0) sorts first, and the sha is in it and in record 2, listed
        // descending.
        assert_eq!(f.record(0).unwrap()[0], 0);
        assert_eq!(shas.record_index(0), Some(2));
        assert_eq!(shas.record_index(1), Some(0));
    }

    #[test]
    fn hashsets_only_dedups_hashes_and_has_no_records() {
        let mut b = Builder::new(&[HashType::Md5, HashType::Sha1]).unwrap();
        b.add_text_line(
            "081d3d40b257d8bbc5858345ad186beb 0af8e028c7048ad772ddec2200ec7e0e4d58b0c3",
        )
        .unwrap();
        b.add_text_line(
            "081d3d40b257d8bbc5858345ad186beb 1127ceb2c2d789c1d7615b12082ca30222f3c612",
        )
        .unwrap();
        let opts = BuildOptions::new("n", "d")
            .records(false)
            .hint(HintSpec::LEGACY);
        let f_bytes = b.build(&opts).unwrap();
        let f = decode(&f_bytes).unwrap();
        assert!(f.rhdr.is_none());
        assert_eq!(f.sections[0].len(), 1);
        assert_eq!(f.sections[1].len(), 2);
        assert!(f.sections[0].ridx.is_none());
        assert_eq!(
            f.sections[0].hint.map(|h| h.tag()),
            Some(crate::format::HINT_BLOCK8_LEGACY)
        );
        let records_only = b
            .build(&BuildOptions::new("n", "d").hashsets(false))
            .unwrap();
        let f = decode(&records_only).unwrap();
        assert!(f.sections.is_empty());
        assert_eq!(f.record_count(), 2);
    }

    #[test]
    fn size_fields_get_no_hint_and_parse_decimal() {
        let mut b = Builder::new(&[HashType::Size]).unwrap();
        b.add_text_line("1024").unwrap();
        b.add_text_line("7").unwrap();
        let f_bytes = b.build(&BuildOptions::new("n", "d")).unwrap();
        let f = decode(&f_bytes).unwrap();
        assert!(f.sections[0].hint.is_none());
        // bytewise order of little-endian 7 and 1024 puts 1024 (0x00 0x04) first
        assert_eq!(f.sections[0].hash(0), &1024u64.to_le_bytes());
        assert_eq!(format_value(&b.fields()[0], f.sections[0].hash(0)), "1024");
        let mut w = Vec::new();
        write_value(&b.fields()[0], f.sections[0].hash(0), &mut w).unwrap();
        assert_eq!(w, b"1024");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Every type a hash set can store: all of them but `Fuzzy`.
    fn storable() -> Vec<HashType> {
        HashType::ALL
            .iter()
            .copied()
            .filter(|&t| t != HashType::Fuzzy)
            .collect()
    }

    proptest! {
        #[test]
        fn sorted_rows_matches_sort_dedup(
            width in 1usize..=8,
            rows in vec(any::<u8>(), 0..=256),
            dedup in any::<bool>(),
        ) {
            let data = &rows[..rows.len() / width * width];
            let mut expected: Vec<&[u8]> = data.chunks_exact(width).collect();
            expected.sort();
            if dedup {
                expected.dedup();
            }
            prop_assert_eq!(sorted_rows(data, width, dedup), expected.concat());
        }

        #[test]
        fn parse_format_roundtrip(
            t in prop::sample::select(storable()),
            raw in vec(any::<u8>(), 0..=64),
            f in any::<f64>().prop_filter("finite", |f| f.is_finite()),
        ) {
            let fd = FieldDescriptor::for_type(t).unwrap();
            let value = if t == HashType::Entropy {
                f.to_le_bytes().to_vec()
            } else {
                let mut v = raw;
                v.resize(t.length().unwrap(), 0);
                if t == HashType::Tlsh {
                    // The T1 hex form has no room for the reserved byte.
                    v[TLSH_LENGTH - 1] = 0;
                }
                v
            };
            let text = format_value(&fd, &value);
            prop_assert_eq!(parse_value(&fd, &text).ok(), Some(value), "{} {:?}", t, text);
        }

        #[test]
        fn add_text_line_rejects_wrong_column_count(cols in 0usize..=5) {
            let mut b = Builder::new(&[HashType::Md5, HashType::Size]).unwrap();
            let line = " ".repeat(cols.saturating_sub(1));
            let r = b.add_text_line(&line);
            if cols <= 2 {
                prop_assert!(r.is_ok(), "{:?}: {:?}", line, r);
            } else {
                prop_assert!(matches!(r, Err(Error::Input(_))), "{:?}: {:?}", line, r);
            }
        }
    }
}
