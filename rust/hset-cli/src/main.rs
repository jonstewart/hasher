//! `hset`: make, inspect, query, verify, and combine `.hset` hash-set files.

use std::fs::File;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};
use hset::format::{self, Document, HashsetIn, HsetFile};
use hset::lookup::{self, BatchMode, BitsPolicy, HintSpec, SearchConfig, SingleMode};
use hset::{BuildOptions, Builder, HashType, Hashset, SetOp, builder, hex, ops, synth};

#[derive(Parser)]
#[command(name = "hset", version, about = "Make and query .hset hash-set files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build an .hset from text (one record per line, one column per hash type)
    Make(MakeArgs),
    /// Show metadata, sections, and record layout
    Info(InfoArgs),
    /// Print hashes (or records) as text
    Dump(DumpArgs),
    /// Look up hashes
    Query(QueryArgs),
    /// Check digest, ordering, record links, and hint soundness
    Verify(FileArg),
    /// Union of two hash sets
    Union(SetOpArgs),
    /// Intersection of two hash sets
    Intersect(SetOpArgs),
    /// Records of the first hash set not in the second
    Subtract(SetOpArgs),
    /// Rewrite a file with different hints or metadata
    Reindex(ReindexArgs),
    /// Time lookups against a file with synthetic queries
    Bench(BenchArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum HintKind {
    /// Convex-hull fitted lines per block (default, fastest)
    Hull,
    /// Flat min/max deviation per block
    Block,
    /// Flat 8-bit blocks, readable by the C++ libhasher
    Legacy,
    /// No hint; plain binary search
    None,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum SingleKind {
    /// Recursive without a hint, 8-ary with one (default)
    Auto,
    /// 8-ary search
    Kary,
    /// Branchless binary search
    Binary,
    /// Recursive dictionary search around the model's prediction
    Recursive,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum BatchKind {
    Auto,
    Staged,
    Lanes,
    Passes,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum Only {
    Both,
    Single,
    Batch,
}

#[derive(Args, Clone)]
struct OutputArgs {
    /// Hash set name
    #[arg(short = 'n', long, default_value = "", allow_hyphen_values = true)]
    name: String,
    /// Hash set description
    #[arg(short = 'd', long, default_value = "", allow_hyphen_values = true)]
    desc: String,
    /// Timestamp to record (ISO-8601 UTC); default is now
    #[arg(long)]
    timestamp: Option<String>,
    /// Omit the records (RHDR/RDAT) and record indices
    #[arg(long)]
    no_records: bool,
    /// Omit the per-type sorted hash sections
    #[arg(long)]
    no_hashsets: bool,
    /// Lookup hint written for each digest section
    #[arg(long, value_enum, default_value_t = HintKind::Hull)]
    hint: HintKind,
    /// Block bits for the hint (default: chosen from the set size)
    #[arg(long)]
    bits: Option<u8>,
    /// Hint table size budget as a fraction of the hash data
    #[arg(long, default_value_t = 0.02)]
    budget: f64,
    /// Output file
    #[arg(short = 'o', long, required = true)]
    output: PathBuf,
}

impl OutputArgs {
    fn hint_spec(&self) -> HintSpec {
        match (self.hint, self.bits) {
            (HintKind::None, _) => HintSpec::None,
            (HintKind::Legacy, _) => HintSpec::LEGACY,
            (HintKind::Block, bits) => HintSpec::Block {
                bits: bits.unwrap_or(0),
            },
            (HintKind::Hull, bits) => HintSpec::Hull {
                bits: bits.unwrap_or(u8::MAX),
            },
        }
    }

    fn options(&self, name: Option<&str>, desc: Option<&str>) -> BuildOptions {
        let mut o = BuildOptions::new(name.unwrap_or(&self.name), desc.unwrap_or(&self.desc))
            .records(!self.no_records)
            .hashsets(!self.no_hashsets)
            .hint(self.hint_spec())
            .bits_policy(BitsPolicy {
                budget: self.budget,
                ..BitsPolicy::default()
            });
        if let Some(t) = &self.timestamp {
            o = o.timestamp(t.clone());
        }
        o
    }
}

#[derive(Args)]
struct MakeArgs {
    /// Hash types in column order, e.g. `md5,sha1` or `sha1,size`
    #[arg(short = 't', long, required = true, value_delimiter = ',')]
    types: Vec<HashType>,
    #[command(flatten)]
    out: OutputArgs,
    /// Input text files (default: stdin; `-` is stdin)
    inputs: Vec<PathBuf>,
}

#[derive(Args)]
struct FileArg {
    /// An .hset file
    file: PathBuf,
}

#[derive(Args)]
struct InfoArgs {
    file: PathBuf,
    /// Also list every chunk with its offset
    #[arg(long)]
    chunks: bool,
}

#[derive(Args)]
struct DumpArgs {
    file: PathBuf,
    /// Dump the hashes of this type only
    #[arg(short = 't', long)]
    r#type: Option<HashType>,
    /// Dump records (default when the file has records and no type is given)
    #[arg(long)]
    records: bool,
}

#[derive(Args)]
struct QueryArgs {
    file: PathBuf,
    /// Hash type to query (default: inferred from the hash length)
    #[arg(short = 't', long)]
    r#type: Option<HashType>,
    /// Read hex hashes, one per line, from this file (`-` is stdin)
    #[arg(short = 'f', long)]
    from: Option<PathBuf>,
    /// Print the matching records instead of found/missing
    #[arg(short = 'r', long)]
    records: bool,
    /// Print only the hashes that are found
    #[arg(long)]
    found_only: bool,
    /// Print nothing; the exit status says whether every hash was found
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Hex hashes to look up
    #[arg(allow_negative_numbers = true)]
    hashes: Vec<String>,
}

#[derive(Args)]
struct SetOpArgs {
    left: PathBuf,
    right: PathBuf,
    #[command(flatten)]
    out: OutputArgs,
}

#[derive(Args)]
struct ReindexArgs {
    input: PathBuf,
    #[command(flatten)]
    out: OutputArgs,
    /// Keep the input's name, description, and timestamp
    #[arg(long)]
    keep_metadata: bool,
}

#[derive(Args)]
struct BenchArgs {
    file: PathBuf,
    #[arg(short = 't', long)]
    r#type: Option<HashType>,
    /// Number of queries
    #[arg(long, default_value_t = 1_000_000)]
    queries: usize,
    /// Fraction of queries that are present in the set
    #[arg(long, default_value_t = 0.5)]
    hit_fraction: f64,
    /// Batch size for the batched run
    #[arg(long, default_value_t = 4096)]
    batch: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Search used inside the window for single lookups
    #[arg(long, value_enum, default_value_t = SingleKind::Auto)]
    single: SingleKind,
    /// Batch pipeline: auto (staged for small windows, lanes otherwise), staged, lanes, passes
    #[arg(long, value_enum, default_value_t = BatchKind::Auto)]
    batch_mode: BatchKind,
    /// Time only single lookups, only batches, or both
    #[arg(long, value_enum, default_value_t = Only::Both)]
    only: Only,
    /// Windows up to this many bytes are prefetched whole (default 1024)
    #[arg(long, default_value_t = 1024)]
    window_bytes: usize,
    /// Largest region one recursive level fetches, in bytes (default 512)
    #[arg(long, default_value_t = 512)]
    region_bytes: usize,
    /// Queries per sub-batch in the passes batch mode (default 32)
    #[arg(long, default_value_t = 32)]
    sub_batch: usize,
    /// Copy the file into anonymous memory (transparent huge pages) before timing
    #[arg(long)]
    copy: bool,
    /// Also time plain binary search without the hint, for comparison
    #[arg(long)]
    compare: bool,
}

type CliResult<T> = Result<T, String>;

/// `println!` that ignores a closed stdout (e.g. `| head`) instead of panicking.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}

fn err<T>(msg: impl std::fmt::Display) -> CliResult<T> {
    Err(msg.to_string())
}

fn map_file(path: &Path) -> CliResult<memmap2::Mmap> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: the mapping is read-only and the file is not expected to change
    // while this process runs; a concurrent writer could only produce garbage
    // input, which the decoder rejects, never undefined behaviour in safe code
    // paths that bounds-check every access.
    let m = unsafe { memmap2::Mmap::map(&f) }.map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(m)
}

fn load<'a>(buf: &'a [u8], path: &Path) -> CliResult<Hashset<'a>> {
    Hashset::load(buf).map_err(|e| format!("{}: {e}", path.display()))
}

fn open_input(path: &Path) -> CliResult<Box<dyn BufRead>> {
    if path.as_os_str() == "-" {
        Ok(Box::new(io::stdin().lock()))
    } else {
        let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Box::new(io::BufReader::new(f)))
    }
}

fn human(n: usize) -> String {
    if n >= 1 << 30 {
        format!("{:.2} GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.2} MiB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn write_output(path: &Path, bytes: &[u8]) -> CliResult<()> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn summarize(bytes: &[u8], path: &Path) -> CliResult<()> {
    let hs = load(bytes, path)?;
    let mut e = io::stderr().lock();
    let _ = writeln!(e, "wrote {} ({})", path.display(), human(bytes.len()));
    if let Some(r) = hs.record_header() {
        let _ = writeln!(
            e,
            "  records: {} x {} bytes",
            r.record_count, r.record_length
        );
    }
    for (i, s) in hs.sections().iter().enumerate() {
        let _ = writeln!(
            e,
            "  {}: {} hashes, hint {}",
            s.header.name,
            s.len(),
            s.hint.map_or("none".to_string(), |h| h.describe())
        );
        let _ = i;
    }
    Ok(())
}

fn cmd_make(a: MakeArgs) -> CliResult<()> {
    let mut b = Builder::new(&a.types).map_err(|e| e.to_string())?;
    let inputs: Vec<PathBuf> = if a.inputs.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        a.inputs.clone()
    };
    for input in &inputs {
        let reader = open_input(input)?;
        for (lineno, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("{}: {e}", input.display()))?;
            b.add_text_line(&line)
                .map_err(|e| format!("{}:{}: {e}", input.display(), lineno + 1))?;
        }
    }
    let bytes = b
        .build(&a.out.options(None, None))
        .map_err(|e| e.to_string())?;
    write_output(&a.out.output, &bytes)?;
    summarize(&bytes, &a.out.output)
}

fn cmd_info(a: InfoArgs) -> CliResult<()> {
    let m = map_file(&a.file)?;
    let hs = load(&m, &a.file)?;
    let f = hs.file();
    let out = io::stdout();
    let mut o = BufWriter::new(out.lock());
    let w = &mut o;
    let _ = writeln!(w, "file:        {} ({})", a.file.display(), human(m.len()));
    let _ = writeln!(w, "name:        {}", hs.name());
    let _ = writeln!(w, "description: {}", hs.description());
    let _ = writeln!(w, "timestamp:   {}", hs.timestamp());
    let _ = writeln!(w, "version:     {}", hs.version());
    let _ = writeln!(
        w,
        "sha2-256:    {} ({})",
        hex::encode(hs.sha2_256()),
        if hs.verify_digest() { "ok" } else { "MISMATCH" }
    );
    match hs.record_header() {
        Some(r) => {
            let _ = writeln!(
                w,
                "records:     {} x {} bytes",
                r.record_count, r.record_length
            );
            for fd in &r.fields {
                let _ = writeln!(
                    w,
                    "  field {:<10} {:<10} {} bytes",
                    fd.name,
                    fd.htype.to_string(),
                    fd.length
                );
            }
        }
        None => {
            let _ = writeln!(w, "records:     none");
        }
    }
    let _ = writeln!(w, "sections:    {}", hs.section_count());
    for (i, s) in hs.sections().iter().enumerate() {
        let lk = hs.lookup(i);
        let _ = writeln!(
            w,
            "  [{i}] {:<10} {:<10} {} x {} bytes{}",
            s.header.name,
            s.header.htype.to_string(),
            s.len(),
            s.header.hash_length,
            if s.ridx.is_some() {
                ", record index"
            } else {
                ""
            }
        );
        let _ = writeln!(
            w,
            "      hint: {}; strategy: {}; table {}",
            s.hint.map_or("none".to_string(), |h| h.describe()),
            lk.describe(),
            human(lk.table_bytes())
        );
    }
    if a.chunks {
        let _ = writeln!(w, "chunks:");
        for (off, ty) in &f.toc {
            let ch = format::chunk::read_chunk(&m, *off as usize).map_err(|e| e.to_string())?;
            let _ = writeln!(
                w,
                "  {:>12}  {:<4}  {} bytes",
                off,
                format::chunk::printable(*ty),
                ch.data.len()
            );
        }
    }
    Ok(())
}

/// Write one record as space-separated columns plus a newline.
fn write_record_line<W: Write>(hs: &Hashset<'_>, rec: &[u8], w: &mut W) -> io::Result<()> {
    for (k, (f, v)) in hs.record_fields(rec).iter().enumerate() {
        if k > 0 {
            w.write_all(b" ")?;
        }
        if let Some(v) = v {
            builder::write_value(f, v, w)?;
        }
    }
    w.write_all(b"\n")
}

fn cmd_dump(a: DumpArgs) -> CliResult<()> {
    let m = map_file(&a.file)?;
    let hs = load(&m, &a.file)?;
    let out = io::stdout();
    let mut o = BufWriter::new(out.lock());
    let dump_records = a.records || (a.r#type.is_none() && hs.record_header().is_some());
    if dump_records {
        if hs.record_header().is_none() {
            return err("file has no records");
        }
        for rec in hs.records() {
            if write_record_line(&hs, rec, &mut o).is_err() {
                break;
            }
        }
        return Ok(());
    }
    let sections: Vec<usize> = match a.r#type {
        Some(t) => vec![
            hs.index_for_type(t)
                .ok_or_else(|| format!("file has no {t} section"))?,
        ],
        None => (0..hs.section_count()).collect(),
    };
    for i in sections {
        let s = hs.section(i);
        let fd = format::FieldDescriptor {
            htype: s.header.htype,
            name: s.header.name.clone(),
            length: s.header.hash_length,
        };
        if a.r#type.is_none() && hs.section_count() > 1 {
            let _ = writeln!(o, "# {} ({} hashes)", s.header.name, s.len());
        }
        if matches!(fd.htype, HashType::Size | HashType::Entropy) {
            for j in 0..s.len() {
                let _ = builder::write_value(&fd, s.hash(j), &mut o);
                let _ = o.write_all(b"\n");
            }
        } else {
            // Digest sections: stream the whole sorted array as hex rows.
            let hl = s.hash_length();
            let _ = hex::encode_rows_to_writer(&s.data[..s.len() * hl], hl, b"\n", &mut o);
        }
    }
    Ok(())
}

fn section_for(hs: &Hashset<'_>, t: Option<HashType>, hash_len: Option<usize>) -> CliResult<usize> {
    if let Some(t) = t {
        return hs
            .index_for_type(t)
            .ok_or_else(|| format!("file has no {t} section"));
    }
    if hs.section_count() == 1 {
        return Ok(0);
    }
    if let Some(len) = hash_len {
        let matches: Vec<usize> = (0..hs.section_count())
            .filter(|&i| hs.section(i).hash_length() == len)
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0]);
        }
    }
    err("several sections match; choose one with --type")
}

fn cmd_query(a: QueryArgs) -> CliResult<ExitCode> {
    let m = map_file(&a.file)?;
    let hs = load(&m, &a.file)?;
    if hs.section_count() == 0 {
        return err("file has no hash sections");
    }
    let mut lines: Vec<String> = a.hashes.clone();
    if let Some(p) = &a.from {
        for line in open_input(p)?.lines() {
            let line = line.map_err(|e| format!("{}: {e}", p.display()))?;
            let line = line.trim();
            if !line.is_empty() {
                lines.push(line.to_string());
            }
        }
    }
    if lines.is_empty() {
        return err("no hashes given (pass them as arguments or with --from)");
    }
    let first_len = lines[0].len() / 2;
    let idx = section_for(&hs, a.r#type, Some(first_len))?;
    let s = hs.section(idx);
    let hl = s.hash_length();
    let fd = format::FieldDescriptor {
        htype: s.header.htype,
        name: s.header.name.clone(),
        length: s.header.hash_length,
    };

    let mut queries = Vec::with_capacity(lines.len() * hl);
    if matches!(fd.htype, HashType::Size | HashType::Entropy) {
        for l in &lines {
            let v = builder::parse_value(&fd, l).map_err(|e| e.to_string())?;
            queries.extend_from_slice(&v);
        }
    } else {
        hex::decode_rows(lines.iter().map(String::as_str), hl, &mut queries)
            .map_err(|e| e.to_string())?;
    }
    let mut found = vec![false; lines.len()];
    hs.contains_batch(idx, &queries, &mut found);

    let out = io::stdout();
    let mut o = BufWriter::new(out.lock());
    let mut missing = 0usize;
    for (i, l) in lines.iter().enumerate() {
        if !found[i] {
            missing += 1;
        }
        if a.quiet {
            continue;
        }
        if a.records {
            if found[i] {
                let recs = hs.records_for(idx, &queries[i * hl..(i + 1) * hl]);
                if recs.is_empty() {
                    let _ = writeln!(o, "{l}\tfound");
                }
                for r in recs {
                    let _ = write_record_line(&hs, r, &mut o);
                }
            } else if !a.found_only {
                let _ = writeln!(o, "{l}\tmissing");
            }
        } else if found[i] {
            let _ = writeln!(o, "{l}\tfound");
        } else if !a.found_only {
            let _ = writeln!(o, "{l}\tmissing");
        }
    }
    Ok(if missing == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn cmd_verify(a: FileArg) -> CliResult<ExitCode> {
    let m = map_file(&a.file)?;
    let hs = load(&m, &a.file)?;
    let r = hs.verify();
    out!("digest: {}", if r.digest_ok { "ok" } else { "MISMATCH" });
    for s in &r.sections {
        out!(
            "{}: {} hashes, sorted={}, duplicates={}, hint={}, hint_sound={}, window mean={:.1} max={}, table {}",
            s.name,
            s.count,
            s.sorted,
            s.duplicates,
            s.hint.as_deref().unwrap_or("none"),
            s.hint_sound,
            s.mean_window,
            s.max_window,
            human(s.table_bytes)
        );
    }
    if r.is_ok() {
        out!("OK");
        Ok(ExitCode::SUCCESS)
    } else {
        for p in &r.problems {
            out!("PROBLEM: {p}");
        }
        Ok(ExitCode::from(1))
    }
}

fn cmd_setop(op: SetOp, a: SetOpArgs) -> CliResult<()> {
    let ml = map_file(&a.left)?;
    let mr = map_file(&a.right)?;
    let fl = format::decode(&ml).map_err(|e| format!("{}: {e}", a.left.display()))?;
    let fr = format::decode(&mr).map_err(|e| format!("{}: {e}", a.right.display()))?;
    let b = ops::apply(op, &fl, &fr).map_err(|e| e.to_string())?;
    let desc = if a.out.desc.is_empty() {
        format!("{} of '{}' and '{}'", op.name(), fl.fhdr.name, fr.fhdr.name)
    } else {
        a.out.desc.clone()
    };
    let bytes = b
        .build(&a.out.options(None, Some(&desc)))
        .map_err(|e| e.to_string())?;
    write_output(&a.out.output, &bytes)?;
    summarize(&bytes, &a.out.output)
}

fn reindex_sections_only(
    f: &HsetFile<'_>,
    a: &ReindexArgs,
    name: &str,
    desc: &str,
    time: &str,
) -> CliResult<Vec<u8>> {
    let spec = a.out.hint_spec();
    let mut hints: Vec<Option<(u16, Vec<u8>)>> = Vec::new();
    for s in &f.sections {
        let h = if s.header.htype.is_digest() {
            let spec = lookup::resolve_bits(
                spec,
                s.len(),
                s.hash_length(),
                &BitsPolicy {
                    budget: a.out.budget,
                    ..BitsPolicy::default()
                },
            );
            lookup::build_hint(s.hash_length(), s.data, spec).map_err(|e| e.to_string())?
        } else {
            None
        };
        hints.push(h);
    }
    let doc = Document {
        version: format::FORMAT_VERSION,
        name,
        desc,
        time,
        records: None,
        hashsets: f
            .sections
            .iter()
            .zip(&hints)
            .map(|(s, h)| HashsetIn {
                htype: s.header.htype,
                name: &s.header.name,
                hash_length: s.hash_length(),
                data: s.data,
                hint: h.as_ref().map(|(t, b)| (*t, b.as_slice())),
                ridx: None,
                tivf: None,
            })
            .collect(),
    };
    format::encode(&doc).map_err(|e| e.to_string())
}

fn cmd_reindex(a: ReindexArgs) -> CliResult<()> {
    let m = map_file(&a.input)?;
    let f = format::decode(&m).map_err(|e| format!("{}: {e}", a.input.display()))?;
    let now = builder::now_utc();
    let (name, desc, time) = if a.keep_metadata {
        (
            f.fhdr.name.as_str(),
            f.fhdr.desc.as_str(),
            f.fhdr.time.as_str(),
        )
    } else {
        (
            a.out.name.as_str(),
            a.out.desc.as_str(),
            a.out.timestamp.as_deref().unwrap_or(now.as_str()),
        )
    };
    let bytes = match (&f.rhdr, f.rdat) {
        (Some(rhdr), Some(_)) => {
            let mut b = Builder::with_fields(rhdr.fields.clone());
            for i in 0..f.record_count() {
                b.add_raw_record(f.record(i).unwrap())
                    .map_err(|e| e.to_string())?;
            }
            let opts = a.out.options(Some(name), Some(desc)).timestamp(time);
            b.build(&opts).map_err(|e| e.to_string())?
        }
        _ => {
            if a.out.no_hashsets {
                return err("input has no records; cannot write a records-only file");
            }
            reindex_sections_only(&f, &a, name, desc, time)?
        }
    };
    write_output(&a.out.output, &bytes)?;
    summarize(&bytes, &a.out.output)
}

fn cmd_bench(a: BenchArgs) -> CliResult<()> {
    let mapped = map_file(&a.file)?;
    let copied;
    let m: &[u8] = if a.copy {
        let mut anon = memmap2::MmapOptions::new()
            .len(mapped.len())
            .map_anon()
            .map_err(|e| e.to_string())?;
        // Best effort: huge pages shrink TLB misses on large sets.
        let _ = anon.advise(memmap2::Advice::HugePage);
        anon.copy_from_slice(&mapped);
        copied = anon;
        &copied
    } else {
        &mapped
    };
    let cfg = SearchConfig {
        single: match a.single {
            SingleKind::Auto => SingleMode::Auto,
            SingleKind::Kary => SingleMode::KAry,
            SingleKind::Binary => SingleMode::Binary,
            SingleKind::Recursive => SingleMode::Recursive,
        },
        batch: match a.batch_mode {
            BatchKind::Auto => BatchMode::Auto,
            BatchKind::Staged => BatchMode::Staged,
            BatchKind::Lanes => BatchMode::Lanes,
            BatchKind::Passes => BatchMode::Passes,
        },
        window_prefetch_bytes: a.window_bytes.max(64),
        region_bytes: a.region_bytes.max(64),
        passes_sub_batch: a.sub_batch.clamp(1, 256),
    };
    let hs = Hashset::load_with(m, cfg).map_err(|e| format!("{}: {e}", a.file.display()))?;
    let idx = section_for(&hs, a.r#type, None)?;
    let s = hs.section(idx);
    let hl = s.hash_length();
    let queries = synth::queries(s.data, hl, a.queries, a.hit_fraction, a.seed);
    out!(
        "{}: {} hashes x {} bytes; {}; table {}",
        s.header.name,
        s.len(),
        hl,
        hs.lookup(idx).describe(),
        human(hs.lookup(idx).table_bytes())
    );

    let run = |lk: &dyn lookup::Lookup, label: &str| {
        let t = Instant::now();
        let mut hits = 0usize;
        if a.only != Only::Batch {
            for q in queries.chunks_exact(hl) {
                hits += usize::from(lk.contains(q));
            }
        }
        let single = t.elapsed();
        let mut out = vec![false; a.batch.max(1)];
        let t = Instant::now();
        let mut bhits = 0usize;
        if a.only != Only::Single {
            for (qs, n) in queries
                .chunks(hl * a.batch.max(1))
                .map(|c| (c, c.len() / hl))
            {
                lk.contains_batch(qs, &mut out[..n]);
                bhits += out[..n].iter().filter(|b| **b).count();
            }
        }
        let batch = t.elapsed();
        if a.only == Only::Both {
            assert_eq!(hits, bhits, "single and batch disagree");
        }
        out!(
            "{label:<28} single {:>8.1} ns/lookup   batch({}) {:>8.1} ns/lookup   hits {hits}/{}",
            single.as_nanos() as f64 / a.queries as f64,
            a.batch,
            batch.as_nanos() as f64 / a.queries as f64,
            a.queries
        );
    };
    run(hs.lookup(idx), "with hint");
    if a.compare {
        let basic = lookup::make_lookup_with(hl, s.data, None, cfg).map_err(|e| e.to_string())?;
        run(basic.as_ref(), "no hint (auto search)");
        let legacy = lookup::build_hint(hl, s.data, HintSpec::LEGACY).map_err(|e| e.to_string())?;
        if let Some((t, b)) = &legacy {
            let h = lookup::hint_from_parts(*t, b);
            let lk =
                lookup::make_lookup_with(hl, s.data, Some(&h), cfg).map_err(|e| e.to_string())?;
            run(lk.as_ref(), "legacy block8 hint");
        }
    }
    Ok(())
}

fn run(cli: Cli) -> CliResult<ExitCode> {
    match cli.cmd {
        Cmd::Make(a) => cmd_make(a).map(|()| ExitCode::SUCCESS),
        Cmd::Info(a) => cmd_info(a).map(|()| ExitCode::SUCCESS),
        Cmd::Dump(a) => cmd_dump(a).map(|()| ExitCode::SUCCESS),
        Cmd::Query(a) => cmd_query(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::Union(a) => cmd_setop(SetOp::Union, a).map(|()| ExitCode::SUCCESS),
        Cmd::Intersect(a) => cmd_setop(SetOp::Intersect, a).map(|()| ExitCode::SUCCESS),
        Cmd::Subtract(a) => cmd_setop(SetOp::Subtract, a).map(|()| ExitCode::SUCCESS),
        Cmd::Reindex(a) => cmd_reindex(a).map(|()| ExitCode::SUCCESS),
        Cmd::Bench(a) => cmd_bench(a).map(|()| ExitCode::SUCCESS),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("hset: error: {msg}");
            ExitCode::from(2)
        }
    }
}
