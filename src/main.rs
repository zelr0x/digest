use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, ValueEnum};
use digest::{Digest, DynDigest};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

/// A prefix for all messages to stderr.
const ERR_PREFIX: &str = "digest: ";

const DEFAULT_128_BIT_ALG: Alg = Alg::Md5;
const DEFAULT_160_BIT_ALG: Alg = Alg::Sha1;
const DEFAULT_224_BIT_ALG: Alg = Alg::Sha224;
const DEFAULT_256_BIT_ALG: Alg = Alg::Sha256;
const DEFAULT_384_BIT_ALG: Alg = Alg::Sha384;
const DEFAULT_512_BIT_ALG: Alg = Alg::Sha512;

const DEFAULT_ALG: &[Alg] = &[
    DEFAULT_128_BIT_ALG,
    DEFAULT_160_BIT_ALG,
    DEFAULT_256_BIT_ALG,
    DEFAULT_512_BIT_ALG,
];

// Each variant must have a clap name set.
#[derive(Clone, Copy, ValueEnum)]
enum Alg {
    // MD5
    #[value(alias("MD5"))]
    #[clap(name = "md5")]
    Md5,

    // SHA1
    #[value(alias("SHA1"))]
    #[clap(name = "sha1")]
    Sha1,

    // SHA2
    #[value(alias("SHA2-224"))]
    #[value(alias("sha2-224"))]
    #[value(alias("SHA224"))]
    #[clap(name = "sha224")]
    Sha224,

    #[value(alias("SHA2-256"))]
    #[value(alias("sha2-256"))]
    #[value(alias("SHA256"))]
    #[clap(name = "sha256")]
    Sha256,

    #[value(alias("SHA2-384"))]
    #[value(alias("sha2-384"))]
    #[value(alias("SHA384"))]
    #[clap(name = "sha384")]
    Sha384,

    #[value(alias("SHA2-512"))]
    #[value(alias("sha2-512"))]
    #[value(alias("SHA512"))]
    #[clap(name = "sha512")]
    Sha512,

    #[value(alias("SHA512-224"))]
    #[clap(name = "sha512-224")]
    Sha512_224,

    #[value(alias("SHA512-256"))]
    #[clap(name = "sha512-256")]
    Sha512_256,

    // SHA3
    #[value(alias("SHA3-224"))]
    #[clap(name = "sha3-224")]
    Sha3_224,

    #[value(alias("SHA3-256"))]
    #[clap(name = "sha3-256")]
    Sha3_256,

    #[value(alias("SHA3-384"))]
    #[clap(name = "sha3-384")]
    Sha3_384,

    #[value(alias("SHA3-512"))]
    #[clap(name = "sha3-512")]
    Sha3_512,
}

#[allow(unused)]
impl Alg {
    fn name(&self) -> &'static str {
        match self {
            Alg::Md5 => "MD5",
            Alg::Sha1 => "SHA1",
            Alg::Sha224 => "SHA224",
            Alg::Sha256 => "SHA256",
            Alg::Sha384 => "SHA384",
            Alg::Sha512 => "SHA512",
            Alg::Sha512_224 => "SHA512-224",
            Alg::Sha512_256 => "SHA512-256",
            Alg::Sha3_224 => "SHA3-224",
            Alg::Sha3_256 => "SHA3-256",
            Alg::Sha3_384 => "SHA3-384",
            Alg::Sha3_512 => "SHA3-512",
        }
    }
}

/// Calculates checksums for given files or a standard input stream.
#[derive(Parser)]
#[command(
    name = "digest",
    version,
    about,
    override_usage = "digest [OPTION]... [FILE]...",
    long_about = None,
    after_help = r#"
The default mode is to print a line with checksum, a space, a character
indicating input mode ('*' for binary, ' ' for text or where binary is
insignificant), and the name for each FILE.

Note: There is no difference between binary mode and text mode on GNU systems,
there should be difference in Windows in some cases, but it is currently not
supported - binary and text flags currently exist for backwards compatibility.

When two positional parameters are supplied, the program checks if there is
a file in the current directory with a name matching the last positional
parameter, if there is no such file, it is treated as an expected digest
to compare the calculated digest of the first file with. If you want to
force this check even in the presense of a file named as the digest value
in the current directory, specify (-e | --eq) option.

Return codes:
0 - success
1 - invalid usage, digest mismatch, missing file or file read error,
    improperly formatted digest in fast-check mode
2 - improperly formatted checksum file
3 - unexpected error"#,
)]
struct Args {
    /// the target file or, in a check mode (-c), a checksum file
    file: Vec<String>,

    /// treat the last positional argument as expected digest for fast check
    #[arg(short = 'e', long = "eq")]
    eq: bool,

    /// the algorithms to use
    #[clap(hide_possible_values = true)] // there is --list for that
    #[arg(short = 'a', long = "alg", value_enum)]
    alg: Vec<Alg>,

    /// list supported algorithms
    #[arg(long = "list", default_value_t = false)]
    list: bool,

    /// read in binary mode (default unless reading tty stdin)
    #[arg(short = 'b', long = "binary", default_value_t = false)]
    binary: bool,

    /// read in text mode (deafult if reading tty stdin)
    #[arg(short = 't', long = "text", default_value_t = false)]
    text: bool,

    /// print algorithm even if only one algorithm is specified; more verbose check
    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    verbose: bool,

    /// don't print the filename if only one algorithm is specified
    #[arg(long = "digest-only", default_value_t = false)]
    digest_only: bool,

    /// read sums from the FILEs and check them
    #[arg(short = 'c', long = "check", default_value_t = false)]
    check: bool,

    /// create a BSD-style checksum
    #[arg(long = "tag", default_value_t = false)]
    tag: bool,

    /// resolve file paths within the checksum file relative to that file's parent
    #[arg(long = "relative", default_value_t = false)]
    relative: bool,

    /// don't fail or report status for missing files
    #[arg(long = "ignore-missing", default_value_t = false)]
    ignore_missing: bool,

    /// don't print OK for each successfully verified file
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    quiet: bool,

    /// don't output anything, status code shows success
    #[arg(long = "status", default_value_t = false)]
    status: bool,

    /// exit non-zero for improperly formatted checksum lines
    #[arg(long = "strict", default_value_t = false)]
    strict: bool,

    /// warn about improperly formatted checksum lines
    #[arg(short = 'w', long = "warn", default_value_t = false)]
    warn: bool,
}

fn checkonly(optval: bool, optname: &str) {
    if !optval {
        return;
    }
    eprintln!(
        "{}the {} option is meaningful only when verifying checksums",
        ERR_PREFIX, optname
    );
    exit(1);
}

fn fopen_or_exit(filename: &str) -> File {
    File::open(filename).unwrap_or_else(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            eprintln!("{}{}: No such file or directory", ERR_PREFIX, filename);
            exit(1);
        } else {
            eprintln!("{}could not open file {}: {}", ERR_PREFIX, filename, e);
            exit(1);
        }
    })
}

fn guess_alg(digest_str: &str) -> Option<Alg> {
    let a = match digest_str.len() / 2 {
        16 => DEFAULT_128_BIT_ALG,
        20 => DEFAULT_160_BIT_ALG,
        28 => DEFAULT_224_BIT_ALG,
        32 => DEFAULT_256_BIT_ALG,
        48 => DEFAULT_384_BIT_ALG,
        64 => DEFAULT_512_BIT_ALG,
        _ => return None,
    };
    Some(a)
}

fn hasher(a: Alg) -> Box<dyn DynDigest> {
    match a {
        Alg::Md5 => Box::new(Md5::new()),
        Alg::Sha1 => Box::new(Sha1::new()),
        Alg::Sha224 => Box::new(Sha224::new()),
        Alg::Sha256 => Box::new(Sha256::new()),
        Alg::Sha384 => Box::new(Sha384::new()),
        Alg::Sha512 => Box::new(Sha512::new()),
        Alg::Sha512_224 => Box::new(Sha512_224::new()),
        Alg::Sha512_256 => Box::new(Sha512_256::new()),
        Alg::Sha3_224 => Box::new(Sha3_224::new()),
        Alg::Sha3_256 => Box::new(Sha3_256::new()),
        Alg::Sha3_384 => Box::new(Sha3_384::new()),
        Alg::Sha3_512 => Box::new(Sha3_512::new()),
    }
}

fn hash(
    alg: &[Alg],
    file: &mut dyn Read,
    buf: &mut [u8],
    _binary: bool,
) -> Result<Vec<Box<[u8]>>, io::Error> {
    let mut hs: Vec<_> = alg.iter().map(|a| hasher(*a)).collect();
    loop {
        let n = match file.read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        for h in &mut hs {
            h.update(&buf[..n]);
        }
    }
    let res = hs.into_iter().map(|h| h.finalize()).collect();
    Ok(res)
}

fn print_hex(bytes: &[u8], buf: &mut [u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = bytes.len();
    for (i, &b) in bytes.iter().enumerate() {
        buf[2 * i] = HEX[(b >> 4) as usize];
        buf[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    let mut out = io::stdout(); // TODO: could reuse
    out.write_all(&buf[..2 * n]).unwrap_or_else(|e| {
        eprintln!("{}failed to output digest: {}", ERR_PREFIX, e);
        exit(3);
    });
    out.flush()
}

#[inline]
fn hex_val(b: u8) -> Result<u8, String> {
    let res = match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => return Err(format!("invalid hex char '{}'", b)),
    };
    Ok(res)
}

fn decode_digest(hexs: &str, digest_buf: &mut Vec<u8>) -> Result<(), String> {
    let bytes = hexs.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        digest_buf.push((hi << 4) | lo);
    }
    Ok(())
}

// TODO:
// Proper text and binary mode handling on Windows requires using Win32 API.
// Currently, files are not opened in text mode and line endings are not
// normalized. The options are preserved mainly for the tag output.
fn main() {
    let args = Args::parse();

    if args.list {
        for a in Alg::value_variants() {
            let av = a.to_possible_value().unwrap();
            println!("{}", av.get_name());
        }
        exit(0);
    }

    if !args.check {
        checkonly(args.ignore_missing, "--ignore-missing");
        checkonly(args.quiet, "--quiet");
        checkonly(args.status, "--status");
        checkonly(args.strict, "--strict");
        checkonly(args.warn, "--warn");
        checkonly(args.relative, "--relative");
    }

    let mut binary = args.binary;
    let text = args.text;
    // TODO: allow this and make the last specified win as in coreutils?
    if binary && text {
        eprintln!(
            "{}binary and text options are mutually exclusive",
            ERR_PREFIX
        );
        exit(1);
    }

    let (files, expected) = {
        let mut files = args.file;
        let mut expected: Option<String> = None;
        if files.len() > 1 {
            expected = if args.eq {
                // TODO: allow reading expected from stdin when eq is specified and files.len() == 1?
                files.pop()
            } else {
                match files.last() {
                    Some(last) if !Path::new(last).is_file() => files.pop(),
                    _ => None,
                }
            };
        }
        (files, expected)
    };

    let filename = if files.is_empty() { "-" } else { &files[0] };
    let mut filepath: Option<&Path> = None;
    let mut file: Box<dyn Read> = if filename == "-" {
        // text = !binary; // implied, uncomment if needed.
        Box::new(io::stdin())
    } else {
        binary = !text;
        let p = Path::new(&filename);
        if p.is_dir() {
            eprintln!("{}{}: Is a directory", ERR_PREFIX, filename);
            exit(1);
        }
        filepath = Some(p);
        let f = fopen_or_exit(filename);
        Box::new(f)
    };

    let mut alg: &[Alg] = &args.alg;
    let mut buf = [0u8; 8 * 1024];

    // mode: fast-check mode (hash(file[0]) == expected)
    if let Some(exp_digest_str) = &expected {
        let mut digest_buf: Vec<u8> = Vec::with_capacity(64);
        if let Err(e) = decode_digest(exp_digest_str, &mut digest_buf) {
            println!("{}: FAILED: improperly formatted digest: {}", filename, e);
            exit(1);
        }
        let exp_digest = &digest_buf;
        let got_digest = if alg.len() == 1 {
            hash(alg, &mut file, &mut buf, binary).unwrap_or_else(|e| {
                if !args.status {
                    eprintln!(
                        "{}failed to calculate digest {}: {}",
                        ERR_PREFIX, filename, e
                    );
                }
                exit(3);
            })
        } else {
            let alg = guess_alg(exp_digest_str).unwrap_or_else(|| {
                if !args.status {
                    eprintln!(
                        "{}could not guess algorithm, specify one with -a",
                        ERR_PREFIX
                    );
                }
                exit(1);
            });
            if args.verbose {
                println!("guessed algorithm: {}", alg.name());
            }
            let mut algs: [Alg; 1] = [Alg::Md5]; // dummy init value
            algs[0] = alg;
            hash(&algs, &mut file, &mut buf, binary).unwrap_or_else(|e| {
                if !args.status {
                    eprintln!(
                        "{}failed to calculate digest {}: {}",
                        ERR_PREFIX, filename, e
                    );
                }
                exit(3);
            })
        };
        assert_eq!(1, got_digest.len());
        let got_digest = got_digest.into_iter().next().unwrap();
        if exp_digest == got_digest.as_ref() {
            if !args.quiet {
                println!("{}: OK", filename);
            }
        } else {
            if !args.status {
                println!("{}: FAILED", filename);
            }
            exit(1);
        }
        exit(0);
    }

    // mode: check
    // Maybe try to detect alg by name as well when  not specified by the user?
    if args.check {
        let reader = BufReader::new(file);
        let mut digest_buf = Vec::with_capacity(64);

        let mut algs: Vec<Alg> = Vec::with_capacity(1); // dummy init value
        if alg.len() == 1 {
            algs.push(alg[0]);
        }

        let mut malformed = 0;
        let mut missing = 0;
        let mut mismatched = 0;
        let mut well_formed = 0;
        for (i, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    if args.verbose {
                        eprintln!("{}{}: {}: {}", ERR_PREFIX, filename, i, e);
                    }
                    continue;
                }
            };
            if line.trim().is_empty() {
                malformed += 1;
                if args.warn {
                    eprintln!(
                        "{}{}: {}: improperly formatted checksum line",
                        ERR_PREFIX, filename, i
                    );
                }
                continue;
            }
            let parts: Vec<_> = line.split_whitespace().collect();
            let mut digest_offset_parts = 0;
            let mut digest_offset_bytes = 0;

            let mut alg_override: Option<Alg> = None;
            if parts.len() == 3 {
                // If 3 parts, we assume the checksum is in the format generated
                // by this program without --tag and with either --verbose
                // or with multiple algorithms used during generation.
                let algpart = &parts[0];
                let alg = match Alg::from_str(algpart, true) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!(
                            "{}{}: {}: improperly formatted checksum line: {}",
                            ERR_PREFIX, filename, i, e
                        );
                        continue;
                    }
                };
                if args.verbose {
                    println!("parsed algorithm: {}", alg.name());
                }
                alg_override = Some(alg);
                digest_offset_parts = 1;
                digest_offset_bytes = algpart.len() + 1;
            } else if parts.len() != 2 {
                malformed += 1;
                if args.warn {
                    eprintln!(
                        "{}{}: {}: improperly formatted checksum line",
                        ERR_PREFIX, filename, i
                    );
                }
                continue;
            }
            let exp_digest_str = parts[digest_offset_parts];
            if i == 0 && algs.is_empty() {
                let alg = guess_alg(exp_digest_str).unwrap_or_else(|| {
                    if !args.status {
                        eprintln!(
                            "{}could not guess algorithm, specify one with -a",
                            ERR_PREFIX
                        );
                    }
                    exit(1);
                });
                if args.verbose {
                    println!("guessed algorithm: {}", alg.name());
                }
                algs.push(alg);
            }
            let rest = line[digest_offset_bytes + exp_digest_str.len()..].trim_start();
            digest_buf.clear();
            let exp_digest = match decode_digest(exp_digest_str, &mut digest_buf) {
                Err(_) => {
                    malformed += 1;
                    if args.warn {
                        eprintln!(
                            "{}{}: {}: improperly formatted checksum line",
                            ERR_PREFIX, filename, i
                        );
                    }
                    continue;
                }
                Ok(_) => &digest_buf,
            };
            let (sep, fname) = rest.split_at(1);
            let bin = sep == "*";

            let fpath: PathBuf = if args.relative {
                filepath
                    .and_then(|fp| fp.parent().map(|p| p.join(fname)))
                    .unwrap_or_else(|| fname.into())
            } else {
                fname.into()
            };
            well_formed += 1; // Maybe move to a later stage?
            let mut f = match File::open(fpath) {
                Ok(f) => f,
                Err(e) => {
                    missing += 1;
                    if args.ignore_missing {
                        continue;
                    }
                    if e.kind() == io::ErrorKind::NotFound {
                        // Ignoring args.status here is consistent with reference implementation.
                        eprintln!("{}: {}: No such file or directory", ERR_PREFIX, fname);
                    } else {
                        eprintln!("{}: {}: {}", ERR_PREFIX, fname, e);
                    }
                    if !args.status {
                        println!("{}: FAILED open or read", fname);
                    }
                    continue;
                }
            };
            let mut aa: [Alg; 1] = [Alg::Md5]; // dummy init value
            let alg: &[Alg] = match alg_override {
                Some(a) => {
                    aa[0] = a;
                    &aa
                }
                None => &algs,
            };
            let got_digest = hash(alg, &mut f, &mut buf, bin).unwrap_or_else(|e| {
                eprintln!("{}failed to calculate digest: {}", ERR_PREFIX, e);
                exit(3);
            });
            assert_eq!(1, got_digest.len());
            let got_digest = got_digest.into_iter().next().unwrap();
            if args.verbose {
                print!("{}: calculated {} digest: ", fname, alg[0].name());
                let _ = print_hex(&got_digest, &mut buf);
                println!();
            }
            if exp_digest == got_digest.as_ref() {
                if !args.quiet {
                    println!("{}: OK", fname);
                }
            } else {
                if !args.status {
                    println!("{}: FAILED", fname);
                }
                mismatched += 1;
            }
        }
        if malformed > 0 {
            eprintln!(
                "{}WARNING: {} lines are improperly formatted",
                ERR_PREFIX, malformed
            );
        }
        if missing > 0 && (!args.ignore_missing || malformed > 0 || mismatched > 0) {
            // Warn about missing only when not ignoring missing OR when
            // any other warnings are issued anyway.
            eprintln!(
                "{}WARNING: {} listed files could not be read",
                ERR_PREFIX, missing
            );
        }
        if mismatched > 0 {
            eprintln!(
                "{}WARNING: {} computed checksum did NOT match",
                ERR_PREFIX, mismatched
            );
        }
        if well_formed == 0 {
            eprintln!(
                "{}{}: no properly formatted checksum lines found",
                ERR_PREFIX, filename
            );
            exit(1);
        }
        if mismatched > 0 || (missing > 0 && !args.ignore_missing) {
            exit(1);
        }
        if args.strict && malformed > 0 {
            exit(2);
        }
        exit(0);
    }

    // mode: hash
    if alg.is_empty() {
        alg = DEFAULT_ALG;
    }
    for filename in files {
        let mut file = fopen_or_exit(&filename);
        let ds = hash(alg, &mut file, &mut buf, binary).unwrap_or_else(|e| {
            eprintln!("{}failed to calculate digest: {}", ERR_PREFIX, e);
            exit(3);
        });
        for (i, a) in alg.iter().enumerate() {
            let d = &ds[i];
            let av = a.to_possible_value().unwrap();
            if args.tag {
                print!("{} ({}) = ", av.get_name(), filename);
                print_hex(d, &mut buf).unwrap_or_else(|e| {
                    eprintln!("{}failed to output digest: {}", ERR_PREFIX, e);
                });
                println!();
            } else {
                if alg.len() > 1 || args.verbose {
                    print!("{} ", av.get_name());
                }
                print_hex(d, &mut buf).unwrap_or_else(|e| {
                    eprintln!("{}failed to output digest: {}", ERR_PREFIX, e);
                });
                if !args.digest_only {
                    if binary {
                        println!(" *{}", filename);
                    } else {
                        println!("  {}", filename);
                    }
                }
            }
        }
    }
}
