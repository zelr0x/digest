# digest

Calculates checksums for given files or a standard input stream.

## Features
- Normal and check modes implemented very close to GNU coreutils (md5sum, sha256sum, etc.) APIs
- Fast check mode to compare with the expected digest
- Relative check mode to avoid switching directories to check
- Multiple algorithms in one tool, multiple digests per file, algorithm detection
- Check mode supports a checksum file format with digests calculated with different algorithms


## Usage

### Normal mode

Normal mode allows to calculate multiple digests at once for every specified file.

```bash
digest Cargo.toml
md5 d5b8f89ce311568b6f99ee11ae18caca *cargo.toml
sha1 f59b269cf0afe557e41962a200c81a7aebefd69f *cargo.toml
sha256 e57ae0b20a81dbb9ba31508fc1bccd0df00e2bc7e58643c92b6bc96b633423e1 *cargo.toml
sha512 ec0ee5516e59a34b0a1a9559b832d5e793f585e821fcea0e98193c194460196f349c9616b7110394d5f8f5dcd8a9caeb6094c4b3bb45f3f4dd0c1fb8a15c5cfe *cargo.toml
```

You can specify algorithms with `-a`. 
```bash
digest -a sha256 -a sha512 Cargo.toml
sha256 e57ae0b20a81dbb9ba31508fc1bccd0df00e2bc7e58643c92b6bc96b633423e1 *cargo.toml
sha512 ec0ee5516e59a34b0a1a9559b832d5e793f585e821fcea0e98193c194460196f349c9616b7110394d5f8f5dcd8a9caeb6094c4b3bb45f3f4dd0c1fb8a15c5cfe *cargo.toml
```

List supported algorithms with `--list`.

By default md5, sha1, sha256 (sha2-256), and sha512 (sha2-512) are used
when `-a` option is not supplied.


### Fast check mode

Fast check mode allows to quickly compare with the expected digest

```bash
digest -a sha256 Cargo.toml e57ae0b20a81dbb9ba31508fc1bccd0df00e2bc7e58643c92b6bc96b633423e1
cargo.toml: OK
```

The algorithm can be guessed based on length of the supplied digest

```bash
digest Cargo.toml e57ae0b20a81dbb9ba31508fc1bccd0df00e2bc7e58643c92b6bc96b633423e1
cargo.toml: OK
```

The default algorithm for every length is currently hardcoded in constants
at the top of the `src/main.rs`, feel free to modify them to your liking.

Note that if the current directory contains a file named exactly as the supplied
digest, it will be treated as a second file to calculate digests for. To override
this behavior and still do the check, use `-e` option. This is usually not needed
though.

### Check mode

Check mode allows to check digests using the checksum file

```bash
digest digest-v0.1-sha256sum.txt
Cargo.toml: OK
Cargo.lock: OK
missing_file: FAILED open or read
existing_but_wrong_digest: FAILED
digest: WARNING: 1 computed checksum did NOT match
```

#### Relative check
 `--relative` option allows to check digests via a checksum file
 treating all paths inside relative to the path of the checksum file
 itself. This is useful when you're not in the same directory as
 the checksum file and the files specified inside it.


### Full help

```bash
digest --help
Usage: digest [OPTION]... [FILE]...

Arguments:
  [FILE]...  the target file or, in a check mode (-c), a checksum file

Options:
  -e, --eq              treat the last positional argument as expected digest for fast check
  -a, --alg <ALG>       the algorithms to use
      --list            list supported algorithms
  -b, --binary          read in binary mode (default unless reading tty stdin)
  -t, --text            read in text mode (deafult if reading tty stdin)
  -v, --verbose         print algorithm even if only one algorithm is specified; more verbose check
      --digest-only     don't print the filename if only one algorithm is specified
  -c, --check           read sums from the FILEs and check them
      --tag             create a BSD-style checksum
      --relative        resolve file paths within the checksum file relative to that file's parent
      --ignore-missing  don't fail or report status for missing files
  -q, --quiet           don't print OK for each successfully verified file
      --status          don't output anything, status code shows success
      --strict          exit non-zero for improperly formatted checksum lines
  -w, --warn            warn about improperly formatted checksum lines
  -h, --help            Print help
  -V, --version         Print version


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
3 - unexpected error
```
