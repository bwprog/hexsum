---
title: HEXSUM
section: 1
header: User Manual
footer: hexsum 1.0.0
date: 2023-10-22
---

# NAME
hexsum: a python checksum tool using OpenSSL, xxhash, and blake3.

# SYNOPSIS
**hexsum** [*OPTION*] FILE

# DESCRIPTION
**hexsum** is a Python script using hashlib (OpenSSL), xxhash, and blake3 algorithms to create or validate checksums.

Hexsum Options      (New Options provided by hexsum)
-a          Print all available <HASH> types and exit.
-C=TEXT     Compare to provided checksum; use -h <HASH> to match source algorithm; will attempt to compare to all with "-h all"; ex: "-c=bf3ed5f58439bd05"
--gnu       Traditional GNU checksum output "<CHECKSUM> FILE" with no indication of <HASH> algorithm used; use "--zzz" to output this legacy style to console instead of rich Colorized output.
-h=TEXT     <HASH> type to run; "-h all" will checksum the FILE with all <HASH>es; use "-a" to view available <HASH>es; use comma delimination with no space for multiple <HASH>es;ex: "-h sha256,blake3" will checksum the FILE with sha256 and blake3. [default: sha256]
-s=INT      Use with "-h shake_128" or "-h shake_256"; otherwise ignored. [default: 32]
-v          Read xattr for saved checksums and validate against live checksum.
-V          Write xattr checksums as "user.<HASH>.hash" and "user.<HASH>.date" for future validation.
-Z          Write checksum file as "CHECKSUM.<HASH>-FILE in "--tag" (BSD) style [DEFAULT]; or as <FILE.<HASH> in
            "--gnu" (GNU) mode.

Standard Options    (Standard Options found in legacy programs like md5sum)
-b          Read in binary mode; legacy switch, ignored as always read binary. [default: True]
-c          Read checksums from the FILEs and check them; use "--gnu" to force non-BSD style.
-t          Read in text mode; legacy switch, ignored as always read binary ("-b").
--tag       Create a BSD-style checksum format e.g. "<HASH> (FILE) = checksum"); use "--zzz" to output this legacy style to console instead of rich Colorized output. [default: True]
-z          End each output line with NUL instead of newline, and disable file name escaping. [default: True]
--version   Print version and exit.
--help      Show this message and exit.

Validation Options  (Used when verifying checksums)
--ignore-missing    Do not print, report, or exit code fail for missing files.
--quiet             Do not print OK for each successfully verified file.
--status            Do not print anything; exit codes shows success.
--strict            Exit non-zero code for improperly formatted checksum lines.
-w                  Warn about improperly formatted checksum lines.


# AUTHOR
Written by Brandon Wells.

# REPORTING BUGS
github:

# COPYRIGHT
Copyright © 2023 Brandon Wells, License GPLv3+:  GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.
