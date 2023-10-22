# Command Logic
The Order of Precedence used by the program

## ARGUMENTS
FILE = This is the single file to checksum (shell can pass * to checksum everything in a directory)

## Option Order
These two evaluate whichever is first in CLI switch order:
1a)     -a          Is evaluated first -- prints all available hashes and exits
1b)     --version   Is evaluated first -- prints version and exits

2)      --help      Is also an eager evaluation but below the first two -- prints help and exits

3)      --zzz       Boring legacy style output -- evaluate here to know how to format data and ignore -v display
4)      --gnu       Above --tag since BSD style is default so this needs to override.
5)      --tag       Default style

6)      -c          This has to evaluate here to treat the FILE argument as a checksum file to read instead of hash

7)      -b          Option has no effect because it is always on; all data is binary check-summed.

8)      -h          Set the hash or hashes to use
9)      -s          Set Shake size to use if shake, or ignore

10)     -v          Read xattr values for comparison
11)     -C          CLI compare value

<Read File>
<Hash File or files if -c>

12)     -V          Write xattr value for future comparison (validate file integrity over time)

13)     -Z          Write checksum file for future use
<write File>

Console Output setup
14)     --ignore-missing    Don't print missing files
15)     --quiet     Don't print OK for good files
16)     --status    Don't print anything
17)     --strict    Warn about improperly formatted checksums
18)     -w          Warn about bad checksum lines (in file)

<compare steps here>
-c
-C
-v
<console out>
zzz/rich
    gnu
        tag
            c/C
                v


19)     -t      Option has no effect as nothing is check-summed in text mode. Is here to not throw error from invalid option.
