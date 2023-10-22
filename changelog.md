# 0.9.9 (2023-10-22)
* bump version
* bump date
* add this changelog.md
* add docs folder with manual & logic flow
* added flit to project
* renamed -l to -s and added support for blake3 to use it
* support for any number of hash inputs as comma separated instead of just all or one
* colorized every 16th checksum digit blue for easy readability on length
* modularized program by pulling functions out into separate files
* updated help section options into 3 rich panel segments: Hexsum specific, Standard, and Validation
* updated help to be more consistent
* added unbound protection by implementing yield generator on file read in 1MB blocks
