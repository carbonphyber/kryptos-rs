# kryptos-rs
Tools written in Rust to assist with solving the mystery surrounding Kryptos scupture at CIA Langley.

# About
The Kryptos sculpture was commissioned in about 1988 to be created in the courtyard of CIA headquarters. Jim Sanborn, the artist, worked with a retiring CIA deputy director to create encrypted messages which are hidden in the sculpture(s).

Useful links:

- [Elonk's Kryptos Page](http://www.elonka.com/kryptos/)
- [KarlWang @ UCSD](http://www.math.ucsd.edu/~crypto/Projects/KarlWang/index2.html)

So-called K0, K1, K2, K3 are subsections of the mystery and have all been previously deciphered by smarter minds than myself. K4 remains to be deciphered (at least disclosed to the public). This project aims to programmatically decipher K1, K2, K3. And possibly K4 if I get very ambitious.

# Usage
* Install Rust programming environment
* clone the repo to a local `kryptos-rs` directory
* `cd kryptos-rs`
* `cargo build` ("cargo" is the Rust packaging command)
* `scripts/k1.sh` ("K1" is the first of four sections of the Kryptos tableau). Ensure this script has execute permissions.

# Philosophy
These scripts accept CLI parameters and write to STDOUT.
Sections that have been previously deciphered and publicly revealed have BASH scripts in this repo to decipher them.


# License
MIT licensed project.

# Author
[CarbonPhyber](https://github.com/carbonphyber/)
