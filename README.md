[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AIGoFuzzing : MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
=================================================

To compile use `./configure.sh` and then `make`.

Usage:
----------------------------------

   ./multaigenfuzzer  <-i n> <out>  [-cl] [-h] [-r] [-s n]

Mandatory:
  -i n    sets the input bit-width to 'n'
  out     name of output file"

Optional:
  -cl     removes carry-lookahead adder from the fuzzing modules
  -h      prints this help
  -r      enables reencoding of generated AIG
  -s n    sets the seed to 'n' (default: randomly generated)


Daniela Kaufmann,
Mo Mar 28 13:13:20 2022
