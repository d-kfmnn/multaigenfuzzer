[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
=================================================

Our tool MultAIGenFuzzer is a mutation-based fuzzing tool for AIGs.

For further information we refer to the paper

Daniela Kaufmann, Armin Biere. 
 [`Fuzzing and Delta Debugging And-Inverter Graph Verification Tools.`](https://danielakaufmann.at/wp-content/uploads/2022/07/TAP_Kaufmann.pdf)
In Proc. 16th Intl. Conference on Tests and Proofs (TAP), p. 69-88, 2022.

and the corresponding website http://fmv.jku.at/aigfuzzing_artifact/ where you can find experimental data.

Build:
----------------------------------

To compile use `./configure.sh` and then `make`.

Usage:
----------------------------------

      ./multaigenfuzzer  <-i n> <out>  [-cl] [-h] [-r] [-s n]

Mandatory:  

      -i n    sets the input bit-width to 'n'  
      out     name of output file  

Optional:  

      -cl     removes carry-lookahead adder from the fuzzing modules  
      -h      prints this help  
      -r      enables reencoding of generated AIG  
      -s n    sets the seed to 'n' (default: randomly generated)  

