/*------------------------------------------------------------------------*/
/*! \file aigofuzzing.cpp
    \brief main file of our tool AIGoFuzzing

  Part of MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
  Copyright(C) 2022 Daniela Kaufmann, Johannes Kepler University Linz
*/
/*------------------------------------------------------------------------*/
#define VERSION "1.0"
/*------------------------------------------------------------------------*/
// / Manual of AIGoFuzzing, will be printed with command line '-h'
static const char * USAGE =
"[maf] \n"
"[maf] ### USAGE ###\n"
"[maf] usage : multaigenfuzzer  <-i n> <out>  [-cl] [-h] [-r] [-s n] \n"
"[maf] \n"
"[maf] -i n    sets the input bit-width to 'n' \n"
"[maf] out     name of output file\n"
"[maf] \n"
"[maf] -cl     removes carry-lookahead adder from the fuzzing modules \n"
"[maf] -h      prints this help\n"
"[maf] -r      enables reencoding of generated AIG\n"
"[maf] -s n    sets the seed to 'n'\n"
"[maf] \n";
/*------------------------------------------------------------------------*/
#include "fuzzer.h"
#include <algorithm>
#include <climits>
#include <cstring>
#include <time.h>

/*------------------------------------------------------------------------*/
// / Name of the input file
static const char * output_name = 0;
static double seed = 0;


static int invalid_argument = 11;

/*------------------------------------------------------------------------*/
static bool isNumber(const std::string &s) {
  return !s.empty() && std::find_if(s.begin(),
        s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}


/**
    @see init_all_signal_handlers()
*/
static void init_all(double size, bool use_cl) {
  init_all_signal_handers();

  msg(1,"MultAIGenFuzzer " VERSION);
  msg(1,"Generation-Based AIG Fuzzer for Multipliers");
  msg(1,"Copyright(C) 2022, Daniela Kaufmann, Johannes Kepler University Linz");
  msg(1,"____________________________________________________________________");
  msg(1,"");
  msg(1,"");

  if(!seed) {
    srand(time(NULL));
    seed = rand()%INT_MAX;
  }

  msg(1, "Initialization");
  msg(1, "==========================================================");
  msg(1, "  Seed:            %.f", seed);
  msg(1, "  Size:            %g", size);
  msg(1, "  CLA elements:    %s", use_cl ? "ON" : "OFF");
  msg(1,"");

  srand(seed);

  init_time = process_time();

  init_aig(size);

}
/*------------------------------------------------------------------------*/

/**
    Calls the deallocaters of the involved data types
    @see reset_all_signal_handlers()
*/
static void reset_all() {
  reset_all_signal_handlers();
  reset_aig();

  reset_time = process_time();
}
/*------------------------------------------------------------------------*/
/**
    Main Function of MultAIGenFuzzer.
    Generates a fuzzed - correct! - multiplier circuit whose components are
    completely mixed from smaller pieces.

    Prints statistics to stdout after finishing.
*/
int main(int argc, char ** argv) {
  int size = 0;
  bool reencode = 0;
  bool use_cl = 1;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-h") ||
    !strcmp(argv[i], "--help")) {
      fputs(USAGE, stdout);
      fflush(stdout);
      exit(0);
    } else if (!strcmp(argv[i], "-v0")) { verbose = 0;
    } else if (!strcmp(argv[i], "-v1")) { verbose = 1;
    } else if (!strcmp(argv[i], "-v2")) { verbose = 2;
    } else if (!strcmp(argv[i], "-v3")) { verbose = 3;
    } else if (!strcmp(argv[i], "-r"))  { reencode = 1;
    } else if (!strcmp(argv[i], "-cl"))  { use_cl = 0;
    } else if (!strcmp(argv[i], "-i")) {
      if(i == argc-1) die(invalid_argument, "no value for option '-i' given");

      if(!isNumber(argv[++i])) die(invalid_argument, "argument '%s' invalid, \n         "
        "option '-i' needs to be followed by a positive number", argv[i]);
      else size = std::stoi(argv[i], nullptr);

    } else if (!strcmp(argv[i], "-s")) {
      if(i == argc-1) die(invalid_argument, "no value for option '-s' given");

      if(!isNumber(argv[++i])) die(invalid_argument, "argument '%s' invalid, \n                  "
        "option '-s' needs to be followed by a nonnegative integer", argv[i]);
      else seed = std::stoi(argv[i], nullptr);

    } else if (output_name) {
      die(invalid_argument, "too many arguments '%s' and '%s'(try '-h')",
        output_name, argv[i]);
    } else {
      output_name = argv[i];
    }
  }


  if (!output_name)  die(invalid_argument, "no output file given(try '-h')");



  init_all(size, use_cl);
  generate_fuzzed_mult(size, use_cl);

  write_fuzzed_model(output_name, reencode);


  reset_all();


  print_statistics();

  return 0;
}
