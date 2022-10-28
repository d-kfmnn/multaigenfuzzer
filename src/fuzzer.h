/*------------------------------------------------------------------------*/
/*! \file fuzzer.h
    \brief contains functions necessary to parse the AIG

  Part of MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
  Copyright(C) 2022 Daniela Kaufmann, Johannes Kepler University Linz
*/
/*------------------------------------------------------------------------*/
#ifndef AIGENFUZZER_SRC_FUZZER_H_
#define AIGENFUZZER_SRC_FUZZER_H_
/*------------------------------------------------------------------------*/
#include "aig.h"
#include <algorithm>
#include <list>
#include <vector>

// currently only SPP support


void generate_fuzzed_mult(int size, bool use_cl);

#endif  // AIGENFUZZER_SRC_FUZZER_H_
