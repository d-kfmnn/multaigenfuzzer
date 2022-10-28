/*------------------------------------------------------------------------*/
/*! \file aig.h
    \brief contains functions necessary to parse the AIG

  Part of MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
  Copyright(C) 2022 Daniela Kaufmann, Johannes Kepler University Linz
*/
/*------------------------------------------------------------------------*/
#ifndef AIGENFUZZER_SRC_AIG_H_
#define AIGENFUZZER_SRC_AIG_H_
/*------------------------------------------------------------------------*/
#include <assert.h>

#include "signal_statistics.h"

extern "C" {
  #include "../includes/aiger.h"
}
/*------------------------------------------------------------------------*/

extern unsigned idx; // /< counts idx

extern aiger * model;
/*------------------------------------------------------------------------*/

/**
    Initializes the 'aiger* model', which is local to aig.cpp
*/
void init_aig(int size);

/*------------------------------------------------------------------------*/

/**
    Resets the 'aiger* model', which is local to aig.cpp
*/
void reset_aig();
/*------------------------------------------------------------------------*/

/**
    Inserts 2*size inputs to AIG
*/
void insert_inputs(int size);
/*------------------------------------------------------------------------*/

/**
    Writes the 'aiger* model' to the provided file.

    @param file output file

*/
void write_fuzzed_model(const char * output_name, bool reencode);


#endif  // AIGENFUZZER_SRC_AIG_H_
