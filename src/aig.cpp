/*------------------------------------------------------------------------*/
/*! \file aig.cpp
    \brief contains functions necessary to parse the AIG

  Part of MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
  Copyright(C) 2022 Daniela Kaufmann, Johannes Kepler University Linz
*/
/*------------------------------------------------------------------------*/
#include "aig.h"
/*------------------------------------------------------------------------*/
// Global Variables
unsigned idx;

/*------------------------------------------------------------------------*/
// Local Variables

aiger * model;   // /< aiger* object, used for storing the generated AIG graph

static unsigned writing_error = 21;



/*------------------------------------------------------------------------*/
void init_aig(int size) {
  assert(!model);
  model = aiger_init();
  assert(model);

  insert_inputs(size);

}
/*------------------------------------------------------------------------*/
void reset_aig() {
  assert(model);
  aiger_reset(model);
}
/*------------------------------------------------------------------------*/
void insert_inputs(int size){

  for (int i = 1; i <= size; i++) {
    std::string s = "a" + std::to_string(i-1);
    aiger_add_input (model, 2*i, s.c_str() );
    msg(3,"    Input %i %s", 2*i, s.c_str());
  }


  for (int i = size+1; i <= 2*size; i++) {
    std::string s = "b" + std::to_string(i-size-1);
    aiger_add_input (model, 2*i, s.c_str());
    msg(3,"    Input %i %s", 2*i, s.c_str());
  }

  idx = 2*size;
  msg(2,"  Inserted %i inputs", 2*size);
}


/*=========================================================================*/

void write_fuzzed_model(const char * output_name, bool reencode) {
  if(reencode) {
    aiger_reencode(model);
    msg(2,"  Reencoded AIG");
  }

  FILE * output_file;
  if (!(output_file = fopen(output_name, "w")))
      die(writing_error, "can not write output to '%s'", output_name);

  if (!aiger_write_to_file(model, aiger_binary_mode, output_file))
        die(writing_error, "failed to write rewritten aig to '%s'", output_name);

  msg(1,"Output");
  msg(1,"==========================================================");
  msg(1,"  Printed fuzzed AIG to: '%s'", output_name);
  msg(1,"");

  fclose(output_file);

}
/*------------------------------------------------------------------------*/
