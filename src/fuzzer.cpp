/*------------------------------------------------------------------------*/
/*! \file fuzzer.cpp
    \brief contains functions necessary to parse the AIG

  Part of MultAIGenFuzzer: Generation-Based AIG Fuzzer for Multipliers
  Copyright(C) 2022 Daniela Kaufmann, Johannes Kepler University Linz
*/
/*------------------------------------------------------------------------*/
#include "fuzzer.h"
/*------------------------------------------------------------------------*/
static std::vector<std::vector<unsigned>> slices;
static unsigned error_fsa_empty = 31;
static unsigned error_fsa_size = 32;
/*------------------------------------------------------------------------*/
static void print_slices(){
  int i = 0;
  for(auto it = slices.begin(); it != slices.end(); ++it){
    auto l = *it;
    msg(2,"slice %i", i);
    for(auto iit = l.begin(); iit != l.end(); ++iit){
      msg(2,"%i", *iit);

    }
    i++;
  }
}

/*------------------------------------------------------------------------*/
int rangeRandomZeroMax (int max){
    if(!max) return 0;
    int n = max;
    int remainder = RAND_MAX % n;
    int x;
    do{
        x = rand();
    }while (x >= RAND_MAX - remainder);
    return x % n;
}

/*------------------------------------------------------------------------*/
static void fuzz_pp(unsigned size){
  idx++;
  for(unsigned s = 0; s < size; s++){
    std::vector<unsigned> sl;
    for(unsigned i = 0; i <= s; i++){
      int j = s - i;
      aiger_add_and(model, 2*idx, 2*(i+1), 2*(j+1+size));

      sl.push_back(2*idx);
      idx++;
    }
    slices.push_back(sl);
  }

  for(unsigned s = 0; s < size; s++){
    std::vector<unsigned> sl;
    for(unsigned i = s+1; i < size; i++){
      int j = size + s - i;
      aiger_add_and(model, 2*idx, 2*(i+1), 2*(j+1+size));
      sl.push_back(2*idx);
      idx++;
    }
    slices.push_back(sl);
  }
}

/*------------------------------------------------------------------------*/
static void generate_a_ha
  (unsigned a, unsigned b, int sel_sl, int size){

  unsigned g1 = 2*idx + 2;
  unsigned g2 = 2*idx + 4;
  unsigned g3 = 2*idx + 6;
  unsigned g4 = 2*idx + 8;


  aiger_add_and(model, g1, a^1,  b);
  aiger_add_and(model, g2, a,    b^1);
  aiger_add_and(model, g3, g1^1, g2^1); //sum
  slices[sel_sl].push_back(g3^1);


  if(sel_sl < 2*size-1) {
    aiger_add_and(model, g4, a,  b);
    msg(3,"      slice %i A-HA %i %i %i %i ", sel_sl, g4^1, g3^1, a,b);
    slices[sel_sl+1].push_back(g4);
    idx = idx + 4;
  } else {
    msg(3,"      slice %i MS-A-HA %i %i %i", sel_sl, g3^1, a,b);
    idx = idx + 3;
  }
}
/*------------------------------------------------------------------------*/
static void generate_b_ha
  (unsigned a, unsigned b, int sel_sl, int size){

  unsigned one   = 2*idx + 2;
  unsigned two   = 2*idx + 4;
  unsigned three = 2*idx + 6;


  aiger_add_and(model, one,   a^1,    b^1);
  aiger_add_and(model, two,   a,      b);     //carry
  aiger_add_and(model, three, one^1,  two^1); //sum
  slices[sel_sl].push_back(three);


  if(sel_sl < 2*size-1) {
    msg(3,"      slice %i B-HA %i %i %i %i ", sel_sl, two, three, a,b);
    slices[sel_sl+1].push_back(two);
    idx = idx + 3;
  } else {
    msg(3,"      slice %i MS-B-HA %i %i %i", sel_sl, three, a,b);
    idx = idx + 3;
  }
}



/*------------------------------------------------------------------------*/
static void generate_ha
  (unsigned a, unsigned b, int sel_sl, int size){

  if(rangeRandomZeroMax(2)) generate_a_ha(a,b, sel_sl, size);
  else generate_b_ha(a, b, sel_sl, size);
}
/*------------------------------------------------------------------------*/
static void generate_a_fa
  (unsigned a, unsigned b, unsigned c, int sel_sl, int size){

  unsigned g1  = 2*idx + 2;
  unsigned g2  = 2*idx + 4;
  unsigned g3  = 2*idx + 6;
  unsigned g4  = 2*idx + 8;
  unsigned g5  = 2*idx + 10;
  unsigned g6  = 2*idx + 12;
  unsigned g7  = 2*idx + 14;
  unsigned g8  = 2*idx + 16;
  unsigned g9  = 2*idx + 18;
  unsigned g10 = 2*idx + 20;
  unsigned g11 = 2*idx + 22;

  aiger_add_and(model, g1, a,     b^1);
  aiger_add_and(model, g2, b,     a^1);
  aiger_add_and(model, g3, g1^1,  g2^1);
  aiger_add_and(model, g4, g3^1,  c^1);
  aiger_add_and(model, g5, g3,    c);
  aiger_add_and(model, g6, g4^1,  g5^1); // sum

  slices[sel_sl].push_back(g6^1);

  if(sel_sl < 2*size-1) {
    aiger_add_and(model, g7, a,     b);
    aiger_add_and(model, g8, a,     c);
    aiger_add_and(model, g9, b,     c);
    aiger_add_and(model, g10, g7^1, g8^1);
    aiger_add_and(model, g11, g10,  g9^1);  //carry
    msg(3,"      slice %i A-FA %i %i %i %i %i", sel_sl, g11^1, g6^1, a,b,c);
    slices[sel_sl+1].push_back(g11^1);
    idx = idx + 11;
  } else {
    msg(3,"      slice %i MS-A-FA %i %i %i %i", sel_sl, g6^1, a,b,c);
    idx = idx + 6;
  }
}
/*------------------------------------------------------------------------*/

static void generate_b_fa
  (unsigned a, unsigned b, unsigned c, int sel_sl, int size){

  unsigned one   = 2*idx + 2;
  unsigned two   = 2*idx + 4;
  unsigned three = 2*idx + 6;
  unsigned four  = 2*idx + 8;
  unsigned five  = 2*idx + 10;
  unsigned six   = 2*idx + 12;
  unsigned seven = 2*idx + 14;

  aiger_add_and(model, one,   a^1,    b^1);
  aiger_add_and(model, two,   a,      b);
  aiger_add_and(model, three, one^1,  two^1);
  aiger_add_and(model, four,  c^1,    three^1);
  aiger_add_and(model, five,  c,      three);
  aiger_add_and(model, six,   four^1, five^1);  //sum
  slices[sel_sl].push_back(six);


  if(sel_sl < 2*size-1) {
    aiger_add_and(model, seven, two^1,    five^1);  //carry
    msg(3,"      slice %i B-FA %i %i %i %i %i", sel_sl, seven^1, six, a,b,c);
    slices[sel_sl+1].push_back(seven^1);
    idx = idx + 7;
  } else {
    msg(3,"      slice %i MS-B-FA %i %i %i %i", sel_sl, six, a,b,c);
    idx = idx + 6;
  }
}



/*------------------------------------------------------------------------*/
static void generate_fa
  (unsigned a, unsigned b, unsigned c, int sel_sl, int size){

  if(rangeRandomZeroMax(2)) generate_a_fa(a,b,c, sel_sl, size);
  else generate_b_fa(a, b, c, sel_sl, size);
}

/*------------------------------------------------------------------------*/
static unsigned gen_xor (unsigned a, unsigned b){
  unsigned g1 = 2*idx + 2;
  unsigned g2 = 2*idx + 4;
  unsigned g3 = 2*idx + 6;

  aiger_add_and(model, g1, a^1,    b);
  aiger_add_and(model, g2, a,      b^1);
  aiger_add_and(model, g3, g1^1,   g2^1);
  idx = idx +3;

  return g3^1;
}

/*------------------------------------------------------------------------*/
static unsigned gen_and (unsigned a, unsigned b){
  unsigned g1 = 2*idx + 2;
  aiger_add_and(model, g1, a,    b);
  idx = idx +1;
  return g1;

}

/*------------------------------------------------------------------------*/
static unsigned gen_or (unsigned a, unsigned b){
  unsigned g1 = 2*idx + 2;
  aiger_add_and(model, g1, a^1,    b^1);
  idx = idx +1;
  return g1^1;
}
/*------------------------------------------------------------------------*/
static unsigned gen_cla_recursive_carry(unsigned c, unsigned p, unsigned g){
  unsigned g1 = 2*idx + 2;
  unsigned g2 = 2*idx + 4;
  aiger_add_and(model, g1, c, p);
  aiger_add_and(model, g2, g1^1, g^1);
  idx = idx +2;
  return g2^1;
}
/*------------------------------------------------------------------------*/
static unsigned gen_cla_iterative_carry(
  int max, unsigned c, std::vector<unsigned> p, std::vector<unsigned> g){

  unsigned carry = g[max];

  for (int j = 0; j <= max; j++){
    unsigned p_sum = p[max];

    for (int i = max-1; i >= j; i--){
      p_sum = gen_and (p_sum, p[i]);
    }

    if (!j) p_sum = gen_and (p_sum, c);
    else    p_sum = gen_and (p_sum, g[j-1]);

    carry = gen_or (carry, p_sum);
  }

  return carry;

}
/*------------------------------------------------------------------------*/

static int generate_cla (int id, int size){
  msg(3, "    slice %i start CLA", id);
  int count = 0;
  for (int i = id; i < 2*size-1; i++){
    if(slices[i].size() >= 2) count++;
    else break;
  }

  int cla_size = rangeRandomZeroMax(count)+1;
  msg(3, "      fuzzed CLA size %i", cla_size);

  std::vector<unsigned> prop;
  std::vector<unsigned> gen;

  int carry_idx = rangeRandomZeroMax(3);
  unsigned carry = slices[id][carry_idx];
  slices[id].erase(slices[id].begin() + carry_idx);


  for (int i = 0; i < cla_size; i++){
    prop.push_back(gen_xor(slices[id+i][0], slices[id+i][1]));
    gen.push_back(gen_and(slices[id+i][0], slices[id+i][1]));
  }


  int iterative_recursive_mixed = rangeRandomZeroMax(3);
  if(!iterative_recursive_mixed) msg(3, "      mixed carry generation");
  else if(iterative_recursive_mixed == 1) msg(3, "      iterative carry generation");
  else if(iterative_recursive_mixed == 2) msg(3, "      recursive carry generation");

  msg(3, "      init carry %i", carry);

  for (int i = 0; i < cla_size; i++){
    unsigned out = gen_xor(carry, prop[i]);

    if (iterative_recursive_mixed == 0){   // Mixed: each carry is random
      if(!rangeRandomZeroMax(2)){
        carry = gen_cla_iterative_carry(i, carry, prop, gen);
        msg(3,"      slice %i iterative CLA %i %i", id+i, carry, out);
      } else {
        carry = gen_cla_recursive_carry(carry, prop[i], gen[i]);
        msg(3,"      slice %i recursive CLA %i %i", id+i, carry, out);
      }
    } else if (iterative_recursive_mixed == 1) { // All iterative
      carry = gen_cla_iterative_carry(i, carry, prop, gen);
      msg(3,"      slice %i CLA %i %i", id+i, carry, out);
    } else if (iterative_recursive_mixed == 2) {  // All recursive
      carry = gen_cla_recursive_carry(carry, prop[i], gen[i]);
      msg(3,"      slice %i CLA %i %i", id+i, carry, out);
    } else die(3, "error %i", iterative_recursive_mixed);

    std::string s = "o" + std::to_string(id+i);
    aiger_add_output(model, out, s.c_str());
    msg(3,"    Output %i %s", out, s.c_str());

  }


  slices[id+cla_size].push_back(carry);

  return cla_size;

}
/*------------------------------------------------------------------------*/
static void fuzz_ppa(int size){

  msg(2,"  Fuzzing partial product accumulation");
  std::vector<unsigned> sl;
  for (int i = 0; i < 2*size; i++){
    if(slices[i].size() >= 3) sl.push_back(i);
  }

  while(!sl.empty()){
    int rand_sl = rangeRandomZeroMax(sl.size());
    int sel_sl = sl[rand_sl];
    int rand_sl_size = slices[sel_sl].size();


    int a_idx = rangeRandomZeroMax(rand_sl_size);
    unsigned a = slices[sel_sl][a_idx];
    slices[sel_sl].erase(slices[sel_sl].begin() + a_idx);

    int b_idx = rangeRandomZeroMax(--rand_sl_size);
    unsigned b = slices[sel_sl][b_idx];
    slices[sel_sl].erase(slices[sel_sl].begin() + b_idx);

    if(!rangeRandomZeroMax(3)) generate_ha(a,b,sel_sl, size);
    else {
      int c_idx = rangeRandomZeroMax(--rand_sl_size);
      unsigned c = slices[sel_sl][c_idx];
      slices[sel_sl].erase(slices[sel_sl].begin() + c_idx);

      generate_fa(a,b,c, sel_sl, size);

    }


    if(slices[sel_sl].size() < 3) sl.erase(sl.begin() + rand_sl);

    if(sel_sl < 2*size-1 && slices[sel_sl+1].size() >= 3) {
      if(std::find(sl.begin(), sl.end(), sel_sl+1) == sl.end() ){
        sl.push_back(sel_sl+1);
      }
    }
  }

}
/*------------------------------------------------------------------------*/
static void fuzz_fsa(int size, bool use_cl){
  msg(2,"  Fuzzing final stage addition");


  for(int i = 0; i < 2*size; i++){
    std::string s = "o" + std::to_string(i);
    size_t si_size = slices[i].size();

    if(si_size == 0){
      die(error_fsa_empty, "Slice %i for FSA fuzzing is empty", i);
    } else if(si_size == 1){
      aiger_add_output(model, slices[i][0], s.c_str());
      msg(3,"    Output %i %s", slices[i][0], s.c_str());

    } else if (si_size == 2){
      generate_ha(slices[i][0], slices[i][1], i, size);
      aiger_add_output(model, slices[i][2], s.c_str());
      msg(3,"    Output %i %s", slices[i][2], s.c_str());

    } else if (si_size == 3 && use_cl && i < 2*size-1){
      int r = rangeRandomZeroMax(3);
      int cla = 0;
      if(r) { // give a ratio of 2:1 for cla
        cla = generate_cla(i, size);
      }

      if(r && cla) {i += cla-1;    //increase slices if CLA is success
      } else {
        generate_fa(slices[i][0], slices[i][1], slices[i][2], i, size);
        aiger_add_output(model, slices[i][3], s.c_str());
        msg(3,"    Output %i %s", slices[i][3], s.c_str());
      }
    } else if (si_size == 3){

      generate_fa(slices[i][0], slices[i][1], slices[i][2], i, size);
      aiger_add_output(model, slices[i][3], s.c_str());
      msg(3,"    Output %i %s", slices[i][3], s.c_str());

    } else die(error_fsa_size, "Slice %i is too large for FSA fuzzing", i);
  }
}

/*------------------------------------------------------------------------*/

void generate_fuzzed_mult(int size, bool use_cl){
  fuzz_pp(size);
  fuzz_ppa(size);
  fuzz_fsa(size, use_cl);
}
