/*
Øving 8
I oppgave 1 antar jeg at meldingen er krytpert med k-skift, og prøver å brute-force den.
Jeg finner den dekrypterte meldingen med en offset på 35.

I oppgave 2 så genererer jeg en nøkkel med pass phrase: "Dette er en nøkkel",
og bruker den til å dekryptere med RSA.

Oppgave 3: se /openssl-example/tests/crypto_test.cpp
*/

#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "crypto.hpp"

using namespace std;

int main() {
  string simple_decrypted_message = "judwxohuhuCghuhCkduCixqqhwCphoglqjhqD";
  cout << opg1(simple_decrypted_message); //Dekodet melding: GRATULERER DERE HAR FUNNET MELDINGEN!
  
  string decrypted_message = "114b70745a521c57371f7a245d6440662d49";
  string opg_2_key = "Dette er en noekkel";
  vector<unsigned int> byte_value = HexToBytes(decrypted_message);
  vector<unsigned char> generated_key = generate_key(opg_2_key);
  
  vector<unsigned char> original_message;
  original_message = opg2(byte_value, generated_key);
  cout<<string(original_message.begin(),original_message.end())<<endl;
  
  return 0;
}


