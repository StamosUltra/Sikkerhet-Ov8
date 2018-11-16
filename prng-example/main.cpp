#include <iostream>
#include <random>
#include <sstream>
#include <string>

int main() {
  std::string key = "Dette er en noekkel";

  //Create seed from key
  std::seed_seq seed(key.begin(), key.end());

  //Choice of pseudorandom number generator using the given seed
  std::minstd_rand0 generator(seed);

  //Choice of distribution with 1 byte values
  std::uniform_int_distribution<char> distribution;

  //Retrieve random numbers from the generator using the chosen distribution:
  for (size_t c = 0; c < 5; ++c)
    std::cout << (int)distribution(generator) << std::endl;
}
