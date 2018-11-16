#pragma once
#include <vector>
#include <random>
#include <iomanip>
#include <iostream>
// #include <openssl/buffer.h>
// #include <openssl/evp.h>
// #include <openssl/pem.h>
// #include <openssl/rsa.h>
// #include <openssl/sha.h>
#include <sstream>
#include <string>


std::string simple_decrypt(int offset, std::string &input) {
  std::string output;
  output.reserve(input.size());
  for(char &i : input) {
    output.push_back((char)(i-offset));
  }
  return output;
}

std::string opg1(std::string &input) {
  std::string output;
  for (int i = 0; i < 42; i++) {
    output += simple_decrypt(i, input);
    output += " Offset: ";
    output += std::to_string(i);
    output += "\n";
  }
  return output;
}

std::vector<unsigned int> HexToBytes(const std::string& input){
	std::vector<unsigned int> bytes;
	std::stringstream ss;
	
	for (unsigned int i = 0; i < input.length(); i += 2){
		std::string byteString = input.substr(i, 2);
		bytes.push_back(std::stoul(byteString.c_str(),nullptr,16));
	}
	
	return bytes;
}

std::vector<unsigned char> generate_key(const std::string &key) {
  //Finds the number of characters in the decrypted message.
  size_t length = key.length();
  
  //Create seed from key
  std::seed_seq seed(key.begin(), key.end());
  
  //Choice of pseudorandom number generator using the given seed
  std::minstd_rand0 generator(seed);
  
  //Choice of distribution with 1 byte values
  std::uniform_int_distribution<char> distribution;
  
  std::vector<unsigned char> output;
  
  //Retrieve random numbers from the generator using the chosen distribution:
  for (size_t c = 0; c < length; ++c){
    output.push_back((int)distribution(generator));
  }
  return output;
}

std::vector<unsigned char> opg2 (const std::vector<unsigned int> &cipher, const std::vector<unsigned char> &key) {
  unsigned char c;
  std::vector<unsigned char> de_crypted;
  for (size_t i=0; i<cipher.size(); i++) {
    c = (cipher[i])^(key[i%key.size()]);
    de_crypted.emplace_back(c);
  }
  return de_crypted;
}