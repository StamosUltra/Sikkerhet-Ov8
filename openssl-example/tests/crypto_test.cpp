/*
Oppgave 3:
Jeg først om den signerte meldingen til bytes,
deretter krypterer jeg klarteksten med min offentlige nøkkel.
Deretter hasher jeg meldingen i klartekst, og sammenligner de to og ser at de er like.
Det er ingen grunn til å tro at den har blitt tuklet med

 */

#include "crypto.hpp"
#include <cassert>
#include <iostream>

using namespace std;

int main() {
  assert(Crypto::hex(Crypto::sha1("Test")) == "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa");
  assert(Crypto::hex(Crypto::sha1(Crypto::sha1("Test"))) == "af31c6cbdecd88726d0a9b3798c71ef41f1624d5");
  
  assert(Crypto::hex(Crypto::pbkdf2("Password", "Salt", 4096, 128)) == "f66df50f8aaa11e4d9721e1312ff2e66");
  assert(Crypto::hex(Crypto::pbkdf2("Password", "Salt", 8192, 512)) == "a941ccbc34d1ee8ebbd1d34824a419c3dc4eac9cbc7c36ae6c7ca8725e2b618a6ad22241e787af937b0960cf85aa8ea3a258f243e05d3cc9b08af5dd93be046c");
  
  auto keys = Crypto::RSA::generate_keys();
  auto message = "message";
  auto encrypted = Crypto::RSA::encrypt_public(message, keys.first);
  auto decrypted = Crypto::RSA::decrypt_private(encrypted, keys.second);
  assert(decrypted == message);
  encrypted = Crypto::RSA::encrypt_private(message, keys.second);
  decrypted = Crypto::RSA::decrypt_public(encrypted, keys.first);
  assert(decrypted == message);
  
  message = "important message!";
  string signature_message ="9c3e8d77333fcee3885747250fd48c8a6a5a8e62c24f8ef5f578c752469880409f69fa94a70dae0f71acc7a3988cc81e66881cbc75d5096dedfeeb3d17fb88fd27abe5d32f3b705a11045a91b5b5986f34948009e9b35e8026f986ae871e986392ae37e0458223d62b05fbb50935f63fa920590454d7851d35bf7b3d4cf0752c4683666bcb0398843d141113f32442f8d38f7910a43102da331a6e56fd2a3b3dbe49abf15b4e93c5a81341ed9f87e6bd972536e185e2cde096105db51de519f980901585b2c312b8a097853434bf144a3f14182f2d1b971169280b15061b781a21b8954c626aa4d9417275c1b1812eb0b9770b8320db2f1093f6e775105d39d5";
  string message_bytes = Crypto::StringHexToBytes(signature_message);
  
  string pub_key_messenger = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA639u2haGdEoEQ5wf7lfTHEvDW2FuLBNmZgailV3N9L2JCI9NKtk1\nQOlEW2t6jweRfzjNf7Qs9XZkk6v6hveW2AZAYuhbNxQFT1FOk+Ez2RFVLLNZfIc+\nsXD0VURkORY7m+CFHfT+pf6hlLrvZONEWdJ1ZmxDtMOH6hTESCOooxdJ8m2+WsA5\nGuzOvaagZD/P4Gf9uoVjk/+G4jsB3YyaGAu+hs/Xx/ti9xPwFtCiUloJlUxhsDz9\nmy67QMmPype4vv1w2Hhaj3UabCQi5qj4JgSctNayRy73Wk0iXtos1s2S38CUsUuS\nL7oZWDeIi2pZS0NT7e8cZllAHgSuX8MW+wIDAQAB\n-----END RSA PUBLIC KEY-----";
  
  decrypted = Crypto::RSA::decrypt_public(message_bytes, pub_key_messenger);
  string hash = Crypto::sha1(message);
  cout << "decr: " << decrypted << endl;
  cout << "hash: " << hash << endl;
  assert (decrypted == hash);
    
}
