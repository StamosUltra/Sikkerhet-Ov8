#include <iomanip>
#include <iostream>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <vector>
#include <ios>

// Note: C-style casts, for instance (int), are used to simplify the source code.
//       C++ casts, such as static_cast and reinterpret_cast, should otherwise
//       be used in modern C++.

/// Limited C++ bindings for the OpenSSL Crypto functions.
class Crypto {
public:
  /// Return hex string from bytes in input string.
  static std::string hex(const std::string &input) {
    std::stringstream hex_stream;
    hex_stream << std::hex << std::internal << std::setfill('0');
    for (auto &byte : input)
      hex_stream << std::setw(2) << (int)(unsigned char)byte;
    return hex_stream.str();
  }
  
  static int char2int(char input) {
    if(input >= '0' && input <= '9')
      return input - '0';
    if(input >= 'A' && input <= 'F')
      return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
      return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
  }
  
  // This function assumes src to be a zero terminated sanitized string with
  // an even number of [0-9a-f] characters, and target to be sufficiently large
  static void hex2bin(const char* src, char* target) {
    while(*src && src[1])
    {
      *(target++) = char2int(*src)*16 + char2int(src[1]);
      src += 2;
    }
  }
  
  static std::string StringHexToBytes(const std::string &input_) {
    std::vector<char> bytes;
    for (size_t i = 0; i < input_.length(); i += 2) {
      std::string nextByte = input_.substr(i, 2);
      char byte = std::stoul(nextByte.c_str(), NULL, 16);
      bytes.push_back(byte);
    }
    return std::string(bytes.begin(), bytes.end());
  }
  
  /// Return the MD5 (128-bit) hash from input.
  static std::string md5(const std::string & /*input*/) {
    throw std::logic_error("not yet implemented");
  }

  /// Return the SHA-1 (160-bit) hash from input.
  static std::string sha1(const std::string &input) {
    std::string hash;
    hash.resize(160 / 8);
    SHA1((const unsigned char *)input.data(), input.size(), (unsigned char *)hash.data());
    return hash;
  }

  /// Return the SHA-256 (256-bit) hash from input.
  static std::string sha256(const std::string & /*input*/) {
    throw std::logic_error("not yet implemented");
  }

  /// Return the SHA-512 (512-bit) hash from input.
  static std::string sha512(const std::string & /*input*/) {
    throw std::logic_error("not yet implemented");
  }

  /// Return key from the Password-Based Key Derivation Function 2 (PBKDF2).
  static std::string pbkdf2(const std::string &password, const std::string &salt, int iterations = 4096, int key_length_in_bits = 256) {
    auto key_length_in_bytes = key_length_in_bits / 8;
    std::string key;
    key.resize(key_length_in_bytes);
    auto success = PKCS5_PBKDF2_HMAC_SHA1(password.data(), password.size(),
                                          (const unsigned char *)salt.data(), salt.size(), iterations,
                                          key_length_in_bytes, (unsigned char *)key.data());
    if (!success)
      throw std::runtime_error("openssl: error calling PBKCS5_PBKDF2_HMAC_SHA1");
    return key;
  }

  class RSA {
  public:
    /// Returns public/private key pair in the PEM format
    static std::pair<std::string, std::string> generate_keys(int modulus_size_in_bits = 2048, unsigned long public_exponent = 65537) {
      std::pair<std::string, std::string> keys;

      auto big_num = BN_new();
      auto success = BN_set_word(big_num, public_exponent);
      if (!success) {
        BN_free(big_num);
        throw std::runtime_error("openssl: error calling BN_set_word");
      }

      auto *rsa = RSA_new();
      success = RSA_generate_key_ex(rsa, modulus_size_in_bits, big_num, nullptr);
      if (!success) {
        RSA_free(rsa);
        BN_free(big_num);
        throw std::runtime_error("openssl: error calling RSA_generate_key_ex");
      }

      auto bio = BIO_new(BIO_s_mem());
      auto buf_mem = BUF_MEM_new();
      BIO_set_mem_buf(bio, buf_mem, BIO_CLOSE);
      success = PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
      keys.second.append(buf_mem->data, buf_mem->length);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        BN_free(big_num);
        throw std::runtime_error("openssl: error calling PEM_write_bio_RSAPrivateKey");
      }

      bio = BIO_new(BIO_s_mem());
      buf_mem = BUF_MEM_new();
      BIO_set_mem_buf(bio, buf_mem, BIO_CLOSE);
      success = PEM_write_bio_RSAPublicKey(bio, rsa);
      keys.first.append(buf_mem->data, buf_mem->length);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        BN_free(big_num);
        throw std::runtime_error("openssl: error calling PEM_write_bio_RSAPublicKey");
      }

      RSA_free(rsa);
      BN_free(big_num);

      return keys;
    }

    /// public_key must be in the PEM format
    static std::string encrypt_public(const std::string &input, const std::string &public_key) {
      std::string result;

      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
      auto success = PEM_read_bio_RSAPublicKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPublicKey");
      }
      result.resize(RSA_size(rsa));
      auto length = RSA_public_encrypt(input.size(), (const unsigned char *)input.data(), (unsigned char *)result.data(), rsa, RSA_PKCS1_PADDING);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_public_encrypt");
      result.resize(length);

      return result;
    }
    /*
    static std::string sign_encrypted_message(const std::string &input, const std::string &private_key, int &type) {
      std::string result;
      
      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
      auto success = PEM_read_bio_RSAPublicKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPublicKey");
      }
      result.resize(RSA_size(rsa));
      auto length = RSA_sign(type, (const unsigned char *)input.data(), (unsigned int)input.length(), (unsigned char *)result.data(), (unsigned int *)result.length(), rsa);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_sign");
      result.resize(length);
      
      return result;
    }
    */
    /*
    static int verify_signature(const std::string original, const std::string &signature, const std::string &public_key, int &type) {
      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
      auto success = PEM_read_bio_RSAPublicKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPublicKey");
      }
      auto length = RSA_verify(type, (const unsigned char *)original.data(), (unsigned int)original.size(), (const unsigned char *)signature.data(), (unsigned int)signature.size(), rsa);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_verify");
      return length;
    }
    */

    /// private_key must be in the PEM format
    static std::string encrypt_private(const std::string &input, const std::string &private_key) {
      std::string result;

      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
      auto success = PEM_read_bio_RSAPrivateKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPrivateKey");
      }
      result.resize(RSA_size(rsa));
      auto length = RSA_private_encrypt(input.size(), (const unsigned char *)input.data(), (unsigned char *)result.data(), rsa, RSA_PKCS1_PADDING);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_private_encrypt");
      result.resize(length);

      return result;
    }

    /// public_key must be in the PEM format
    static std::string decrypt_public(const std::string &input, const std::string &public_key) {
      std::string result;

      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
      auto success = PEM_read_bio_RSAPublicKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPublicKey");
      }
      result.resize(RSA_size(rsa));
      auto length = RSA_public_decrypt(input.size(), (const unsigned char *)input.data(), (unsigned char *)result.data(), rsa, RSA_PKCS1_PADDING);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_public_decrypt");
      result.resize(length);

      return result;
    }

    /// private_key must be in the PEM format
    static std::string decrypt_private(const std::string &input, const std::string &private_key) {
      std::string result;

      auto *rsa = RSA_new();
      auto bio = BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size()));
      auto success = PEM_read_bio_RSAPrivateKey(bio, &rsa, nullptr, nullptr);
      BIO_free_all(bio);
      if (!success) {
        RSA_free(rsa);
        throw std::runtime_error("openssl: error calling PEM_read_bio_RSAPrivateKey");
      }
      result.resize(RSA_size(rsa));
      auto length = RSA_private_decrypt(input.size(), (const unsigned char *)input.data(), (unsigned char *)result.data(), rsa, RSA_PKCS1_PADDING);
      RSA_free(rsa);
      if (length < 0)
        throw std::runtime_error("openssl: error calling RSA_private_decrypt");
      result.resize(length);

      return result;
    }
  };
};
