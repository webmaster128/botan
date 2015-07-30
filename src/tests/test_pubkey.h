/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_PUBKEY_H__
#define BOTAN_TEST_PUBKEY_H__

#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/filters.h>

#include "test_rng.h"

using namespace Botan;

inline void dump_data(const std::vector<byte>& out,
               const std::vector<byte>& expected)
   {
   Pipe pipe(new Hex_Encoder);

   pipe.process_msg(out);
   pipe.process_msg(expected);
   std::cout << "Got: " << pipe.read_all_as_string(0) << std::endl;
   std::cout << "Exp: " << pipe.read_all_as_string(1) << std::endl;
   }

inline byte nonzero_byte(RandomNumberGenerator& rng)
   {
   byte b = 0;
   while(b == 0)
      b = rng.next_byte();
   return b;
   }

#define PK_TEST(expr, msg)                                \
   do {                                                \
      const bool test_result = expr;                           \
      if(!test_result)                                           \
         {                                             \
         std::cout << "Test " << #expr << " failed: " << msg << std::endl; \
         ++fails;                                      \
         }                                             \
   } while(0)

inline size_t validate_encryption(PK_Encryptor& e, PK_Decryptor& d,
                           const std::string& algo, const std::string& input,
                           const std::string& random, const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   Fixed_Output_RNG kat_rng(hex_decode(random));

   size_t fails = 0;

   const std::vector<byte> ctext = e.encrypt(message, kat_rng);
   if(ctext != expected)
      {
      std::cout << "FAILED (encrypt): " << algo << std::endl;
      dump_data(ctext, expected);
      ++fails;
      }

   std::vector<byte> decrypted = unlock(d.decrypt(ctext));

   if(decrypted != message)
      {
      std::cout << "FAILED (decrypt): " << algo << std::endl;
      dump_data(decrypted, message);
      ++fails;
      }

   if(algo.find("/Raw") == std::string::npos)
      {
      auto& rng = test_rng();

      for(size_t i = 0; i != ctext.size(); ++i)
         {
         std::vector<byte> bad_ctext = ctext;

         bad_ctext[i] ^= nonzero_byte(rng);

         BOTAN_ASSERT(bad_ctext != ctext, "Made them different");

         try
            {
            auto bad_ptext = unlock(d.decrypt(bad_ctext));
            std::cout << algo << " failed - decrypted bad data" << std::endl;
            std::cout << hex_encode(bad_ctext) << " -> " << hex_encode(bad_ptext) << std::endl;
            std::cout << hex_encode(ctext) << " -> " << hex_encode(decrypted) << std::endl;

            // Ignore PKCS #1 failures as they do occur occasionally (million message attack)
            const bool is_pkcs1 = algo.find("/EME-PKCS1-v1_5") != std::string::npos;

            if(is_pkcs1)
               std::cout << "Ignoring PKCS #1 failure" << std::endl;
            else
               ++fails;
            }
         catch(...) {}
         }
      }

   return fails;
   }

inline size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                                const std::string& algo,
                                const std::string& input,
                                RandomNumberGenerator& signer_rng,
                                RandomNumberGenerator& test_rng,
                                const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   std::vector<byte> sig = s.sign_message(message, signer_rng);

   size_t fails = 0;

   if(sig != expected)
      {
      std::cout << "FAILED (sign): " << algo << std::endl;
      dump_data(sig, expected);
      ++fails;
      }

   PK_TEST(v.verify_message(message, sig), "Correct signature is valid");

   zero_mem(sig.data(), sig.size());

   PK_TEST(!v.verify_message(message, sig), "All-zero signature is invalid");

   for(size_t i = 0; i != 3; ++i)
      {
      auto bad_sig = sig;

      const size_t idx = (test_rng.next_byte() * 256 + test_rng.next_byte()) % sig.size();
      bad_sig[idx] ^= nonzero_byte(test_rng);

      PK_TEST(!v.verify_message(message, bad_sig), "Incorrect signature is invalid");
      }

   return fails;
   }

inline size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                                 const std::string& algo,
                                 const std::string& input,
                                 RandomNumberGenerator& rng,
                                 const std::string& exp)
   {
   return validate_signature(v, s, algo, input, rng, rng, exp);
   }

inline size_t validate_signature(PK_Verifier& v, PK_Signer& s,
                                 const std::string& algo,
                                 const std::string& input,
                                 RandomNumberGenerator& rng,
                                 const std::string& random,
                                 const std::string& exp)
   {
   Fixed_Output_RNG fixed_rng(hex_decode(random));

   return validate_signature(v, s, algo, input, fixed_rng, rng, exp);
   }

inline size_t validate_kas(PK_Key_Agreement& kas,
                    const std::string& algo,
                    const std::vector<byte>& pubkey,
                    const std::string& output,
                    size_t keylen)
   {
   std::vector<byte> expected = hex_decode(output);
   std::vector<byte> got = unlock(kas.derive_key(keylen, pubkey).bits_of());

   size_t fails = 0;

   if(got != expected)
      {
      std::cout << "FAILED: " << algo << std::endl;
      dump_data(got, expected);
      ++fails;
      }

   return fails;
   }

#endif
