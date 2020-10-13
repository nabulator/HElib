/* Copyright (C) 2019-2020 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

// This is a sample program for education purposes only.
// It attempts to show the various basic mathematical
// operations that can be performed on both ciphertexts
// and plaintexts.

#include <iostream>
#include <boost/lexical_cast.hpp>
#include <helib/helib.h>
#include <time.h> 

int main(int argc, char* argv[])
{
  /*  Example of BGV scheme  */

  if( argc != 3 && argc != 4 )
  {std::cout << "not enough args: need p and m" << std::endl;
		exit(-1);
  }
  // Plaintext prime modulus
  unsigned long p = boost::lexical_cast<long>(argv[1]);
  // Cyclotomic polynomial - defines phi(m)
  unsigned long m = boost::lexical_cast<long>(argv[2]);
  // Hensel lifting (default = 1)
  unsigned long r = 1;
  // Number of bits of the modulus chain
  unsigned long bits = argc == 3 ? 300 : boost::lexical_cast<long>(argv[3]);
  // Number of columns of Key-Switching matrix (default = 2 or 3)
  unsigned long c = 2;

	clock_t start = clock();
  // Initialize context
  // This object will hold information about the algebra created from the
  // previously set parameters
  helib::Context context(m, p, r);
  std::cout << "Initialising context object..." << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;
  // Modify the context, adding primes to the modulus chain
  // This defines the ciphertext space
  buildModChain(context, bits, c);
	std::cout << "Building modulus chain..." << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;

  // Print the context
  context.zMStar.printout();
  std::cout << std::endl;

  // Print the security level
  std::cout << "Security: " << context.securityLevel() << std::endl;

  //FIXME: really should make this a separate progrm but too lazy for that
  if( argc == 3)
    exit(0);


  // Secret key management
  std::cout << "Creating secret key..." << std::endl;
  // Create a secret key associated with the context
  helib::SecKey secret_key(context);
  // Generate the secret key
  secret_key.GenSecKey();
  // Compute key-switching matrices that we need
  helib::addSome1DMatrices(secret_key);
  std::cout << "Generating key-switching matrices..." << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;

  // Public key management
  // Set the secret key (upcast: SecKey is a subclass of PubKey)
  const helib::PubKey& public_key = secret_key;

  // Get the EncryptedArray of the context
  const helib::EncryptedArray& ea = *(context.ea);

  // Get the number of slot (phi(m))
  long nslots = ea.size();
  std::cout << "Number of slots: " << nslots << std::endl;

  // Create a vector of long with nslots elements
  helib::Ptxt<helib::BGV> ptxt(context);
  // Set it with numbers 0..nslots - 1
  // ptxt = [0] [1] [2] ... [nslots-2] [nslots-1]
  for (int i = 0; i < ptxt.size(); ++i) {
    ptxt[i] = i;
  }

  // Create a ciphertext object
	start = clock();
  helib::Ctxt ctxt(public_key);
  // Encrypt the plaintext using the public_key
  public_key.Encrypt(ctxt, ptxt);
	std::cout << "Done encrypting: " << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;

  // ********** Operations ********** 
  // Ciphertext and plaintext operations are performed
  // "entry-wise".

  // Square the ciphertext
  // [0] [1] [2] [3] [4] ... [nslots-1]
  // -> [0] [1] [4] [9] [16] ... [(nslots-1)*(nslots-1)]
	start = clock();
	ctxt.multiplyBy(ctxt);
  std::cout << "Power: " << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;
 
  // Raise the copy to the exponent 2
  // Note: 0 is a special case because 0^n = 0 for any power n
  //ctxt.power(2);

  // Subtract it from itself (result should be 0)
	start = clock();
  ctxt += ctxt;
	std::cout << "Subtract: " << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;

  // Create a plaintext for decryption
  start = clock();
  helib::Ptxt<helib::BGV> plaintext_result(context);
  // Decrypt the modified ciphertext
  secret_key.Decrypt(plaintext_result, ctxt);
	std::cout << "Decryt: " << (double)(clock()-start)/CLOCKS_PER_SEC << std::endl;

  // Print the decrypted plaintext
  std::cout << "Decrypted Result: " << plaintext_result << std::endl;

  return 0;
}
