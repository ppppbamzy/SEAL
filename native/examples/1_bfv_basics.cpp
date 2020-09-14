// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    /*
    In this example, we demonstrate performing simple computations (a polynomial
    evaluation) on encrypted integers using the BFV encryption scheme.

    The first task is to set up an instance of the EncryptionParameters class.
    It is critical to understand how the different parameters behave, how they
    affect the encryption scheme, performance, and the security level. There are
    three encryption parameters that are necessary to set:

        - poly_modulus_degree (degree of polynomial modulus);
        - coeff_modulus ([ciphertext] coefficient modulus);
        - plain_modulus (plaintext modulus; only for the BFV scheme).

    The BFV scheme cannot perform arbitrary computations on encrypted data.
    Instead, each ciphertext has a specific quantity called the `invariant noise
    budget' -- or `noise budget' for short -- measured in bits. The noise budget
    in a freshly encrypted ciphertext (initial noise budget) is determined by
    the encryption parameters. Homomorphic operations consume the noise budget
    at a rate also determined by the encryption parameters. In BFV the two basic
    operations allowed on encrypted data are additions and multiplications, of
    which additions can generally be thought of as being nearly free in terms of
    noise budget consumption compared to multiplications. Since noise budget
    consumption compounds in sequential multiplications, the most significant
    factor in choosing appropriate encryption parameters is the multiplicative
    depth of the arithmetic circuit that the user wants to evaluate on encrypted
    data. Once the noise budget of a ciphertext reaches zero it becomes too
    corrupted to be decrypted. Thus, it is essential to choose the parameters to
    be large enough to support the desired computation; otherwise the result is
    impossible to make sense of even with the secret key.
    */
    EncryptionParameters parms(scheme_type::BFV);

    /*
    The first parameter we set is the degree of the `polynomial modulus'. This
    must be a positive power of 2, representing the degree of a power-of-two
    cyclotomic polynomial; it is not necessary to understand what this means.

    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    slower, but enables more complicated encrypted computations. Recommended
    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    to go beyond this range.

    In this example we use a relatively small polynomial modulus. Anything
    smaller than this will enable only very restricted encrypted computations.
    */
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    Next we set the [ciphertext] `coefficient modulus' (coeff_modulus). This
    parameter is a large integer, which is a product of distinct prime numbers,
    each up to 60 bits in size. It is represented as a vector of these prime
    numbers, each represented by an instance of the Modulus class. The
    bit-length of coeff_modulus means the sum of the bit-lengths of its prime
    factors.

    A larger coeff_modulus implies a larger noise budget, hence more encrypted
    computation capabilities. However, an upper bound for the total bit-length
    of the coeff_modulus is determined by the poly_modulus_degree, as follows:

        +----------------------------------------------------+
        | poly_modulus_degree | max coeff_modulus bit-length |
        +---------------------+------------------------------+
        | 1024                | 27                           |
        | 2048                | 54                           |
        | 4096                | 109                          |
        | 8192                | 218                          |
        | 16384               | 438                          |
        | 32768               | 881                          |
        +---------------------+------------------------------+

    These numbers can also be found in native/src/seal/util/hestdparms.h encoded
    in the function SEAL_HE_STD_PARMS_128_TC, and can also be obtained from the
    function

        CoeffModulus::MaxBitCount(poly_modulus_degree).

    For example, if poly_modulus_degree is 4096, the coeff_modulus could consist
    of three 36-bit primes (108 bits).

    Microsoft SEAL comes with helper functions for selecting the coeff_modulus.
    For new users the easiest way is to simply use

        CoeffModulus::BFVDefault(poly_modulus_degree),

    which returns std::vector<Modulus> consisting of a generally good choice
    for the given poly_modulus_degree.
    */
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    /*
    The plaintext modulus can be any positive integer, even though here we take
    it to be a power of two. In fact, in many cases one might instead want it
    to be a prime number; we will see this in later examples. The plaintext
    modulus determines the size of the plaintext data type and the consumption
    of noise budget in multiplications. Thus, it is essential to try to keep the
    plaintext data type as small as possible for best performance. The noise
    budget in a freshly encrypted ciphertext is

        ~ log2(coeff_modulus/plain_modulus) (bits)

    and the noise budget consumption in a homomorphic multiplication is of the
    form log2(plain_modulus) + (other terms).

    The plaintext modulus is specific to the BFV scheme, and cannot be set when
    using the CKKS scheme.
    */
    parms.set_plain_modulus(1024);

    /*
    Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set.
    */
    auto context = SEALContext::Create(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    /*
    When parameters are used to create SEALContext, Microsoft SEAL will first
    validate those parameters. The parameters chosen here are valid.
    */
    cout << "Parameter validation (success): " << context->parameter_error_message() << endl;

    cout << endl;
    cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    /*
    The encryption schemes in Microsoft SEAL are public key encryption schemes.
    For users unfamiliar with this terminology, a public key encryption scheme
    has a separate public key for encrypting data, and a separate secret key for
    decrypting data. This way multiple parties can encrypt data using the same
    shared public key, but only the proper recipient of the data can decrypt it
    with the secret key.

    We are now ready to generate the secret and public keys. For this purpose
    we need an instance of the KeyGenerator class. Constructing a KeyGenerator
    automatically generates the public and secret key, which can immediately be
    read to local variables.
    */
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    /*
    To be able to encrypt we need to construct an instance of Encryptor. Note
    that the Encryptor only requires the public key, as expected.
    */
    Encryptor encryptor(context, public_key);

    /*
    Computations on the ciphertexts are performed with the Evaluator class. In
    a real use-case the Evaluator would not be constructed by the same party
    that holds the secret key.
    */
    Evaluator evaluator(context);

    /*
    We will of course want to decrypt our results to verify that everything worked,
    so we need to also construct an instance of Decryptor. Note that the Decryptor
    requires the secret key.
    */
    Decryptor decryptor(context, secret_key);

    /*
    As an example, we evaluate the degree 4 polynomial

        4x^4 + 8x^3 + 8x^2 + 8x + 4

    over an encrypted x = 6. The coefficients of the polynomial can be considered
    as plaintext inputs, as we will see below. The computation is done modulo the
    plain_modulus 1024.

    While this examples is simple and easy to understand, it does not have much
    practical value. In later examples we will demonstrate how to compute more
    efficiently on encrypted integers and real or complex numbers.

    Plaintexts in the BFV scheme are polynomials of degree less than the degree
    of the polynomial modulus, and coefficients integers modulo the plaintext
    modulus. For readers with background in ring theory, the plaintext space is
    the polynomial quotient ring Z_T[X]/(X^N + 1), where N is poly_modulus_degree
    and T is plain_modulus.

    To get started, we create a plaintext containing the constant 6. For the
    plaintext element we use a constructor that takes the desired polynomial as
    a string with coefficients represented as hexadecimal numbers.
    */
    print_line(__LINE__);
    int x = 6;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

    /*
    We then encrypt the plaintext, producing a ciphertext.
    */
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);

    /*
    In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
    whose coefficients are integers modulo the product of the primes in the
    coeff_modulus. The number of polynomials in a ciphertext is called its `size'
    and is given by Ciphertext::size(). A freshly encrypted ciphertext always
    has size 2.
    */
    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

    /*
    There is plenty of noise budget left in this freshly encrypted ciphertext.
    */
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;

    /*
    We decrypt the ciphertext and print the resulting plaintext in order to
    demonstrate correctness of the encryption.
    */
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

    /*
    When using Microsoft SEAL, it is typically advantageous to compute in a way
    that minimizes the longest chain of sequential multiplications. In other
    words, encrypted computations are best evaluated in a way that minimizes
    the multiplicative depth of the computation, because the total noise budget
    consumption is proportional to the multiplicative depth. For example, for
    our example computation it is advantageous to factorize the polynomial as

        4x^4 + 8x^3 + 8x^2 + 8x + 4 = 4(x + 1)^2 * (x^2 + 1)

    to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
    (x^2 + 1) separately, before multiplying them, and multiplying by 4.

    First, we compute x^2 and add a plaintext "1". We can clearly see from the
    print-out that multiplication has consumed a lot of noise budget. The user
    can vary the plain_modulus parameter to see its effect on the rate of noise
    budget consumption.
    */
    print_line(__LINE__);
    cout << "Compute x_sq_plus_one (x^2+1)." << endl;
    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

    /*
    Encrypted multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform a squaring, and observe both size growth and noise budget
    consumption.
    */
    cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
         << endl;

    /*
    Even though the size has grown, decryption works as usual as long as noise
    budget has not reached 0.
    */
    Plaintext decrypted_result;
    cout << "    + decryption of x_sq_plus_one: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    /*
    Next, we compute (x + 1)^2.
    */
    print_line(__LINE__);
    cout << "Compute x_plus_one_sq ((x+1)^2)." << endl;
    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
         << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    /*
    Finally, we multiply (x^2 + 1) * (x + 1)^2 * 4.
    */
    print_line(__LINE__);
    cout << "Compute encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    Ciphertext encrypted_result;
    Plaintext plain_four("4");
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
         << endl;
    cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;

    cout << endl;
    cout << "~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    /*
    Noise budget has reached 0, which means that decryption cannot be expected
    to give the correct result. This is because both ciphertexts x_sq_plus_one
    and x_plus_one_sq consist of 3 polynomials due to the previous squaring
    operations, and homomorphic operations on large ciphertexts consume much more
    noise budget than computations on small ciphertexts. Computing on smaller
    ciphertexts is also computationally significantly cheaper.

    `Relinearization' is an operation that reduces the size of a ciphertext after
    multiplication back to the initial size, 2. Thus, relinearizing one or both
    input ciphertexts before the next multiplication can have a huge positive
    impact on both noise growth and performance, even though relinearization has
    a significant computational cost itself. It is only possible to relinearize
    size 3 ciphertexts down to size 2, so often the user would want to relinearize
    after each multiplication to keep the ciphertext sizes at 2.

    Relinearization requires special `relinearization keys', which can be thought
    of as a kind of public key. Relinearization keys can easily be created with
    the KeyGenerator.

    Relinearization is used similarly in both the BFV and the CKKS schemes, but
    in this example we continue using BFV. We repeat our computation from before,
    but this time relinearize after every multiplication.

    Here we use the function KeyGenerator::relin_keys_local(). In production
    code it is much better to use KeyGenerator::relin_keys() instead. We will
    explain and discuss these differences in `6_serialization.cpp'.
    */
    print_line(__LINE__);
    cout << "Generate locally usable relinearization keys." << endl;
    auto relin_keys = keygen.relin_keys_local();

    /*
    We now repeat the computation relinearizing after each multiplication.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    cout << string(13, ' ') << "then compute x_sq_plus_one (x^2+1)" << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    cout << "    + size of x_squared: " << x_squared.size() << endl;
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "    + size of x_squared (after relinearization): " << x_squared.size() << endl;
    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
         << endl;
    cout << "    + decryption of x_sq_plus_one: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "Compute x_plus_one (x+1)," << endl;
    cout << string(13, ' ') << "then compute and relinearize x_plus_one_sq ((x+1)^2)." << endl;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
    evaluator.square(x_plus_one, x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
         << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    cout << "Compute and relinearize encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "    + size of encrypted_result (after relinearization): " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
         << endl;

    cout << endl;
    cout << "NOTE: Notice the increase in remaining noise budget." << endl;

    /*
    Relinearization clearly improved our noise consumption. We have still plenty
    of noise budget left, so we can expect the correct answer when decrypting.
    */
    print_line(__LINE__);
    cout << "Decrypt encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    decryptor.decrypt(encrypted_result, decrypted_result);
    cout << "    + decryption of 4(x^2+1)(x+1)^2 = 0x" << decrypted_result.to_string() << " ...... Correct." << endl;
    cout << endl;

    /*
    For x=6, 4(x^2+1)(x+1)^2 = 7252. Since the plaintext modulus is set to 1024,
    this result is computed in integers modulo 1024. Therefore the expected output
    should be 7252 % 1024 == 84, or 0x54 in hexadecimal.
    */

    /*
    Sometimes we create customized encryption parameters which turn out to be invalid.
    Microsoft SEAL can interpret the reason why parameters are considered invalid.
    Here we simply reduce the polynomial modulus degree to make the parameters not
    compliant with the HomomorphicEncryption.org security standard.
    */
    print_line(__LINE__);
    cout << "An example of invalid parameters" << endl;
    parms.set_poly_modulus_degree(2048);
    context = SEALContext::Create(parms);
    print_parameters(context);
    cout << "Parameter validation (failed): " << context->parameter_error_message() << endl << endl;

    /*
    This information is helpful to fix invalid encryption parameters.
    */
}

const uint64_t logN = 15;
// const uint64_t modulo = 0x80000000080001ULL;
const uint64_t modulo = 18014398492704769ULL;
random_device r;
default_random_engine e1(r());
uniform_int_distribution<uint64_t> uniform_coeff(0, modulo - 1);

void test_ntt_and_mul()
{
    MemoryPoolHandle pool_ = seal::MemoryManager::GetPool(seal::mm_prof_opt::FORCE_NEW, true);
    util::NTTTables *tables = nullptr;
    tables = new seal::util::NTTTables(logN, modulo, pool_);
    // cout << "table coeff count = " << tables->coeff_count() << endl;
    // cout << "root = " << tables->get_root() << endl;
    // cout << "table:\n[ "; for (int i = 0; i < (1 << (logN - 3)); i++) { cout << i << "th: (" << tables->get_from_root_powers(i).operand << ", " << tables->get_from_root_powers(i).quotient << "), "; } cout << "]\n" << endl;
    uint64_t poly1[1 << logN], poly2[1 << logN], prod[1 << logN];
    for (int i = 0; i < (1 << logN); i++) { poly1[i] = uniform_coeff(e1); poly2[i] = uniform_coeff(e1); }
    // for (int i = 0; i < (1 << logN); i++) { poly1[i] = 0; poly2[i] = 0; poly1[1] = 1; poly2[1] = 1; }
    // cout << "poly -- all blocks: " << intptr_t(poly) << endl;
    util::CoeffIter iter1(poly1);
    util::CoeffIter iter2(poly2);
    util::CoeffIter result(prod);
    // uint64_t original_poly1[1 << logN];
    // uint64_t original_poly2[1 << logN];
    // for (int i = 0; i < (1 << logN); i++) { original_poly1[i] = poly1[i]; original_poly2[i] = poly2[i]; }
    // cout << "original poly: [ "; for (int i = 0; i < (1 << logN); i++) { cout << iter[i] << ", "; } cout << "]\n" << endl;
    // util::ntt_negacyclic_harvey(iter1, *tables);
    // cout << "ntt results: " << endl;
    // uint64_t ndiv8 = 1 << (logN - 3);
    // for (int i = 0; i < 8; i++) {
    //     cout << "[ ";
    //     for (int idx = i * ndiv8; idx < (i + 1) * ndiv8; idx++) { cout << poly[idx] << ", "; }
    //     cout << "]\n";
    // }
    // cout << endl;
    // util::inverse_ntt_negacyclic_harvey(iter1, *tables);
    // cout << "recovered poly: [ "; for (int i = 0; i < (1 << logN); i++) { cout << iter[i] << ", "; } cout << "]\n" << endl;
    // cout << "\nNTT Correct?\n";
    // for (int i = 0; i < (1 << logN); i++) { if (poly2[i] != poly1[i]) { cout << "Incorrect.\n"; break; } }

    // util::ntt_negacyclic_harvey(iter1, *tables);
    // util::ntt_negacyclic_harvey(iter2, *tables);
    // uint64_t tmp_poly[1 << logN];
    // for (int i = 0; i < (1 << logN); i++) { tmp_poly[i] = poly1[i]; }
    // util::CoeffIter tmp_iter(tmp_poly);
    // util::inverse_ntt_negacyclic_harvey(tmp_iter, *tables);
    // cout << "\nntt(poly1) correct? "; for (int i = 0; i < (1 << logN); i++) { if (tmp_iter[i] != original_poly1[i]) { cout << "Incorrect.\n"; break; } }
    // for (int i = 0; i < (1 << logN); i++) { tmp_poly[i] = poly2[i]; }
    // util::inverse_ntt_negacyclic_harvey(tmp_iter, *tables);
    // cout << "\nntt(poly2) correct? "; for (int i = 0; i < (1 << logN); i++) { if (tmp_iter[i] != original_poly2[i]) { cout << "Incorrect.\n"; break; } }
    // dyadic_product_coeffmod(iter1, iter2, 1 << logN, modulo, *tables, result);
    // util::inverse_ntt_negacyclic_harvey(result, *tables);
    // for (int i = 0; i < (1 << logN); i++) { tmp_poly[i] = 0; }
    // for (int i = 0; i < (1 << logN); i++) {
    //     for (int j = 0; j < (1 << logN); j++) {
    //         uint64_t tmp = (__uint128_t)original_poly1[i] * original_poly2[j] % modulo;
    //         if (i + j < (1 << logN)) {
    //             tmp_poly[i + j] += tmp;
    //             tmp_poly[i + j] %= modulo;
    //         } else {
    //             tmp_poly[i + j - (1 << logN)] += modulo - tmp;
    //             tmp_poly[i + j - (1 << logN)] %= modulo;
    //         }
    //     }
    // }
    // cout << "\nproduct correct? "; for (int i = 0; i < (1 << logN); i++) { if (tmp_poly[i] != result[i]) { cout << "Incorrect.\n"; break; } }
    cout << endl;

    // cout << "\ntable for dyadic: [ ";
    // for (int i = 0; i < (1 << logN) / 8; i++) {
    //     cout << tables->get_x_ntt_form(i) << ", ";
    // }
    // cout << "] " << endl;


    // timing
    // ...
    const uint64_t count = 10000;
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < count; i++) {
        util::ntt_negacyclic_harvey(iter1, *tables);
        util::ntt_negacyclic_harvey(iter2, *tables);
        dyadic_product_coeffmod(iter1, iter2, 1 << logN, modulo, result);
        util::inverse_ntt_negacyclic_harvey(result, *tables);
    }
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    // cout << "Done [" << time_diff.count() / count << " microseconds]" << endl;
    cout << "SEAL:" << endl;
    cout << "Average poly mul using NTT: " << time_diff.count() / count << " microseconds" << endl;
}

// void test_enc_and_dec() {
//     cout << "Test enc and then dec:\n";
//     EncryptionParameters parms(scheme_type::BFV);
//     parms.set_poly_modulus_degree(1 << logN);
//     parms.set_coeff_modulus(CoeffModulus::BFVDefault(1 << logN));
//     // cout << "moduli: [ "; for (auto& m: (parms.coeff_modulus())) { cout << m.value() << ", "; } cout << "] " << endl;
//     parms.set_plain_modulus(PlainModulus::Batching(1 << logN, 32));
//     auto ctx = SEALContext::Create(parms);
//     auto& ctx_data = *ctx -> key_context_data();
//     vector<uint64_t> raw;
//     for (int i = 0; i < (1 << logN); i++) { raw.push_back(uniform_coeff(e1)); }
//     // cout << "Initial data: [ "; for (auto& item: raw) { cout << item << ", "; } cout << "] " << endl;
//     BatchEncoder bencoder(ctx);
//     Plaintext plain;
//     Plaintext plain_recovered;
//     bencoder.encode(raw, plain);
//     Ciphertext cipher;
//     KeyGenerator kg(ctx);
//     auto sk = kg.secret_key();
//     auto pk = kg.public_key();
//     Encryptor enc(ctx, pk);
//     Decryptor dec(ctx, sk);


//     // timing
//     // ...
//     chrono::high_resolution_clock::time_point time_start, time_end;
//     chrono::microseconds time_diff;
//     time_start = chrono::high_resolution_clock::now();
//     for (int i = 0; i < 10000; i++) {
//         enc.encrypt(plain, cipher);
//         dec.decrypt(cipher, plain_recovered);
//     }
//     time_end = chrono::high_resolution_clock::now();
//     time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//     cout << "Done [" << time_diff.count() / 10000 << " microseconds]" << endl;

//     vector<uint64_t> raw_recovered;
//     raw_recovered.resize(1 << logN);
//     bencoder.decode(plain_recovered, raw_recovered);

//     if (plain_recovered != plain) { cout << "Incorrect." << endl; } else { cout << "Correct." << endl; }
//     // cout << "Recovered data: [ "; for (auto& item: raw_recovered) { cout << item << ", "; } cout << "] " << endl;
// }

void custom_test() {
    test_ntt_and_mul();
}