#include <iostream>
using namespace std;

#include "des.cpp"
#include "config.h"
#include "inverse_keygen.cpp"

/**
* Bits involved in the approximations for 6 and 7 rounds
*
*/
ui64 ph_masks[3] = {7, 18, 24};
ui64 pl_masks[2] = {12, 16};
ui64 ch_masks[1] = {15};
ui64 cl_masks[4] = {7, 18, 24, 29};
ui64 f_masks[1] = {15};


/**
*   Bits involved in the approximations for 7 round (symmetric direction)
*
*/
ui64 ph_masks7[4] = {7, 18, 24, 29};
ui64 pl_masks7[1] = {15};
ui64 cl_masks7[3] = {7, 18, 24};
ui64 ch_masks7[2] = {12, 16};



/**
* creates a random 64 bit plaintext 
*/
ui64 create_plaintext() {
    ui64 v = 0;
    for (int i = 0; i < 64; i = i + 4) {
        v = v << 4;
        v |= (rand() % 256);
    }

    return v;
}

/**
* @param key: the key for encryption (uint64_t)
* @param plaintext: the plaintext to encrypt (uint64_t)
*/
ui64 encrypt(ui64 key, ui64 plaintext, int mode) {
    DES *cipher = new DES(mode,key);
    ui64 c =  cipher->encrypt(plaintext);
    free(cipher);
    return c;
}

/*
* Computes the key value which raises to the max deviation from the half of plaintexts
*
*/
ui64 getMaxDeviationCandidate(int* counters, int shift, int n_plain, int number_keys) {
    int max = 0;
    for (int i = 0; i < number_keys; i++) {
        if (counters[i] > max) {
            max = counters[i];
        }
    }

    int min = max;
    for (int i = 0; i < number_keys; i++) {
        if (counters[i] < min) {
            min = counters[i];
        }
    }

    int value = 0;
    if (abs(max - (n_plain/2)) > abs(min - (n_plain/2))) {
        value = max;
    } else {
        value = min;
    }

    int key_bits = 0;
    printf("\nThe counter is: %d\nAnd the values are:\n",value);
    for (int i = 0; i < number_keys; i++) {
        if (counters[i] == value) {
            printf("%lx\n", ((ui64)i)<<shift);
            key_bits = i;
        }
    }

    ui64 k = ((ui64)key_bits)<<shift;

    return k;

}



/**
*   6 ROUND approximation used to find 6 bits of K1 or K8 in the position indicagted by SBOX 5
*   Given plaintext and ciphertexts, if they are given in that order, we will find bits of K8, otherwise 
*   we will find bits of K1.
*   @param plaintexts
*   @param ciphertexts
*   @param n_plain: the number of plaintexts
*   @param the key to use in order to skip the first round and make the approximation valid
*/
ui64 exfiltrate_key_bits_6rounds(ui64* plaintexts, ui64* ciphertexts, int n_plain, ui64 k_last_known) {
    
    int counter_key[64];
    for (int i = 0; i < 64; i++) {
        counter_key[i] = 0;
    }

    for (ui64 temp_key = 0; temp_key < 64; temp_key++) {
        for (int i = 0; i < 600000; i++) {
            ui64 p = plaintexts[i];  
            //p = DES::ip(p);
            ui64 c = ciphertexts[i];
            //c = DES::ip(c); we skip the initial and final permutation so it is commented

            ui32 CL = (ui32) (c & L64_MASK);
            ui32 CH = (ui32) (c >> 32) & L64_MASK;
            ui32 f8 = DES::f(CL, k_last_known);

            ui64 k = temp_key << 18;
            ui32 PH = (ui32) (p >> 32) & L64_MASK;
            ui32 PL = (ui32) (p & L64_MASK);

            ui32 f1 = DES::f(PL, k);
            int xor_value = 0;

            

            for (int index = 0; index < 3; index++) {
                xor_value = xor_value ^ ((PH & (0x1 << (ph_masks[index]))) >> (ph_masks[index]));
            }

            for (int index = 0; index < 3; index++) {
                xor_value = xor_value ^ ((f1 & (0x1 << (ph_masks[index]))) >> (ph_masks[index]));
            }
        
        
            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((CH & (0x1 << (ch_masks[index]))) >> (ch_masks[index]));
            }

            for (int index = 0; index < 4; index++) {
                xor_value = xor_value ^ ((CL & (0x1 << (cl_masks[index]))) >> (cl_masks[index]));
            }

            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((f8 & (0x1 << (f_masks[index]))) >> (f_masks[index]));
            }
    
            if (xor_value == 0) {
                counter_key[temp_key]++;
            }
                     
        }
    }    


    ui64 k = getMaxDeviationCandidate(counter_key, 18, 600000, 64);

    return k;

}


/**
*   7 ROUND approximation used to find 6 bits of K1 or K8 in the position indicated by SBOX 1
*   Given plaintext and ciphertexts, if they are given in that order, we will find bits of K8, otherwise 
*   we will find bits of K1.
*   @param plaintexts
*   @param ciphertexts
*   @param n_plain: the number of plaintexts
*/
ui64 exfiltrate_key_bits_7rounds(ui64* plaintexts, ui64* ciphertexts, int n_plain) {
    
    int counter_key[64];
    for (int i = 0; i < 64; i++) {
        counter_key[i] = 0;
    }

    for (ui64 temp_key = 0; temp_key < 64; temp_key++) {
        for (int i = 0; i < n_plain; i++) {
            ui64 p = plaintexts[i];
            //p = DES::ip(p);
            ui64 c = ciphertexts[i];
            //c = DES::ip(c); we skip the initial and final permutation so it is commented

            ui32 CL = (ui32) (c & L64_MASK);
            ui32 CH = (ui32) (c >> 32) & L64_MASK;
            ui64 k = temp_key << 42;
            ui32 d = DES::f(CL, k);

            ui32 PH = (ui32) (p >> 32) & L64_MASK;
            ui32 PL = (ui32) (p & L64_MASK);

            int xor_value = 0;

            

            for (int index = 0; index < 3; index++) {
                xor_value = xor_value ^ ((PH & (0x1 << (ph_masks[index]))) >> (ph_masks[index]));
            }

            for (int index = 0; index < 2; index++) {
                xor_value = xor_value ^ ((PL & (0x1 << (pl_masks[index]))) >> (pl_masks[index]));
            }

            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((CH & (0x1 << (ch_masks[index]))) >> (ch_masks[index]));
            }

            for (int index = 0; index < 4; index++) {
                xor_value = xor_value ^ ((CL & (0x1 << (cl_masks[index]))) >> (cl_masks[index]));
            }

            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((d & (0x1 << (f_masks[index]))) >> (f_masks[index]));
            }

            if (xor_value == 0) {
                counter_key[temp_key]++;
            }
                     
        }
    }

    ui64 k = getMaxDeviationCandidate(counter_key, 42, n_plain, 64);

    return k;

}



/**
*   7 ROUND approximation in the reverse order thanks to the DEs symmetries.
*   Used to find 12 bits of K8 in the position indicated by SBOX 3,4. Some of them are
*   already known from the previous functions, then we can use that fact to reduce the search space.
*   Order: Plaintext to Ciphertext
*   @param plaintexts
*   @param ciphertexts
*   @param n_plain: the number of plaintexts
*   @param key8_knowledge: previous knowledge of K8 from the previous computations
*/
ui64 exfiltrate_key_bits_7rounds_oppositeptoc(ui64* plaintexts, ui64* ciphertexts, int n_plain, ui64 key8_knowledge) {
    
    int counter_key[256];
    for (int i = 0; i < 256; i++) {
        counter_key[i] = 0;
    }

    for (ui64 temp_key = 0; temp_key < 256; temp_key++) {
        for (int i = 0; i < 2500000; i++) {
            ui64 p = plaintexts[i];
            //p = DES::ip(p);
            ui64 c = ciphertexts[i];
            //c = DES::ip(c);
            ui64 k = key8_knowledge;
            ui32 CL = (ui32) (c & L64_MASK);
            ui32 CH = (ui32) (c >> 32) & L64_MASK;
            
            ui64 piece1 = temp_key >> 5;
            k = k ^ (piece1 << 33);

            ui64 p30 = (temp_key & 0b10000) >> 4;
            ui64 p28 = (temp_key & 0b1000) >> 3;
            ui64 p27 = (temp_key & 0b100) >> 2;
            ui64 p25 = (temp_key & 0b10) >> 1;
            ui64 p24 = (temp_key & 0b1);
            
            k ^= (p30 << 30);
            k ^= (p28 << 28);
            k ^= (p27 << 27);
            k ^= (p25 << 25);
            k ^= (p24 << 24);

            ui32 PH = (ui32) (p >> 32) & L64_MASK;
            ui32 PL = (ui32) (p & L64_MASK);

            ui32 d = DES::f(CL, k);
            int xor_value = 0;

            
            for (int index = 0; index < 4; index++) {
                xor_value = xor_value ^ ((PH & (0x1 << (ph_masks7[index]))) >> (ph_masks7[index]));
            }

            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((PL & (0x1 << (pl_masks7[index]))) >> (pl_masks7[index]));
            }

            for (int index = 0; index < 2; index++) {
                xor_value = xor_value ^ ((CH & (0x1 << (ch_masks7[index]))) >> (ch_masks7[index]));
            }

            for (int index = 0; index < 3; index++) {
                xor_value = xor_value ^ ((CL & (0x1 << (cl_masks7[index]))) >> (cl_masks7[index]));
            }

            for (int index = 0; index < 2; index++) {
                xor_value = xor_value ^ ((d & (0x1 << (ch_masks7[index]))) >> (ch_masks7[index]));
            }

            if (xor_value == 0) {
                counter_key[temp_key]++;
            }
                     
        }
    }

    ui64 temp_key = getMaxDeviationCandidate(counter_key, 0, 2500000, 256);
    ui64 k = key8_knowledge;
  
    ui64 piece1 = temp_key >> 5;
    k = k ^ (piece1 << 33);

    ui64 p30 = (temp_key & 0b10000) >> 4;
    ui64 p28 = (temp_key & 0b1000) >> 3;
    ui64 p27 = (temp_key & 0b100) >> 2;
    ui64 p25 = (temp_key & 0b10) >> 1;
    ui64 p24 = (temp_key & 0b1);
    
    k ^= (p30 << 30);
    k ^= (p28 << 28);
    k ^= (p27 << 27);
    k ^= (p25 << 25);
    k ^= (p24 << 24);

    return k;

}


/**
*   7 ROUND approximation in the reverse order thanks to the DES symmetries.
*   Used to find 12 bits of K1 in the position indicated by SBOX 3,4. Some of them are
*   already known from the previous functions, then we can use that fact to reduce the search space.
*   Order: Ciphertext to Plaintext
*   @param plaintexts
*   @param ciphertexts
*   @param n_plain: the number of plaintexts
*   @param key1_knowledge: previous knowledge of K1 from the previous computations
*/
ui64 exfiltrate_key_bits_7rounds_oppositectop(ui64* plaintexts, ui64* ciphertexts, int n_plain, ui64 key1_knowledge) {
    
    int counter_key[32];
    for (int i = 0; i < 32; i++) {
        counter_key[i] = 0;
    }

    for (ui64 temp_key = 0; temp_key < 32; temp_key++) {
        for (int i = 0; i < 2500000; i++) {
            ui64 p = plaintexts[i];
            //p = DES::ip(p);
            ui64 c = ciphertexts[i];
            //c = DES::ip(c);
            ui64 k = key1_knowledge;
            ui32 CL = (ui32) (c & L64_MASK);
            ui32 CH = (ui32) (c >> 32) & L64_MASK;
            
            ui64 p34 = (temp_key & 0b11000) >> 3;
            ui64 p28 = (temp_key & 0b110) >> 1;
            ui64 p25 = (temp_key & 0b1);
         
            k ^= (p34 << 34);
            k ^= (p28 << 28);
            k ^= (p25 << 25);
        
            ui32 PH = (ui32) (p >> 32) & L64_MASK;
            ui32 PL = (ui32) (p & L64_MASK);


            ui32 d = DES::f(CL, k);
            int xor_value = 0;

            

            for (int index = 0; index < 4; index++) {
                xor_value = xor_value ^ ((PH & (0x1 << (ph_masks7[index]))) >> (ph_masks7[index]));
            }

            for (int index = 0; index < 1; index++) {
                xor_value = xor_value ^ ((PL & (0x1 << (pl_masks7[index]))) >> (pl_masks7[index]));
            }

            for (int index = 0; index < 2; index++) {
                xor_value = xor_value ^ ((CH & (0x1 << (ch_masks7[index]))) >> (ch_masks7[index]));
            }

            for (int index = 0; index < 3; index++) {
                xor_value = xor_value ^ ((CL & (0x1 << (cl_masks7[index]))) >> (cl_masks7[index]));
            }

            for (int index = 0; index < 2; index++) {
                xor_value = xor_value ^ ((d & (0x1 << (ch_masks7[index]))) >> (ch_masks7[index]));
            }

            if (xor_value == 0) {
                counter_key[temp_key]++;
            }
                     
        }
    }

    ui64 temp_key = getMaxDeviationCandidate(counter_key, 0, 2500000, 32);
    ui64 k = key1_knowledge;
  
    ui64 p34 = (temp_key & 0b11000) >> 3;
    ui64 p28 = (temp_key & 0b110) >> 1;
    ui64 p25 = (temp_key & 0b1);
    
    k ^= (p34 << 34);
    k ^= (p28 << 28);
    k ^= (p25 << 25);

    return k;

}



/**
* It perform exhaustive search against the remaining bits. O(2^22)
*
**/
void perform_bruteforce(int remaining_bits, ui64* plaintexts, ui64* ciphertexts, ui64 original_key) {
    int max_attempts = 2<<remaining_bits;
    for (int i = 0; i < max_attempts; i++) {
        int bit_container = i;
        int8_t* key_master_temp = (int8_t*) malloc(56*sizeof(int8_t));

        //copying key_master into an other array and putting new values from bit_container
        int index_unknown_bit = 0; // goes from 0 <= index_unknown_bit < remaining_bits

        for (int j = 0; j < 56; j++) {
            if (key_master[j] == -1) {
                key_master_temp[j] = (bit_container >> index_unknown_bit) & 0x1;
                index_unknown_bit++;
            } else {
                key_master_temp[j] = key_master[j];
            }
        }

        // generate ui64 from key_master temp
        ui64 key_master_value_attempt = 0;
        for (int j = 0; j < 56; j++) {
           
            key_master_value_attempt ^= (((ui64)key_master_temp[j]) << j);
        }

        free(key_master_temp);

        uint8_t key_guessed = 1;
        for (int t = 0; t < 3; t++) {
            ui64 p = plaintexts[t];
            ui64 original_ciphertext = ciphertexts[t];

            ui64 computed_ciphertext = encrypt(key_master_value_attempt, p, 1); //mode 1, from 56 bits

            if (computed_ciphertext != original_ciphertext) {
                key_guessed = 0;
                break;
            }
        }

        
        if (key_guessed == 1) {
            printf("Key FOUND at the attempt number: %d\n", i);
            printf("The key is: %lx\n", key_master_value_attempt);
            break;
        }
    
    }
}



int main(int argc, char **argv)
{
   
    // initialization of the seed random function for generating random plaintexts
    srand(time(NULL));

    // preparing the random plaintexts
    int n_plain = 3000000;
    ui64* plaintexts = (ui64*) malloc(n_plain * sizeof(ui64));
    for (int i = 0; i < n_plain; i++) {
        plaintexts[i] = create_plaintext();
    }

    ui64* ciphertexts = (ui64*) malloc(n_plain * sizeof(ui64));
    for (int i = 0; i < n_plain; i++) {
        ciphertexts[i] = encrypt(KEY, plaintexts[i], 0);
    }

    // key container initialization
    key_containers_initialization();

    ui64 original_key = get56BitsKey();
    printf("The 56 bits key derived from your 64 bits input is: %lx\n", original_key);

    /**
    *  ------------------------------------------------- ATTACK ----------------------------------------------------------------
    **/
    printf("Running the attack ....");
    clock_t begin = clock();

    ui64 k8_s1 = exfiltrate_key_bits_7rounds(plaintexts, ciphertexts, n_plain);
    ui64 k1_s1 = exfiltrate_key_bits_7rounds(ciphertexts, plaintexts, n_plain);

    ui64 k1_s5 = exfiltrate_key_bits_6rounds(plaintexts, ciphertexts, n_plain, k8_s1);
    ui64 k8_s5 = exfiltrate_key_bits_6rounds(ciphertexts, plaintexts, n_plain, k1_s1);

    // compute the master until now
    ui64 master = inverse_keygen(k1_s1, 1, 42, 47) | inverse_keygen(k8_s1, 8, 42, 47) | inverse_keygen(k1_s5, 1, 18, 23) | inverse_keygen(k8_s5, 8, 18, 23);
    // generate subkeys from the derived master key: this is useful to identify what are the bits we already know
    keygen(master);

    ui64 k8_s3s4 = exfiltrate_key_bits_7rounds_oppositeptoc(plaintexts, ciphertexts, n_plain, sub_keys[7]);

    reset_sub_keys();
    master = master | inverse_keygen(k8_s3s4, 8, 24, 35); // TODO: repeat this in order to set the right bits
    keygen(master);

    ui64 k1_s3s4 = exfiltrate_key_bits_7rounds_oppositectop(ciphertexts, plaintexts, n_plain, sub_keys[0]);

    reset_sub_keys();
    master = master | inverse_keygen(k1_s3s4, 1, 24, 35); // TODO: repeat this in order to set the right bits
    keygen(master);
    
    printf("The master is: %lx\n", master);
    printf("SubKey Round 1: %lx\n", sub_keys[0]);
    printf("Subkey Round 8: %lx\n", sub_keys[7]);


    // count the number of bits I need the set yet
    int remaining_bits = 0;
    for (int i = 0; i < 56; i++) {
    
        if (key_master[i] == -1) {
            remaining_bits++;
        }
    }
    

    // these are the bits I can discover by using the linear equations
    // unfortunately they are already set, then we can't discover more bits with this method
    // I printed it in order to check whether they satisfy or not the equations, CORRECT
    /*
    printf("K1-19: %d\n", subkey_expanded[0][19]);
    printf("K1-23: %d\n", subkey_expanded[0][23]);
    printf("K8-19: %d\n", subkey_expanded[7][19]);
    printf("K8-23: %d\n", subkey_expanded[7][23]);
    */ 


    printf("We need to find %d bits yet.\n", remaining_bits);

    /**
    *  ------------------------------------------------- STARTING BRUTEFORCE EXHAUSTIVE SEARCH ON REMAINING BITS ----------------------------------------------------------------
    **/

    printf("Running exhaustive search on remaining bits ...\n");
    // it already know key master because it is a global variable
    perform_bruteforce(remaining_bits, plaintexts, ciphertexts, original_key);


    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("Execution time: %lf seconds\n", time_spent);
    /**
    *  ------------------------------------------------- FINISH ----------------------------------------------------------------
    **/

    return 0;
    
}
