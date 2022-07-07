int8_t key_master[56]; // will contain the master key generated from the guessing
ui64 sub_keys[16]; // contains the 48 bits subkey values of each round
int subkey_expanded[16][56]; //contains the the bits values of each round subkey
   
/**
* DES key generation function
* It fills the value of the array sub_keys and automatically sets the bits values in the array subkey_expanded for each round
* It is used to have a trace of the bits already known and not
*/
void keygen(ui64 key)
{
    // initial key schedule calculation
    ui64 permuted_choice_1 = key; // 56 bits
    

    int positions_CD[56];
    for (int i = 0; i < 56; i++) {
        positions_CD[i] = i;
    }

    // 28 bits
    ui32 C = (ui32) ((permuted_choice_1 >> 28) & 0x000000000fffffff);
    ui32 D = (ui32)  (permuted_choice_1 & 0x000000000fffffff);

    // Calculation of the ROUNDS keys
    for (ui8 i = 0; i < ROUNDS; i++)
    {
        // key schedule, shifting Ci and Di
        for (ui8 j = 0; j < ITERATION_SHIFT[i]; j++)
        {
            C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
            D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));

            for (int p = 55; p >= 0; p--) {
                if (positions_CD[p] == 55) {
                    positions_CD[p] = 28;
                } else if (positions_CD[p] == 27) {
                    positions_CD[p] = 0;
                } else {
                    positions_CD[p] = positions_CD[p] + 1;
                }
            }
          
        }
     

        ui64 permuted_choice_2 = (((ui64) C) << 28) | (ui64) D;


        sub_keys[i] = 0; // 48 bits (2*24)
        for (ui8 j = 0; j < 48; j++)
        {
            sub_keys[i] <<= 1;
            sub_keys[i] |= (permuted_choice_2 >> (56-PC2[j])) & LB64_MASK;
        }

        int new_positions[56];
        for (int l = 0; l < 56; l++) {
            new_positions[l] = -1;
        }
        // update array positions
        for (int j = 0; j < 48; j++)
        {
            int old_position = 56 - PC2[j];
            int new_position = 47 - j;
            for (int p = 55; p >= 0; p--) {
                if (positions_CD[p] == old_position) {
                    new_positions[p] = new_position;
                    
                }
            }
            
        }     

        for (int l = 55; l >= 0; l--) {
            int new_pos = new_positions[l];
            if (new_pos != -1) {
                subkey_expanded[i][new_pos] = key_master[l];
            }
        }

    }
}

/**
*   Computes the master key bits from the known bits of a given round key
*/
ui64 inverse_keygen(ui64 subkey, int rounds, int start_index, int out_index) {
    uint8_t positions[48];
    for (int i = 0; i < 48; i++)
        positions[i] = 100; // value which means 'not assigned'

    ui64 permuted_choice_2 = 0;
        for (int j = 47; j > -1; j = j - 1)
            {
                ui8 original_pos = 56 - PC2[47-j];
                permuted_choice_2 |= (((subkey >> j) & LB64_MASK) << original_pos);

                if (j <= out_index && j >= start_index) {
                    positions[j] = original_pos;
                }
            }

        ui32 C = (ui32) ((permuted_choice_2 >> 28) & 0x000000000fffffff);
        ui32 D = (ui32)  (permuted_choice_2 & 0x000000000fffffff);

        for (int i = 0; i < rounds; i++) {
        for (ui8 j = 0; j < ITERATION_SHIFT[i]; j++)
        {
            C = ((C >> 1) & 0x07ffffff) | (C  & 0x1) << 27;
            D = ((D >> 1) & 0x07ffffff) | (D  & 0x1) << 27;

            if (out_index < 28) {
                for (int p = start_index; p <= out_index; p++) {
                    if (positions[p] == 0) {
                        positions[p] = 27;
                    } else {
                        positions[p] -= 1;
                    }
                }
            } else {
                for (int p = start_index; p <= out_index; p++) {
                    if (positions[p] == 28) {
                        positions[p] = 55;
                    } else {
                        positions[p] -= 1;
                    }
                }
            }
        }

        }
            ui64 permuted_choice_1 = (((ui64) C) << 28) | (ui64) D;

        for (int i = start_index; i <= out_index; i++) {
            uint8_t value = (subkey >> i) & 0x1;
            if (key_master[positions[i]] != -1) {
                if (key_master[positions[i]] != value) {
                    printf("Errore!\n");
                }
            } else {
                key_master[positions[i]] = value;
            } 
        }


        /**
        *
        *   DEBUGGING
        
        printf("\n");
        for (int index = 55; index >= 0; index--) {
            printf(" %d |", key_master[index]);
        }
        printf("\n");
        */

        return permuted_choice_1;


}


ui64 get56BitsKey() {
    // the used will choose a 64 bit key as the standard required
    // From this 64 the tool chooses 56 bits. It is the real key to guess
    ui64 permuted_choice_1 = 0; // 56 bits
    for (ui8 i = 0; i < 56; i++)
    {
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (KEY >> (64-PC1[i])) & LB64_MASK;
    }

    return permuted_choice_1;
}

// to be called before computing all the keys IMPORTANT
void key_containers_initialization() {
    // initializing key to -1
    for (int i = 0; i < 56; i++) {
        key_master[i] = -1;
    }

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 56; j++) {
            subkey_expanded[i][j] = -1;
        }
    }
}

void reset_sub_keys() {
    for (int i = 0; i < 16; i++) {
        sub_keys[i] = 0;
        for (int j = 0; j < 56; j++) {
            subkey_expanded[i][j] = -1;
        }
    }
}

// example of usage
// it is used within main.cpp in order to perform the attack

/*

    ui64 k1 = 0xac0000000000;
    ui64 k2 = 0xc80000000000;
    ui64 k3 = 0x700000;
    ui64 k4 = 0xec0000;
    ui64 k5 = 0x612000000;
    ui64 k6 = 0x1ad000000;

    ui64 master = inverse_keygen(k1, 1, 42, 47) | inverse_keygen(k2, 8, 42, 47) | inverse_keygen(k3, 1, 18, 23) | inverse_keygen(k4, 8, 18, 23) | inverse_keygen(k5, 8, 24, 35) | inverse_keygen(k6, 1, 24, 34);

    printf("%lx\n", master);
    for (int i = 55; i >= 0; i--) {
        printf("%d |", key_master[i]);
    }

    keygen(master);
    printf("%lx\n", sub_keys[0]);
    

    for (int i = 55; i >= 0; i--) {
        printf("%d |", subkey_expanded[0][i]);
    }

*/