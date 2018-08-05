/*
 *   Project: Bitsliced LED-64-128 implementation (Encryption)
 */

// ####################################

#define SET_BIT(value, bit)        ((value) | ((u64)1 << (bit)))
#define CLEAR_BIT(value, bit)      ((value) & ~((u64)1 << (bit)))
#define GET_BIT(value, bit)       ((((value) >> (bit)) & (u64)1))
#define TOGGLE_BIT(value, bit)    ((value) ^ ((u64)1 << (bit)))

// includes
#include "led_bitsliced.h"


// ########################################################################
// CONVERSION FUNCTIONS
// ########################################################################

/*
 * Converts 64 plaintexts of each 64 bit into the bitsliced representation.
 * state[0] contains all MSBs.
 * The bits of plaintext[0] fill the MSBs of the state registers.
 *
 * This way, the LED state-matrix can be written as:
 * | s[ 0]s[ 1]s[ 2]s[ 3]   s[ 4]s[ 5]s[ 6]s[ 7]   s[ 8]s[ 9]s[10]s[11]   s[12]s[13]s[14]s[15] |
 * | s[16]s[17]s[18]s[19]   s[20]s[21]s[22]s[23]   s[24]s[25]s[26]s[27]   s[28]s[29]s[30]s[31] |
 * | s[32]s[33]s[34]s[35]   s[36]s[37]s[38]s[39]   s[40]s[41]s[42]s[43]   s[44]s[45]s[46]s[47] |
 * | s[48]s[49]s[50]s[51]   s[52]s[53]s[54]s[55]   s[56]s[57]s[58]s[59]   s[60]s[61]s[62]s[63] |
 *
 *
 * @param[out] state - the state to fill
 * @param[in] plaintext - an array containing 64 plaintexts
 */
void convert_to_bitsliced_state(bitsliced_state* state, const u64 plaintext[64])
{
    for(int i=0; i<64; i++)
        state->value[i] =0;

    //iterate through all bits at same position through all plaintexts
    for(int stateIndex=0; stateIndex < 64; stateIndex++) //stateIndex = 0...63
    {
        int plaintextBitposition = (stateIndex - 63) * (-1); // bitposition = 63...0
        for(int i = 0; i < 64; i++) //starting with MSB, because
        {
            int stateBitposition = (i - 63) * (-1);

            u64 bit = GET_BIT(plaintext[i] , plaintextBitposition);
            if(bit)
                state->value[stateIndex] = SET_BIT(state->value[stateIndex] , stateBitposition);
            else
                state->value[stateIndex] = CLEAR_BIT(state->value[stateIndex], stateBitposition);
        }
    }

}


/*
 * Converts a bitsliced state into 64 ciphertexts.
 * Inverts convert_to_bitsliced_state if invoked without any steps in between.
 *
 * @param[out] ciphertext - the array to convert into
 * @param[in] state - the bitsliced state
 */
void convert_from_bitsliced_state(u64 ciphertext[64], const bitsliced_state* state)
{
    for(int i=0; i<64; i++)
        ciphertext[i] =0;

    //iterate through all bits at same position through all plaintexts
    for(int ciphertextIndex=0; ciphertextIndex < 64; ciphertextIndex++) //stateIndex = 0...63
    {
        int cipherBitposition = (ciphertextIndex - 63) * (-1);
        for(int i = 0; i < 64; i++) //starting with MSB, because
        {
            int stateBitposition = (i - 63) * (-1);
            u64 bit = GET_BIT(state->value[i], cipherBitposition);

            if(bit)
                ciphertext[ciphertextIndex] = SET_BIT(ciphertext[ciphertextIndex],stateBitposition);
            else
                ciphertext[ciphertextIndex] = CLEAR_BIT(ciphertext[ciphertextIndex],stateBitposition);
        }
    }


}


// ########################################################################
// ROUND FUNCTIONS
// ########################################################################

/*
 * Performs AddRoundKey on a bitsliced state.
 *
 * @param[inout] state - the bitsliced state to update
 * @param[in] key - the key-half (either K1 or K2)
 */
void add_roundkey(bitsliced_state* state, u64 key)
{
    for (u64 stateIndex = 0; stateIndex < 64; stateIndex++)
    {
        u64 keyBitposition = (stateIndex - 63) * (-1);
        u64 keyBit = ((key >> keyBitposition) & (u64)1);
        for(int i=0; i<64;i++)
        {
            if(keyBit == 1)
                state->value[stateIndex] = TOGGLE_BIT(state->value[stateIndex] ,i);
        }
    }

}


/*
 * Performs AddConstants on a bitsliced state.
 *
 * @param[inout] state - the bitsliced state to update
 * @param[in] key - the key-half (either K1 or K2)
 */
void add_constants(bitsliced_state* state, u8 round)
{
    static const u8 RC[48] =
    {
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
        0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
    };

    /*
    * | s[ 0]s[ 1]s[ 2]s[ 3]       s[ 4]s[ 5]s[ 6]s[ 7] + constantRC543   s[ 8]s[ 9]s[10]s[11]   s[12]s[13]s[14]s[15] |
    * | s[16]s[17]s[18]s[19] + 1   s[20]s[21]s[22]s[23] + constantRC210  s[24]s[25]s[26]s[27]   s[28]s[29]s[30]s[31] |
    * | s[32]s[33]s[34]s[35] + 2   s[36]s[37]s[38]s[39] + constantRC543  s[40]s[41]s[42]s[43]   s[44]s[45]s[46]s[47] |
    * | s[48]s[49]s[50]s[51] + 3   s[52]s[53]s[54]s[55] + constantRC210  s[56]s[57]s[58]s[59]   s[60]s[61]s[62]s[63] |
    */

    u64 constantRC543 = (RC[round] >> 3) & 7;
    u64 constantRC210 =  RC[round] & 7;

    u64 constantRC210_8 = constantRC210 << 8;
    u64 constant3_12 = (u64)3 << 12;
    u64 constantRC543_24 = constantRC543 << 24;
    u64 constant2_28 = (u64)2 << 28;
    u64 constantRC210_40 = constantRC210 << 40;
    u64 constant1_44 = (u64)1 << 44;
    u64 constantRC543_56 = constantRC543 << 56;

    u64 constant_state = constantRC210_8 + constant3_12 + constantRC543_24 + constant2_28 + constantRC210_40 + constant1_44 + constantRC543_56;

    add_roundkey(state, constant_state); //reuse

}


/*
 * Performs SubCells on a bitsliced state.
 * Apply your optimized bitwise formulas obtained from KV-maps.
 *
 * @param[inout] state - the bitsliced state to update
 */
void sub_cells(bitsliced_state* state)
{
    for(int stateBitposition=63; stateBitposition >= 0; stateBitposition--)
    {
        for(int stateIndex=0; stateIndex < 64; stateIndex+=4)
        {
            u64 nibbleBit_3 = GET_BIT(state->value[stateIndex], stateBitposition);
            u64 nibbleBit_2 = GET_BIT(state->value[stateIndex + 1], stateBitposition);
            u64 nibbleBit_1 = GET_BIT(state->value[stateIndex + 2], stateBitposition);
            u64 nibbleBit_0 = GET_BIT(state->value[stateIndex + 3], stateBitposition);

            //Bit 3 for SBOX Output
            u64 subNibbleBit_3 = ( (~nibbleBit_3 & ( ~(nibbleBit_0 ^ nibbleBit_1) | (nibbleBit_2 & ~nibbleBit_0) )) | ((nibbleBit_3 & ~nibbleBit_2) & (nibbleBit_0 | nibbleBit_1))  ) & (u64)1; //get only (one) LSB-Bit
            if(subNibbleBit_3)
                state->value[stateIndex] = SET_BIT(state->value[stateIndex] , stateBitposition);
            else
                state->value[stateIndex] = CLEAR_BIT(state->value[stateIndex] , stateBitposition);

            //Bit 2 for SBOX Output
            u64 subNibbleBit_2 = ((~nibbleBit_1 & ~(nibbleBit_2 ^ nibbleBit_3)) | (~nibbleBit_2 & (nibbleBit_0 ^ nibbleBit_1)) | (nibbleBit_0 & nibbleBit_1 & nibbleBit_2 & ~nibbleBit_3) ) & (u64)1;
            if(subNibbleBit_2)
                state->value[stateIndex+1] = SET_BIT(state->value[stateIndex+1], stateBitposition);
            else
                state->value[stateIndex+1] = CLEAR_BIT(state->value[stateIndex+1] , stateBitposition);

            //Bit 1 for SBOX Output
            u64 subNibbleBit_1 = (~nibbleBit_2 & (nibbleBit_1 ^ nibbleBit_3)) | ((nibbleBit_1 & ~nibbleBit_0) & (~nibbleBit_2 | ~nibbleBit_3)) | ((nibbleBit_0 & nibbleBit_3) & (nibbleBit_2 | ~nibbleBit_1));
            if(subNibbleBit_1)
                state->value[stateIndex+2] = SET_BIT(state->value[stateIndex+2], stateBitposition);
            else
                state->value[stateIndex+2] = CLEAR_BIT(state->value[stateIndex+2] , stateBitposition);

            //Bit 0 for SBOX Output
            u64 subNibbleBit_0 = (~nibbleBit_1 & nibbleBit_2) ^ nibbleBit_0 ^ nibbleBit_3;
            if(subNibbleBit_0)
                state->value[stateIndex+3] = SET_BIT(state->value[stateIndex+3], stateBitposition);
            else
                state->value[stateIndex+3] = CLEAR_BIT(state->value[stateIndex+3] , stateBitposition);

        }
    }


}


/*
 * Performs ShiftRows on a bitsliced state.
 * To reduce complexity, this is performed as an individual step and not merged into the inputs of the next operation.
 *
 * @param[inout] state - the bitsliced state to update
 */
void shift_rows(bitsliced_state* state)
{

    /*
     * Before Shifting
     * | s[ 0]s[ 1]s[ 2]s[ 3]   s[ 4]s[ 5]s[ 6]s[ 7]   s[ 8]s[ 9]s[10]s[11]   s[12]s[13]s[14]s[15] |
     * | s[16]s[17]s[18]s[19]   s[20]s[21]s[22]s[23]   s[24]s[25]s[26]s[27]   s[28]s[29]s[30]s[31] |
     * | s[32]s[33]s[34]s[35]   s[36]s[37]s[38]s[39]   s[40]s[41]s[42]s[43]   s[44]s[45]s[46]s[47] |
     * | s[48]s[49]s[50]s[51]   s[52]s[53]s[54]s[55]   s[56]s[57]s[58]s[59]   s[60]s[61]s[62]s[63] |
     *
     * After Shifting
     *
     * | s[ 0]s[ 1]s[ 2]s[ 3]   s[ 4]s[ 5]s[ 6]s[ 7]   s[ 8]s[ 9]s[10]s[11]   s[12]s[13]s[14]s[15] |
     * | s[20]s[21]s[22]s[23]   s[24]s[25]s[26]s[27]   s[28]s[29]s[30]s[31]   s[16]s[17]s[18]s[19] | 1 Left Shift
     * | s[40]s[41]s[42]s[43]   s[44]s[45]s[46]s[47]   s[32]s[33]s[34]s[35]   s[36]s[37]s[38]s[39] | 2 Left Shifts
     * | s[60]s[61]s[62]s[63]   s[48]s[49]s[50]s[51]   s[52]s[53]s[54]s[55]   s[56]s[57]s[58]s[59] | 3 Left Shifts
     *
     */

    //Alternative Code:
    //    //first 4 nibbles are not shifted
    //    //2. Row / next 4 nibbles
    //    u64 tmp4[4];
    //    for(int i=16; i < 20; i++)
    //        tmp4[i - 16] = state->value[i];
    //    for(int i=16; i< 28; i++)
    //        state->value[i] = state->value[i+4];
    //    for(int i=28; i<32; i++)
    //        state->value[i] = tmp4[i - 28];
    //
    //    //3. Row / next 4 nibbles
    //    u64 tmp8[8];
    //    for(int i=32; i < 40; i++)
    //        tmp8[i - 32] = state->value[i];
    //    for(int i=32; i< 40; i++)
    //        state->value[i] = state->value[i+8];
    //    for(int i=40; i< 48; i++)
    //        state->value[i] = tmp8[i - 40];
    //
    //    //4. Row / next 4 nibbles
    //    u64 tmp12[12];
    //    for(int i=48; i < 60; i++)
    //        tmp12[i - 48] = state->value[i];
    //    for(int i=48; i< 52; i++)
    //        state->value[i] = state->value[i+12];
    //    for(int i=52; i< 64; i++)
    //        state->value[i] = tmp12[i - 52];


    //Compact Code
    u64 tmp[12];
    for(int j=1; j<=3; j++)
    {
        int k = (j - 4) * (-1); // k = 3,2,1

        for(int i=16*j; i < 20*j; i++)
            tmp[i - 16*j] = state->value[i];

        for(int i=16*j; i< 16*j + (k*4); i++)
            state->value[i] = state->value[i+4*j];

        for(int i=16*j + (k*4); i< 16*j + (k*4) + j*4; i++)
            state->value[i] = tmp[i - (16*j + (k*4))];
    }

}


// ########################################################################
// MIX COLUMNS SERIAL FUNCTIONS
// ########################################################################

/*
 * Helper structs for MixColumnsSerial
 */
typedef struct
{
    u64 value[4];
} bitsliced_gfelement;

typedef struct
{
    u64 value[16];
} bitsliced_column;


/**================================================
    01 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc1(bitsliced_gfelement val)
{
    bitsliced_gfelement result = {0};
    for (int i = 0; i < 4; i++)
    {
        result.value[i] = val.value[i];
    }
    return result;
}

/**================================================
    02 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc2(bitsliced_gfelement val)
{
    bitsliced_gfelement result;

    u64 x3 = val.value[0];
    u64 x2 = val.value[1];
    u64 x1 = val.value[2];
    u64 x0 = val.value[3];

    u64 y3 = x2;
    u64 y2 = x1;
    u64 y1 = x0 ^ x3;
    u64 y0 = x3;

    result.value[0] = y3;
    result.value[1] = y2;
    result.value[2] = y1;
    result.value[3] = y0;

    return result;
}

/**================================================
    04 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc4(bitsliced_gfelement val)
{
    bitsliced_gfelement result;

    u64 x3 = val.value[0];
    u64 x2 = val.value[1];
    u64 x1 = val.value[2];
    u64 x0 = val.value[3];

    u64 y3 = x1;
    u64 y2 = x0 ^ x3;
    u64 y1 = x2 ^ x3;
    u64 y0 = x2;

    result.value[0] = y3;
    result.value[1] = y2;
    result.value[2] = y1;
    result.value[3] = y0;

    return result;
}

/**================================================
    08 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc8(bitsliced_gfelement val)
{
    bitsliced_gfelement result;

    u64 x3 = val.value[0];
    u64 x2 = val.value[1];
    u64 x1 = val.value[2];
    u64 x0 = val.value[3];

    u64 y3 = x0 ^ x3;
    u64 y2 = x2 ^ x3;
    u64 y1 = x2 ^ x1;
    u64 y0 = x1;

    result.value[0] = y3;
    result.value[1] = y2;
    result.value[2] = y1;
    result.value[3] = y0;

    return result;
}

/**================================================
    05 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc5(bitsliced_gfelement val)
{
    bitsliced_gfelement result;

    //Alternative:
    //    result = mc4(val);
    //    for (u8 i = 0; i < 4; i++)
    //    {
    //        result.value[i] ^= val.value[i];
    //    }
    //    return result;

    u64 x3 = val.value[0];
    u64 x2 = val.value[1];
    u64 x1 = val.value[2];
    u64 x0 = val.value[3];

    u64 y0 = x2 ^ x0;
    u64 y1 = x1 ^ x2 ^ x3;
    u64 y2 = x0 ^ x2 ^ x3;
    u64 y3 = x3 ^ x1;

    result.value[0] = y3;
    result.value[1] = y2;
    result.value[2] = y1;
    result.value[3] = y0;

    return result;
}

/**================================================
    06 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc6(bitsliced_gfelement val)
{
    bitsliced_gfelement tmp = mc4(val);
    bitsliced_gfelement result = mc2(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= tmp.value[i];
    }
    return result;
}

/**================================================
    09 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc9(bitsliced_gfelement val)
{
    bitsliced_gfelement result = mc8(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= val.value[i];
    }
    return result;
}

/**================================================
    10 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc10(bitsliced_gfelement val)
{
    bitsliced_gfelement tmp = mc8(val);
    bitsliced_gfelement result = mc2(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= tmp.value[i];
    }
    return result;
}

/**================================================
    11 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc11(bitsliced_gfelement val)
{
    bitsliced_gfelement tmp = mc8(val);
    bitsliced_gfelement result = mc2(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= (tmp.value[i] ^ val.value[i]);
    }
    return result;
}

/**================================================
    14 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc14(bitsliced_gfelement val)
{
    bitsliced_gfelement tmp  = mc8(val);
    bitsliced_gfelement tmp1 = mc4(val);
    bitsliced_gfelement result = mc2(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= (tmp.value[i] ^ tmp1.value[i]);
    }
    return result;
}

/**================================================
    15 * X in GF(2^4)   X = (val[0], val[1], val[2], val[3])
================================================**/
bitsliced_gfelement mc15(bitsliced_gfelement val)
{
    bitsliced_gfelement tmp  = mc8(val);
    bitsliced_gfelement tmp1 = mc4(val);
    bitsliced_gfelement result = mc2(val);
    for (u8 i = 0; i < 4; i++)
    {
        result.value[i] ^= (tmp.value[i] ^ tmp1.value[i] ^ val.value[i]);
    }
    return result;
}

/*
 * Computes a single MixColumnsSerial column.
 *
 * Basically this function performs the following operation:
 *   -----------------------------------------------
 *   result[0]   = 4*A[0] ^ 1*B[0] ^ 2*C[0] ^ 2*D[0]
 *   result[1]   = 4*A[1] ^ 1*B[1] ^ 2*C[1] ^ 2*D[1]
 *   result[2]   = 4*A[2] ^ 1*B[2] ^ 2*C[2] ^ 2*D[2]
 *   result[3]   = 4*A[3] ^ 1*B[3] ^ 2*C[3] ^ 2*D[3]
 *
 *   result[4-7]   = 8*A[0-3] ^ ? ^ ? ^ ?
 *   result[8-11]  = ? ^ ? ^ ? ^ ?
 *   result[12-15] = ? ^ ? ^ ? ^ ?
 *
 *
 * @param[in] A, B, C, D - the four elements of a column (top to bottom) in bitsliced representation.
 * @returns the output column when performing the matrix multiplication of LED.
 */
bitsliced_column mix_single_column(const bitsliced_gfelement A, const bitsliced_gfelement B, const bitsliced_gfelement C, const bitsliced_gfelement D)
{
    bitsliced_column result;

    /**
        fourA.value[0] equals (4*A)[0]
        fourA.value[1] equals (4*A)[1]
        fourA.value[2] equals (4*A)[2]
        fourA.value[3] equals (4*A)[3]
    **/
    bitsliced_gfelement fourA = mc4(A);
    bitsliced_gfelement oneB  = mc1(B);
    bitsliced_gfelement twoC  = mc2(C);
    bitsliced_gfelement twoD  = mc2(D);

    bitsliced_gfelement eightA = mc8(A);
    bitsliced_gfelement sixB = mc6(B);
    bitsliced_gfelement fiveC = mc5(C);
    bitsliced_gfelement sixD = mc6(D);

    bitsliced_gfelement elevenA = mc11(A);
    bitsliced_gfelement fourteenB = mc14(B);
    bitsliced_gfelement tenC = mc10(C);
    bitsliced_gfelement nineD = mc9(D);

    bitsliced_gfelement twoA = mc2(A);
    bitsliced_gfelement twoB = mc2(B);
    bitsliced_gfelement fifteenC = mc15(C);
    bitsliced_gfelement elevenD = mc11(D);

    //xor sum
    for(int j=0; j < 4; j++) // 0,1,2,3
        result.value[j] = fourA.value[j] ^ oneB.value[j] ^ twoC.value[j] ^ twoD.value[j];
    for(int j=0; j < 4; j++)
        result.value[j + 4] = eightA.value[j] ^ sixB.value[j] ^ fiveC.value[j] ^ sixD.value[j];
    for(int j=0; j < 4; j++)
        result.value[j + 8] = elevenA.value[j] ^ fourteenB.value[j] ^ tenC.value[j] ^ nineD.value[j];
    for(int j=0; j < 4; j++)
        result.value[j + 12] = twoA.value[j] ^ twoB.value[j] ^ fifteenC.value[j] ^ elevenD.value[j];

    return result;
}

/**================================================
    Updates the whole bitsliced_column
================================================**/
void mix_columns_serial(bitsliced_state* state)
{
    bitsliced_gfelement col1A, col1B, col1C, col1D;
    bitsliced_gfelement col2A, col2B, col2C, col2D;
    bitsliced_gfelement col3A, col3B, col3C, col3D;
    bitsliced_gfelement col4A, col4B, col4C, col4D;

    bitsliced_column col1, col2, col3, col4;

    for (u8 i = 0; i < 4; i++)
    {
        col1A.value[i] = state->value[i];
        col1B.value[i] = state->value[16 + i];
        col1C.value[i] = state->value[32 + i];
        col1D.value[i] = state->value[48 + i];

        col2A.value[i] = state->value[4 + i];
        col2B.value[i] = state->value[20 + i];
        col2C.value[i] = state->value[36 + i];
        col2D.value[i] = state->value[52 + i];

        col3A.value[i] = state->value[8 + i];
        col3B.value[i] = state->value[24 + i];
        col3C.value[i] = state->value[40 + i];
        col3D.value[i] = state->value[56 + i];

        col4A.value[i] = state->value[12 + i];
        col4B.value[i] = state->value[28 + i];
        col4C.value[i] = state->value[44 + i];
        col4D.value[i] = state->value[60 + i];
    }

    col1 = mix_single_column(col1A, col1B, col1C, col1D);
    col2 = mix_single_column(col2A, col2B, col2C, col2D);
    col3 = mix_single_column(col3A, col3B, col3C, col3D);
    col4 = mix_single_column(col4A, col4B, col4C, col4D);

    /** update state after MixColumns **/
    for (u8 i = 0; i < 4; i++)
    {
        state->value[0 + i]  = col1.value[i];
        state->value[16 + i] = col1.value[4 + i];
        state->value[32 + i] = col1.value[8 + i];
        state->value[48 + i] = col1.value[12 + i];

        state->value[4 + i]  = col2.value[i];
        state->value[20 + i] = col2.value[4 + i];
        state->value[36 + i] = col2.value[8 + i];
        state->value[52 + i] = col2.value[12 + i];

        state->value[8 + i]  = col3.value[i];
        state->value[24 + i] = col3.value[4 + i];
        state->value[40 + i] = col3.value[8 + i];
        state->value[56 + i] = col3.value[12 + i];

        state->value[12 + i] = col4.value[i];
        state->value[28 + i] = col4.value[4 + i];
        state->value[44 + i] = col4.value[8 + i];
        state->value[60 + i] = col4.value[12 + i];
    }
}


// ########################################################################
// ENCRYPTION FUNCTION
// ########################################################################

/*
 * Encrypts a bitsliced state using LED-64-128.
 *
 * @param[inout] state - the state to encrypt
 * @param[in] key - the 128-bit key, split in two halves: K1 = key[0], K2 = key[1]
 */
void encrypt_bitsliced(bitsliced_state* state, const u64 key[2])
{
    int RN = 48;
    add_roundkey(state, key[0]);
    for (int i = 0; i < RN / 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            add_constants(state, i * 4 + j);
            sub_cells(state);
            shift_rows(state);
            mix_columns_serial(state);
        }
        add_roundkey(state, key[(i + 1) % 2]);
    }
}
