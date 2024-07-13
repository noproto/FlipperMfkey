// This file was (mostly) automatically converted from MFKey on the Flipper Zero
// It is not optimized, do NOT use it for benchmarks. It is only to be used to test certain tricks with Crypto1.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define LF_POLY_ODD  (0x29CE5C)
#define LF_POLY_EVEN (0x870804)
#define CONST_M1_1 (LF_POLY_EVEN << 1 | 1)
#define CONST_M2_1 (LF_POLY_ODD << 1)
#define CONST_M1_2 (LF_POLY_ODD)
#define CONST_M2_2 (LF_POLY_EVEN << 1 | 1)
#define BIT(x, n) ((x) >> (n) & 1)
#define BEBIT(x, n) BIT(x, (n) ^ 24)
#define MSB_LIMIT 16
#define MAX_PATH_LEN 1024

#define SWAPENDIAN(x) (x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8, x = x >> 16 | x << 16)

struct Crypto1State {
    uint32_t odd, even;
};

struct Msb {
    int32_t tail;
    uint32_t states[768];
};

typedef struct {
    uint8_t data[6];
} MfClassicKey;

typedef enum { mfkey32, static_nested } AttackType;

typedef struct {
    AttackType attack;
    MfClassicKey key;
    uint32_t uid;
    uint32_t nt0;
    uint32_t nt1;
    uint32_t uid_xor_nt0;
    uint32_t uid_xor_nt1;
    uint32_t p64;
    uint32_t p64b;
    uint32_t nr0_enc;
    uint32_t ar0_enc;
    uint32_t nr1_enc;
    uint32_t ar1_enc;
    uint32_t ks1_1_enc;
    uint32_t ks1_2_enc;
    char par_1_str[5];
    char par_2_str[5];
    uint8_t par_1;
    uint8_t par_2;
} MfClassicNonce;

typedef struct {
    uint32_t total_nonces;
    MfClassicNonce* remaining_nonce_array;
    size_t remaining_nonces;
} MfClassicNonceArray;

uint32_t prng_successor(uint32_t x, uint32_t n) {
    SWAPENDIAN(x);
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return SWAPENDIAN(x);
}

static inline uint32_t filter(uint32_t const x) {
    uint32_t f;
    f  = 0xf22c0 >> (x       & 0xf) & 16;
    f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80A, f);
}

static inline uint8_t evenparity32(uint32_t x) {
    return __builtin_parity(x);
}

static inline void update_contribution(uint32_t data[], int32_t item, int32_t mask1, int32_t mask2) {
    int32_t p = data[item] >> 25;
    p = p << 1 | evenparity32(data[item] & mask1);
    p = p << 1 | evenparity32(data[item] & mask2);
    data[item] = p << 24 | (data[item] & 0xffffff);
}

void crypto1_get_lfsr(struct Crypto1State* state, MfClassicKey* lfsr) {
    int32_t i;
    uint64_t lfsr_value = 0;
    for(i = 23; i >= 0; --i) {
        lfsr_value = lfsr_value << 1 | BIT(state->odd, i ^ 3);
        lfsr_value = lfsr_value << 1 | BIT(state->even, i ^ 3);
    }

    for(i = 0; i < 6; ++i) {
        lfsr->data[i] = (lfsr_value >> ((5 - i) * 8)) & 0xFF;
    }
}

static inline uint32_t crypt_word(struct Crypto1State* s) {
    uint32_t res_ret = 0;
    uint32_t feedin, t;
    for(int32_t i = 0; i <= 31; i++) {
        res_ret |= (filter(s->odd) << (24 ^ i));
        feedin = LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
    }
    return res_ret;
}

static inline void crypt_word_noret(struct Crypto1State* s, uint32_t in, int32_t x) {
    uint8_t ret;
    uint32_t feedin, t, next_in;
    for(int32_t i = 0; i <= 31; i++) {
        next_in = BEBIT(in, i);
        ret = filter(s->odd);
        feedin = ret & (!!x);
        feedin ^= LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
    }
}

static inline uint32_t crypt_word_ret(struct Crypto1State* s, uint32_t in, int32_t x) {
    uint32_t ret = 0;
    uint32_t feedin, t, next_in;
    uint8_t next_ret;
    for(int32_t i = 0; i <= 31; i++) {
        next_in = BEBIT(in, i);
        next_ret = filter(s->odd);
        feedin = next_ret & (!!x);
        feedin ^= LF_POLY_EVEN & s->even;
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even = s->even << 1 | (evenparity32(feedin));
        t = s->odd, s->odd = s->even, s->even = t;
        ret |= next_ret << (24 ^ i);
    }
    return ret;
}

static inline void rollback_word_noret(struct Crypto1State* s, uint32_t in, int32_t x) {
    uint8_t ret;
    uint32_t feedin, t, next_in;
    for(int32_t i = 31; i >= 0; i--) {
        next_in = BEBIT(in, i);
        s->odd &= 0xffffff;
        t = s->odd, s->odd = s->even, s->even = t;
        ret = filter(s->odd);
        feedin = ret & (!!x);
        feedin ^= s->even & 1;
        feedin ^= LF_POLY_EVEN & (s->even >>= 1);
        feedin ^= LF_POLY_ODD & s->odd;
        feedin ^= !!next_in;
        s->even |= (evenparity32(feedin)) << 23;
    }
}

int32_t check_state(struct Crypto1State* t, MfClassicNonce* n) {
    if(!(t->odd | t->even)) return 0;
    if(n->attack == mfkey32) {
        rollback_word_noret(t, 0, 0);
        rollback_word_noret(t, n->nr0_enc, 1);
        rollback_word_noret(t, n->uid_xor_nt0, 0);
        struct Crypto1State temp = {t->odd, t->even};
        crypt_word_noret(t, n->uid_xor_nt1, 0);
        crypt_word_noret(t, n->nr1_enc, 1);
        if(n->ar1_enc == (crypt_word(t) ^ n->p64b)) {
            crypto1_get_lfsr(&temp, &(n->key));
            return 1;
        }
        return 0;
    } else if(n->attack == static_nested) {
        struct Crypto1State temp = {t->odd, t->even};
        rollback_word_noret(t, n->uid_xor_nt1, 0);
        if(n->ks1_1_enc == crypt_word_ret(t, n->uid_xor_nt0, 0)) {
            rollback_word_noret(&temp, n->uid_xor_nt1, 0);
            crypto1_get_lfsr(&temp, &(n->key));
            return 1;
        }
        return 0;
    }
    return 0;
}

static inline int32_t state_loop(uint32_t* states_buffer, int32_t xks, int32_t m1, int32_t m2, uint32_t in, uint8_t and_val) {
    int32_t states_tail = 0;
    int32_t round = 0, s = 0, xks_bit = 0, round_in = 0;

    for(round = 1; round <= 12; round++) {
        xks_bit = BIT(xks, round);
        if(round > 4) {
            round_in = ((in >> (2 * (round - 4))) & and_val) << 24;
        }

        for(s = 0; s <= states_tail; s++) {
            states_buffer[s] <<= 1;

            if((filter(states_buffer[s]) ^ filter(states_buffer[s] | 1)) != 0) {
                states_buffer[s] |= filter(states_buffer[s]) ^ xks_bit;
                if(round > 4) {
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s] ^= round_in;
                }
            } else if(filter(states_buffer[s]) == xks_bit) {
                if(round > 4) {
                    states_buffer[++states_tail] = states_buffer[s + 1];
                    states_buffer[s + 1] = states_buffer[s] | 1;
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s++] ^= round_in;
                    update_contribution(states_buffer, s, m1, m2);
                    states_buffer[s] ^= round_in;
                } else {
                    states_buffer[++states_tail] = states_buffer[++s];
                    states_buffer[s] = states_buffer[s - 1] | 1;
                }
            } else {
                states_buffer[s--] = states_buffer[states_tail--];
            }
        }
    }

    return states_tail;
}

int32_t binsearch(uint32_t data[], int32_t start, int32_t stop) {
    int32_t mid, val = data[stop] & 0xff000000;
    while(start != stop) {
        mid = (stop - start) >> 1;
        if((data[start + mid] ^ 0x80000000) > (val ^ 0x80000000))
            stop = start + mid;
        else
            start += mid + 1;
    }
    return start;
}

void quicksort(uint32_t array[], int32_t low, int32_t high) {
    if(low >= high) return;
    int32_t middle = low + (high - low) / 2;
    uint32_t pivot = array[middle];
    int32_t i = low, j = high;
    while(i <= j) {
        while(array[i] < pivot) {
            i++;
        }
        while(array[j] > pivot) {
            j--;
        }
        if(i <= j) {
            uint32_t temp = array[i];
            array[i] = array[j];
            array[j] = temp;
            i++;
            j--;
        }
    }
    if(low < j) {
        quicksort(array, low, j);
    }
    if(high > i) {
        quicksort(array, i, high);
    }
}

int32_t extend_table(uint32_t data[], int32_t tbl, int32_t end, int32_t bit, int32_t m1, int32_t m2, uint32_t in) {
    in <<= 24;
    for(data[tbl] <<= 1; tbl <= end; data[++tbl] <<= 1) {
        if((filter(data[tbl]) ^ filter(data[tbl] | 1)) != 0) {
            data[tbl] |= filter(data[tbl]) ^ bit;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= in;
        } else if(filter(data[tbl]) == bit) {
            data[++end] = data[tbl + 1];
            data[tbl + 1] = data[tbl] | 1;
            update_contribution(data, tbl, m1, m2);
            data[tbl++] ^= in;
            update_contribution(data, tbl, m1, m2);
            data[tbl] ^= in;
        } else {
            data[tbl--] = data[end--];
        }
    }
    return end;
}

int32_t old_recover(uint32_t odd[], int32_t o_head, int32_t o_tail, int32_t oks, uint32_t even[], int32_t e_head, int32_t e_tail, int32_t eks, int32_t rem, int32_t s, MfClassicNonce* n, uint32_t in, int32_t first_run) {
    int32_t o, e, i;
    if(rem == -1) {
        for(e = e_head; e <= e_tail; ++e) {
            even[e] = (even[e] << 1) ^ evenparity32(even[e] & LF_POLY_EVEN) ^ (!!(in & 4));
            for(o = o_head; o <= o_tail; ++o, ++s) {
                struct Crypto1State temp = {0, 0};
                temp.even = odd[o];
                temp.odd = even[e] ^ evenparity32(odd[o] & LF_POLY_ODD);
                if(check_state(&temp, n)) {
                    return -1;
                }
            }
        }
        return s;
    }
    if(first_run == 0) {
        for(i = 0; (i < 4) && (rem-- != 0); i++) {
            oks >>= 1;
            eks >>= 1;
            in >>= 2;
            o_tail = extend_table(odd, o_head, o_tail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0);
            if(o_head > o_tail) return s;
            e_tail = extend_table(even, e_head, e_tail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, in & 3);
            if(e_head > e_tail) return s;
        }
    }
    quicksort(odd, o_head, o_tail);
    quicksort(even, e_head, e_tail);
    while(o_tail >= o_head && e_tail >= e_head) {
        if(((odd[o_tail] ^ even[e_tail]) >> 24) == 0) {
            o_tail = binsearch(odd, o_head, o = o_tail);
            e_tail = binsearch(even, e_head, e = e_tail);
            s = old_recover(odd, o_tail--, o, oks, even, e_tail--, e, eks, rem, s, n, in, 0);
            if(s == -1) {
                break;
            }
        } else if((odd[o_tail] ^ 0x80000000) > (even[e_tail] ^ 0x80000000)) {
            o_tail = binsearch(odd, o_head, o_tail) - 1;
        } else {
            e_tail = binsearch(even, e_head, e_tail) - 1;
        }
    }
    return s;
}

int32_t calculate_msb_tables(int32_t oks, int32_t eks, int32_t msb_round, MfClassicNonce* n, uint32_t* states_buffer, struct Msb* odd_msbs, struct Msb* even_msbs, uint32_t* temp_states_odd, uint32_t* temp_states_even, uint32_t in) {
    uint32_t msb_head = (MSB_LIMIT * msb_round);
    uint32_t msb_tail = (MSB_LIMIT * (msb_round + 1));
    int32_t states_tail = 0, tail = 0;
    int32_t i = 0, j = 0, semi_state = 0, found = 0;
    uint32_t msb = 0;
    in = ((in >> 16 & 0xff) | (in << 16) | (in & 0xff00)) << 1;

    memset(odd_msbs, 0, MSB_LIMIT * sizeof(struct Msb));
    memset(even_msbs, 0, MSB_LIMIT * sizeof(struct Msb));

    for(semi_state = 1 << 20; semi_state >= 0; semi_state--) {
        if(filter(semi_state) == (oks & 1)) {
            states_buffer[0] = semi_state;
            states_tail = state_loop(states_buffer, oks, CONST_M1_1, CONST_M2_1, 0, 0);

            for(i = states_tail; i >= 0; i--) {
                msb = states_buffer[i] >> 24;
                if((msb >= msb_head) && (msb < msb_tail)) {
                    found = 0;
                    for(j = 0; j < odd_msbs[msb - msb_head].tail - 1; j++) {
                        if(odd_msbs[msb - msb_head].states[j] == states_buffer[i]) {
                            found = 1;
                            break;
                        }
                    }

                    if(!found) {
                        tail = odd_msbs[msb - msb_head].tail++;
                        odd_msbs[msb - msb_head].states[tail] = states_buffer[i];
                    }
                }
            }
        }

        if(filter(semi_state) == (eks & 1)) {
            states_buffer[0] = semi_state;
            states_tail = state_loop(states_buffer, eks, CONST_M1_2, CONST_M2_2, in, 3);

            for(i = 0; i <= states_tail; i++) {
                msb = states_buffer[i] >> 24;
                if((msb >= msb_head) && (msb < msb_tail)) {
                    found = 0;

                    for(j = 0; j < even_msbs[msb - msb_head].tail; j++) {
                        if(even_msbs[msb - msb_head].states[j] == states_buffer[i]) {
                            found = 1;
                            break;
                        }
                    }

                    if(!found) {
                        tail = even_msbs[msb - msb_head].tail++;
                        even_msbs[msb - msb_head].states[tail] = states_buffer[i];
                    }
                }
            }
        }
    }

    oks >>= 12;
    eks >>= 12;

    for(i = 0; i < MSB_LIMIT; i++) {
        memset(temp_states_even, 0, sizeof(uint32_t) * 1280);
        memset(temp_states_odd, 0, sizeof(uint32_t) * 1280);
        memcpy(temp_states_odd, odd_msbs[i].states, odd_msbs[i].tail * sizeof(uint32_t));
        memcpy(temp_states_even, even_msbs[i].states, even_msbs[i].tail * sizeof(uint32_t));
        int32_t res = old_recover(temp_states_odd, 0, odd_msbs[i].tail, oks, temp_states_even, 0, even_msbs[i].tail, eks, 3, 0, n, in >> 16, 1);
        if(res == -1) {
            return 1;
        }
    }

    return 0;
}

bool recover(MfClassicNonce* n, int32_t ks2, uint32_t in) {
    bool found = false;
    uint32_t* states_buffer = malloc(sizeof(uint32_t) * (2 << 9));
    struct Msb* odd_msbs = malloc(MSB_LIMIT * sizeof(struct Msb));
    struct Msb* even_msbs = malloc(MSB_LIMIT * sizeof(struct Msb));
    uint32_t* temp_states_odd = malloc(sizeof(uint32_t) * 1280);
    uint32_t* temp_states_even = malloc(sizeof(uint32_t) * 1280);
    int32_t oks = 0, eks = 0;
    int32_t i = 0, msb = 0;

    for(i = 31; i >= 0; i -= 2) {
        oks = oks << 1 | BEBIT(ks2, i);
    }
    for(i = 30; i >= 0; i -= 2) {
        eks = eks << 1 | BEBIT(ks2, i);
    }

    for(msb = 0; msb <= ((256 / MSB_LIMIT) - 1); msb++) {
        if(calculate_msb_tables(oks, eks, msb, n, states_buffer, odd_msbs, even_msbs, temp_states_odd, temp_states_even, in)) {
            found = true;
            break;
        }
    }

    free(states_buffer);
    free(odd_msbs);
    free(even_msbs);
    free(temp_states_odd);
    free(temp_states_even);
    return found;
}

MfClassicNonceArray* load_nonces(const char* directory) {
    MfClassicNonceArray* nonce_array = malloc(sizeof(MfClassicNonceArray));
    nonce_array->remaining_nonce_array = NULL;
    nonce_array->remaining_nonces = 0;
    nonce_array->total_nonces = 0;

    DIR* dir;
    struct dirent* ent;
    char filepath[MAX_PATH_LEN];

    // Load Mfkey32 nonces
    FILE* file = fopen(".mfkey32.log", "r");
    if(file) {
        char line[256];
        while(fgets(line, sizeof(line), file)) {
            if(strncmp(line, "Sec", 3) == 0) {
                MfClassicNonce nonce = {0};
                nonce.attack = mfkey32;
                int parsed = sscanf(line,
                    "%*s %*s %*s %*s cuid %x nt0 %x nr0 %x ar0 %x nt1 %x nr1 %x ar1 %x",
                    &nonce.uid, &nonce.nt0, &nonce.nr0_enc, &nonce.ar0_enc,
                    &nonce.nt1, &nonce.nr1_enc, &nonce.ar1_enc);

                if(parsed == 7) {  // Ensure we parsed all 7 values
                    nonce.p64 = prng_successor(nonce.nt0, 64);
                    nonce.p64b = prng_successor(nonce.nt1, 64);
                    nonce.uid_xor_nt0 = nonce.uid ^ nonce.nt0;
                    nonce.uid_xor_nt1 = nonce.uid ^ nonce.nt1;

                    nonce_array->remaining_nonce_array = realloc(nonce_array->remaining_nonce_array,
                                                                 sizeof(MfClassicNonce) * (nonce_array->remaining_nonces + 1));
                    nonce_array->remaining_nonce_array[nonce_array->remaining_nonces] = nonce;
                    nonce_array->remaining_nonces++;
                    nonce_array->total_nonces++;
                }
            }
        }
        fclose(file);
    }

    // Load Nested nonces
    if((dir = opendir(".nested")) != NULL) {
        while((ent = readdir(dir)) != NULL) {
            if(strstr(ent->d_name, ".nonces") != NULL) {
                snprintf(filepath, sizeof(filepath), ".nested/%s", ent->d_name);
                file = fopen(filepath, "r");
                if(file) {
                    char line[256];
                    while(fgets(line, sizeof(line), file)) {
                        if(strncmp(line, "Nested:", 7) == 0) {
                            MfClassicNonce nonce = {0};
                            nonce.attack = static_nested;
                            sscanf(line, "Nested: %*s %*s cuid 0x%x nt0 0x%x ks0 0x%x par0 %4s nt1 0x%x ks1 0x%x par1 %4s",
                                   &nonce.uid, &nonce.nt0, &nonce.ks1_1_enc, nonce.par_1_str,
                                   &nonce.nt1, &nonce.ks1_2_enc, nonce.par_2_str);
                            nonce.par_1 = (uint8_t)strtol(nonce.par_1_str, NULL, 2);
                            nonce.par_2 = (uint8_t)strtol(nonce.par_2_str, NULL, 2);
                            nonce.uid_xor_nt0 = nonce.uid ^ nonce.nt0;
                            nonce.uid_xor_nt1 = nonce.uid ^ nonce.nt1;

                            nonce_array->remaining_nonce_array = realloc(nonce_array->remaining_nonce_array,
                                                                         sizeof(MfClassicNonce) * (nonce_array->remaining_nonces + 1));
                            nonce_array->remaining_nonce_array[nonce_array->remaining_nonces] = nonce;
                            nonce_array->remaining_nonces++;
                            nonce_array->total_nonces++;
                        }
                    }
                    fclose(file);
                }
            }
        }
        closedir(dir);
    }

    return nonce_array;
}

void free_nonces(MfClassicNonceArray* nonce_array) {
    if(nonce_array) {
        free(nonce_array->remaining_nonce_array);
        free(nonce_array);
    }
}

void mfkey() {
    MfClassicKey found_key;
    size_t keyarray_size = 0;
    MfClassicKey* keyarray = malloc(sizeof(MfClassicKey));

    MfClassicNonceArray* nonce_arr = load_nonces(".");
    if(nonce_arr->total_nonces == 0) {
        printf("No nonces found.\n");
        free_nonces(nonce_arr);
        free(keyarray);
        return;
    }

    printf("Total nonces: %u\n", nonce_arr->total_nonces);

    for(uint32_t i = 0; i < nonce_arr->total_nonces; i++) {
        MfClassicNonce* next_nonce = &nonce_arr->remaining_nonce_array[i];
        printf("Processing nonce %u/%u\n", i+1, nonce_arr->total_nonces);

        bool key_found = false;
        if(next_nonce->attack == mfkey32) {
            key_found = recover(next_nonce, next_nonce->ar0_enc ^ next_nonce->p64, 0);
        } else if(next_nonce->attack == static_nested) {
            key_found = recover(next_nonce, next_nonce->ks1_2_enc, next_nonce->nt1 ^ next_nonce->uid);
        }

        if(key_found) {
            found_key = next_nonce->key;
            bool already_found = false;
            for(size_t j = 0; j < keyarray_size; j++) {
                if(memcmp(keyarray[j].data, found_key.data, sizeof(MfClassicKey)) == 0) {
                    already_found = true;
                    break;
                }
            }
            if(!already_found) {
                keyarray = realloc(keyarray, sizeof(MfClassicKey) * (keyarray_size + 1));
                keyarray[keyarray_size] = found_key;
                keyarray_size++;
            }
            printf("Key found for UID: %08x\n", next_nonce->uid);
            printf("Key: ");
            for(int j = 0; j < 6; j++) {
                printf("%02x", next_nonce->key.data[j]);
            }
            printf("\n");
        } else {
            printf("No key found for UID: %08x\n", next_nonce->uid);
        }
    }

    printf("Unique keys found: %zu\n", keyarray_size);
    for(size_t i = 0; i < keyarray_size; i++) {
        printf("Key %zu: ", i+1);
        for(int j = 0; j < 6; j++) {
            printf("%02x", keyarray[i].data[j]);
        }
        printf("\n");
    }

    free_nonces(nonce_arr);
    free(keyarray);
}

int main() {
    printf("MFKey for Linux\n");
    mfkey();
    return 0;
}
