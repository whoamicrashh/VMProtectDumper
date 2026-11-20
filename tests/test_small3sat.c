#include "smtsolver.h"

static su64 rng_state = 88172645463325252ULL;
static su64 rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

int main(void)
{
    for (int t = 0; t < 3000; t++) {
        int nv = 5 + (int)(rnd() % 4);
        int nc = 3 + (int)(rnd() % 8);
        int lits[64][3];
        for (int c = 0; c < nc; c++)
            for (int j = 0; j < 3; j++)
                lits[c][j] = (int)(rnd() % nv) * 2 + (int)(rnd() & 1);

        int expect = 0;
        for (int msk = 0; msk < (1 << nv); msk++) {
            int ok = 1;
            for (int c = 0; c < nc && ok; c++) {
                int sat_c = 0;
                for (int j = 0; j < 3; j++) {
                    int lit = lits[c][j];
                    int av = (msk >> (lit >> 1)) & 1;
                    if ((lit & 1) ? !av : av) { sat_c = 1; break; }
                }
                if (!sat_c) ok = 0;
            }
            if (ok) { expect = 1; break; }
        }

        SmtCtx C;
        smt_init(&C);
        su32 vars[8];
        for (int i = 0; i < nv; i++) vars[i] = smt_var(&C, 1);
        su32 asserts[64];
        for (int c = 0; c < nc; c++) {
            su32 a = smt_const(&C, 1, 0);
            for (int j = 0; j < 3; j++) {
                int lit = lits[c][j];
                su32 v = vars[lit >> 1];
                su32 litnode = (lit & 1) ? smt_lnot(&C, v) : v;
                a = (j == 0) ? litnode : smt_bin(&C, SM_LOR, a, litnode);
            }
            asserts[c] = a;
        }
        int r = smt_solve(&C, asserts, nc, NULL, 0, NULL);
        if ((r == 1) != (expect == 1)) {
            printf("TRIAL %d nv=%d nc=%d brute=%d solver=%d\n", t, nv, nc, expect, r);
            for (int c = 0; c < nc; c++)
                printf("  cl%d: %d %d %d\n", c, lits[c][0], lits[c][1], lits[c][2]);
            smt_free(&C);
            return 1;
        }
        if (r < 0) {
            printf("TRIAL %d solver error %d\n", t, r);
            smt_free(&C);
            return 1;
        }
        smt_free(&C);
    }
    printf("small-3sat: all ok\n");
    return 0;
}
