#include "../smtsolver.h"

static int g_fail = 0;

static void check(const char *name, int got, int want)
{
    printf("  [%s] %s: got=%d want=%d\n",
           (got == want) ? "PASS" : "FAIL", name, got, want);
    if (got != want) g_fail++;
}

static void check64(const char *name, su64 got, su64 want)
{
    printf("  [%s] %s: got=0x%llX want=0x%llX\n",
           (got == want) ? "PASS" : "FAIL", name,
           (unsigned long long)got, (unsigned long long)want);
    if (got != want) g_fail++;
}

int main(void)
{
    SmtCtx C;
    smt_init(&C);

    {
        su32 a = smt_var(&C, 32);
        su32 b = smt_var(&C, 32);
        su32 prod = smt_bin(&C, SM_MUL, a, b);
        su32 c15 = smt_const(&C, 32, 15);
        su32 eq = smt_bin(&C, SM_EQ, prod, c15);
        su32 one = smt_const(&C, 32, 1);
        su32 gt1a = smt_bin(&C, SM_UGT, a, one);
        su32 gt1b = smt_bin(&C, SM_UGT, b, one);
        su32 asserts[3] = { eq, gt1a, gt1b };
        su32 vars[2] = { a, b };
        su64 model[2];
        int r = smt_solve(&C, asserts, 3, vars, 2, model);
        check("factor15 sat", r == 1, 1);
        if (r == 1) {
            printf("    model: a=%llu b=%llu\n",
                   (unsigned long long)model[0], (unsigned long long)model[1]);
            check64("factor15 product", (model[0] * model[1]) & 0xFFFFFFFFULL, 15);
        }
    }

    {
        SmtCtx D;
        smt_init(&D);
        su32 p[4][3];
        su32 asserts[64];
        int na = 0;
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 3; j++)
                p[i][j] = smt_var(&D, 1);
        for (int i = 0; i < 4; i++) {
            su32 row = smt_bin(&D, SM_LOR, p[i][0],
                               smt_bin(&D, SM_LOR, p[i][1], p[i][2]));
            asserts[na++] = row;
        }
        for (int j = 0; j < 3; j++)
            for (int i1 = 0; i1 < 4; i1++)
                for (int i2 = i1 + 1; i2 < 4; i2++) {
                    su32 both = smt_bin(&D, SM_LAND, p[i1][j], p[i2][j]);
                    asserts[na++] = smt_lnot(&D, both);
                }
        int r = smt_solve(&D, asserts, na, NULL, 0, NULL);
        check("pigeonhole-4-3 unsat", r, 0);
        smt_free(&D);
    }

    {
        su32 x = smt_var(&C, 64);
        su32 sh = smt_const(&C, 64, 3);
        su32 shl = smt_bin(&C, SM_SHL, x, sh);
        su32 mul = smt_bin(&C, SM_MUL, x, smt_const(&C, 64, 8));
        su32 ne = smt_lnot(&C, smt_bin(&C, SM_EQ, shl, mul));
        int r = smt_solve(&C, &ne, 1, NULL, 0, NULL);
        check("shl3==mul8 unsat", r, 0);
    }

    {
        su32 x = smt_var(&C, 32);
        su32 y = smt_var(&C, 32);
        su32 sum = smt_bin(&C, SM_ADD, x, y);
        su32 a1 = smt_bin(&C, SM_EQ, sum, smt_const(&C, 32, 0x1234));
        su32 a2 = smt_bin(&C, SM_ULT, x, smt_const(&C, 32, 0x8000));
        su32 a3 = smt_bin(&C, SM_UGT, y, smt_const(&C, 32, 0x8000));
        su32 asserts[3] = { a1, a2, a3 };
        su32 vars[2] = { x, y };
        su64 model[2];
        int r = smt_solve(&C, asserts, 3, vars, 2, model);
        check("add-split sat", r == 1, 1);
        if (r == 1) {
            check64("add-split sum",
                    (model[0] + model[1]) & 0xFFFFFFFFULL, 0x1234);
            check("add-split x<0x8000", model[0] < 0x8000ULL, 1);
            check("add-split y>0x8000", model[1] > 0x8000ULL, 1);
        }
    }

    {
        su32 x = smt_var(&C, 16);
        su32 rol = smt_bin(&C, SM_ROL, x, smt_const(&C, 16, 5));
        su32 ror = smt_bin(&C, SM_ROR, rol, smt_const(&C, 16, 5));
        su32 ne = smt_lnot(&C, smt_bin(&C, SM_EQ, ror, x));
        int r = smt_solve(&C, &ne, 1, NULL, 0, NULL);
        check("rol5+ror5==id unsat", r, 0);
        su32 rol2 = smt_bin(&C, SM_ROL, x, smt_const(&C, 16, 4));
        su32 ror2 = smt_bin(&C, SM_ROR, rol2, smt_const(&C, 16, 12));
        su32 ne2 = smt_lnot(&C, smt_bin(&C, SM_EQ, ror2, x));
        int r2 = smt_solve(&C, &ne2, 1, NULL, 0, NULL);
        check("rol4+ror12!=id sat", r2, 1);
    }

    {
        su32 x = smt_var(&C, 8);
        su32 sx = smt_sext(&C, x, 32);
        su32 asserts[1];
        asserts[0] = smt_bin(&C, SM_EQ, sx, smt_const(&C, 32, 0xFFFFFF80));
        su32 vars[1] = { x };
        su64 model[1];
        int r = smt_solve(&C, asserts, 1, vars, 1, model);
        check("sext(-128) sat", r, 1);
        if (r == 1) check64("sext model==0x80", model[0], 0x80);
    }

    {
        su32 x = smt_var(&C, 32);
        su32 h = smt_extract(&C, x, 16, 16);
        su32 l = smt_extract(&C, x, 0, 16);
        su32 cat = smt_concat(&C, h, l);
        su32 ne = smt_lnot(&C, smt_bin(&C, SM_EQ, cat, x));
        int r = smt_solve(&C, &ne, 1, NULL, 0, NULL);
        check("extract+concat==id unsat", r, 0);
    }

    {
        su32 x = smt_var(&C, 32);
        su32 sub = smt_bin(&C, SM_SUB, smt_bin(&C, SM_ADD, x, smt_const(&C, 32, 7)), x);
        su32 ne = smt_lnot(&C, smt_bin(&C, SM_EQ, sub, smt_const(&C, 32, 7)));
        int r = smt_solve(&C, &ne, 1, NULL, 0, NULL);
        check("add7-sub-x==7 unsat", r, 0);
    }

    {
        su32 x = smt_var(&C, 16);
        su32 slt = smt_bin(&C, SM_SLT, x, smt_const(&C, 16, 1));
        su32 a1 = smt_bin(&C, SM_UGE, x, smt_const(&C, 16, 0x8000));
        su32 a2 = smt_lnot(&C, slt);
        su32 asserts[2] = { a1, a2 };
        int r = smt_solve(&C, asserts, 2, NULL, 0, NULL);
        check("signed-neg<1 unsat", r, 0);
    }

    {
        su32 x = smt_var(&C, 32);
        su32 c = smt_var(&C, 1);
        su32 ite = smt_ite(&C, c, x, smt_const(&C, 32, 0xDEAD0000));
        su32 a1 = smt_bin(&C, SM_EQ, ite, smt_const(&C, 32, 0xDEAD0000));
        su32 a2 = smt_lnot(&C, c);
        su32 a3 = smt_bin(&C, SM_EQ, x, smt_const(&C, 32, 0x777));
        su32 asserts[3] = { a1, a2, a3 };
        su32 vars[2] = { c, x };
        su64 model[2];
        int r = smt_solve(&C, asserts, 3, vars, 2, model);
        check("ite-else sat", r == 1, 1);
        if (r == 1) check64("ite model x", model[1], 0x777);
    }

    {
        su32 x = smt_var(&C, 64);
        su32 h1 = smt_extract(&C, x, 32, 32);
        su32 a1 = smt_bin(&C, SM_EQ, h1, smt_const(&C, 32, 0x12345678));
        su32 a2 = smt_bin(&C, SM_UGT, x, smt_const(&C, 64, 0));
        su32 asserts[2] = { a1, a2 };
        su32 vars[1] = { x };
        su64 model[1];
        int r = smt_solve(&C, asserts, 2, vars, 1, model);
        check("hi-bits sat", r == 1, 1);
        if (r == 1) check64("hi-bits model>>32", model[0] >> 32, 0x12345678);
    }

    {
        FILE *f = fopen("/tmp/smt_dump.smt2", "w");
        if (f) {
            fprintf(f, "(set-logic QF_BV)\n");
            su32 x = smt_const(&C, 8, 0x5A);
            su32 v = smt_var(&C, 8);
            su32 e = smt_bin(&C, SM_ADD, smt_bin(&C, SM_XOR, x, v),
                             smt_extract(&C, smt_concat(&C, v, x), 4, 8));
            fprintf(f, "(declare-fun vv () (_ BitVec 8))\n");
            smt_print_smt2(&C, e, f);
            fprintf(f, "\n");
            fclose(f);
            printf("  [PASS] smt2 print written\n");
        }
    }

    smt_free(&C);

    printf("%s: %d failure(s)\n", g_fail ? "RESULT FAIL" : "RESULT OK", g_fail);
    return g_fail ? 1 : 0;
}
