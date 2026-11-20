#include "smtsolver.h"

static su64 rng_state = 0x9E3779B97F4A7C15ULL;
static su64 rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static su64 mask_of(su32 w)
{
    return (w >= 64) ? ~0ULL : ((1ULL << w) - 1);
}

static su64 apply_op(int op, su64 a, su64 b, su32 w, su32 aw, su32 bw)
{
    su64 m = mask_of(w);
    switch (op) {
    case SM_ADD: return (a + b) & m;
    case SM_SUB: return (a - b) & m;
    case SM_MUL: return (a * b) & m;
    case SM_AND: return (a & b) & m;
    case SM_OR:  return (a | b) & m;
    case SM_XOR: return (a ^ b) & m;
    case SM_SHL: {
        su32 sh = (bw < 64) ? (su32)(b & mask_of(bw)) : (su32)b;
        if (sh >= w) return 0;
        return (a << sh) & m;
    }
    case SM_LSHR: {
        su32 sh = (bw < 64) ? (su32)(b & mask_of(bw)) : (su32)b;
        if (sh >= w) return 0;
        return (a >> sh) & m;
    }
    case SM_ASHR: {
        su32 sh = (bw < 64) ? (su32)(b & mask_of(bw)) : (su32)b;
        su64 sgn = (aw < 64 && ((a >> (aw - 1)) & 1)) ? (a | ~mask_of(aw)) : a;
        if (sh >= 64) sh = 63;
        return ((su64)(((ts64)sgn) >> sh)) & m;
    }
    case SM_ROL: {
        su32 sh = (bw < 64) ? (su32)(b & mask_of(bw)) : (su32)b;
        sh %= (w ? w : 1);
        if (!sh) return a & m;
        return (((a << sh) | (a >> (w - sh))) & m);
    }
    case SM_ROR: {
        su32 sh = (bw < 64) ? (su32)(b & mask_of(bw)) : (su32)b;
        sh %= (w ? w : 1);
        if (!sh) return a & m;
        return (((a >> sh) | (a << (w - sh))) & m);
    }
    default: return 0;
    }
}

int main(void)
{
    struct { const char *nm; int op; } ops[] = {
        {"add", SM_ADD}, {"sub", SM_SUB}, {"mul", SM_MUL},
        {"and", SM_AND}, {"or", SM_OR}, {"xor", SM_XOR},
        {"shl", SM_SHL}, {"lshr", SM_LSHR}, {"ashr", SM_ASHR},
        {"rol", SM_ROL}, {"ror", SM_ROR}
    };
    int bad = 0;
    for (unsigned t = 0; t < 400; t++) {
        su32 w = 4 + (su32)(rnd() % 5) * 4;
        su32 bw = w;
        if (bw > w) bw = w;
        su32 target = (su32)(rnd() & mask_of(w));
        su32 amask = (su32)(rnd() & mask_of(w));
        for (unsigned g = 0; g < sizeof(ops) / sizeof(ops[0]); g++) {
            SmtCtx C;
            smt_init(&C);
            su32 x = smt_var(&C, w);
            su32 y = smt_var(&C, bw);
            su32 rnode = smt_bin(&C, ops[g].op, x, y);
            su32 a1 = smt_bin(&C, SM_EQ, rnode, smt_const(&C, w, target));
            su32 a2 = smt_bin(&C, SM_EQ, smt_bin(&C, SM_AND, x, smt_const(&C, w, amask)),
                              smt_const(&C, w, 0));
            su32 asserts[2] = { a1, a2 };
            su32 vars[2] = { x, y };
            su64 model[2];
            int r = smt_solve(&C, asserts, 2, vars, 2, model);
            if (r == 1) {
                su64 mv = apply_op(ops[g].op, model[0],
                                   model[1],
                                   w, w, bw);
                su64 want = (target & mask_of(w));
                su64 xok = ((model[0] & amask) == 0);
                if (mv != want || !xok) {
                    printf("MISMATCH %s w=%u bw=%u target=%u amask=%u: model x=%llX y=%llX opres=%llX xmask=%llX\n",
                           ops[g].nm, w, bw, target, amask,
                           (unsigned long long)model[0],
                           (unsigned long long)model[1],
                           (unsigned long long)mv,
                           (unsigned long long)(model[0] & amask));
                    if (bad >= 3) { printf("stopping\n"); return 1; }
                    bad++;
                }
            } else if (r == 0) {
                int found = 0;
                for (su64 xv = 0; xv <= mask_of(w) && !found; xv++) {
                    if ((xv & amask) != 0) continue;
                    for (su64 yv = 0; yv <= mask_of(bw); yv++) {
                        if (apply_op(ops[g].op, xv, yv, w, w, bw) == (target & mask_of(w))) {
                            found = 1;
                            break;
                        }
                    }
                }
                if (found) {
                    printf("FALSE-UNSAT %s w=%u bw=%u target=%u amask=%u\n",
                           ops[g].nm, w, bw, target, amask);
                    bad++;
                }
            } else {
                printf("ERROR %s r=%d\n", ops[g].nm, r);
                bad++;
            }
            smt_free(&C);
        }
    }
    printf("diff-fuzz: %d mismatches\n", bad);
    return bad ? 1 : 0;
}
