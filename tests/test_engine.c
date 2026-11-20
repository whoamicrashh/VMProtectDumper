#include <sys/stat.h>
#include <stdlib.h>
#include "shim/windows.h"
#include "../vmpd.h"
#include "../smtengine.h"

char g_output_dir[MAX_PATH] = "/tmp/smt_eng_test";
int   g_no_smt = 0;
WORD g_machine = 0x8664;
DWORD64 g_image_base = 0x400000ULL;
DWORD g_size_of_image = 0x10000;
volatile LONG g_import_count = 0;
int   g_iat_slot_count = 0;
int   g_resolved_iat_count = 0;

ImportEntry g_imports[MAX_IMPORTS];
IATSlotEntry g_iat_slots[MAX_IAT_SLOTS];

long g_smt_resolved = -1;
long g_smt_unresolved = 0;
long g_smt_already_real = 0;
long g_smt_collatz = 0;
long g_smt_bombs = 0;
unsigned long long g_smt_instr = 0;

static const char *tget_basename(const char *path)
{
    const char *sl = strrchr(path, '/');
    const char *bs = strrchr(path, '\\');
    const char *p = (sl > bs) ? sl : bs;
    return p ? p + 1 : path;
}

const char *get_basename(const char *path)
{
    return tget_basename(path);
}

int rewrite_resolved_imports_report(void)
{
    return 0;
}

DWORD GetFileAttributesA(LPCSTR path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return INVALID_FILE_ATTRIBUTES;
    fclose(f);
    return FILE_ATTRIBUTE_NORMAL;
}

static BYTE g_dump[0x10000];

static void wr64(BYTE *p, tu64 v)
{
    for (int i = 0; i < 8; i++) p[i] = (BYTE)((v >> (8 * i)) & 0xFF);
}

static void wr32(BYTE *p, tu32 v)
{
    p[0] = (BYTE)(v & 0xFF);
    p[1] = (BYTE)((v >> 8) & 0xFF);
    p[2] = (BYTE)((v >> 16) & 0xFF);
    p[3] = (BYTE)((v >> 24) & 0xFF);
}

static void wr16(BYTE *p, tu16 v)
{
    p[0] = (BYTE)(v & 0xFF);
    p[1] = (BYTE)((v >> 8) & 0xFF);
}

static void put_pe_header(BYTE *img)
{
    memset(img, 0, 0x400);
    img[0] = 'M';
    img[1] = 'Z';
    wr32(img + 0x3C, 0x80);
    img[0x80] = 'P';
    img[0x81] = 'E';
    img[0x82] = 0;
    img[0x83] = 0;
    wr16(img + 0x84, 0x8664);
    wr16(img + 0x86, 1);
    wr32(img + 0x88, 0);
    wr32(img + 0x8C, 0);
    wr16(img + 0x94, 240);
    wr16(img + 0x98, 0x20B);
    wr32(img + 0xA8, 0x1000);
    wr32(img + 0xB8, 0x1000);
    wr32(img + 0xBC, 0x200);
    wr64(img + 0xB0, 0x400000);
    wr32(img + 0xD0, 0x10000);
    wr32(img + 0xD4, 0x400);
    wr16(img + 0x86, 1);
    {
        BYTE *sh = img + 0x188;
        memcpy(sh, ".flat", 5);
        wr32(sh + 8, 0x10000);
        wr32(sh + 12, 0);
        wr32(sh + 16, 0x10000);
        wr32(sh + 20, 0);
        wr32(sh + 36, 0xE0000060);
    }
}

#define SLOT_RVA   0x3000
#define STUB_RVA   0x2000
#define BLOB_RVA   0x2800

static void build_dump(void)
{
    memset(g_dump, 0, sizeof(g_dump));
    put_pe_header(g_dump);

    BYTE *stub = g_dump + STUB_RVA;
    stub[0] = 0x48;
    stub[1] = 0xB8;
    wr64(stub + 2, 0x7FF800001234ULL);
    stub[10] = 0xC3;

    BYTE *blob = g_dump + BLOB_RVA;
    wr16(blob, 77);
    memcpy(blob + 2, "CreateFileW", 11);
    blob[13] = 0;

    BYTE *sse = g_dump + 0x2400;
    sse[0] = 0x0F;
    sse[1] = 0x28;
    sse[2] = 0x44;
    sse[3] = 0x24;
    sse[4] = 0x10;
    sse[5] = 0xC3;

    BYTE *br = g_dump + 0x2600;
    br[0] = 0x48;
    br[1] = 0x39;
    br[2] = 0xC1;
    br[3] = 0x75;
    br[4] = 0x05;
    br[5] = 0x48;
    br[6] = 0xC7;
    br[7] = 0xC0;
    br[8] = 0x40;
    br[9] = 0x50;
    br[10] = 0x60;
    br[11] = 0x70;
    br[12] = 0xC3;
    br[13] = 0x48;
    br[14] = 0xC7;
    br[15] = 0xC0;
    br[16] = 0x11;
    br[17] = 0x22;
    br[18] = 0x33;
    br[19] = 0x44;
    br[20] = 0xC3;

    BYTE *lv = g_dump + 0x2A00;
    lv[0] = 0x55;
    lv[1] = 0x48; lv[2] = 0x89; lv[3] = 0xE5;
    lv[4] = 0x48; lv[5] = 0xC7; lv[6] = 0xC0; lv[7] = 0x34; lv[8] = 0x12;
    lv[9] = 0; lv[10] = 0;
    lv[11] = 0xC9;
    lv[12] = 0xC3;

    BYTE *sse2 = g_dump + 0x2A40;
    sse2[0] = 0x48; sse2[1] = 0xB8;
    wr64(sse2 + 2, g_image_base + 0x2C00);
    sse2[10] = 0xF3; sse2[11] = 0x0F; sse2[12] = 0x6F; sse2[13] = 0x08;
    sse2[14] = 0x66; sse2[15] = 0x0F; sse2[16] = 0xEF; sse2[17] = 0xC9;
    sse2[18] = 0xF3; sse2[19] = 0x0F; sse2[20] = 0x7F; sse2[21] = 0x48;
    sse2[22] = 0x10;
    sse2[23] = 0x48; sse2[24] = 0x8B; sse2[25] = 0x40; sse2[26] = 0x10;
    sse2[27] = 0xC3;

    BYTE *rmv = g_dump + 0x2B00;
    rmv[0] = 0x48; rmv[1] = 0xBE;
    wr64(rmv + 2, g_image_base + 0x2D00);
    rmv[10] = 0x48; rmv[11] = 0xBF;
    wr64(rmv + 12, g_image_base + 0x2D80);
    rmv[20] = 0x48; rmv[21] = 0xB9;
    wr64(rmv + 22, 8);
    rmv[30] = 0xFC;
    rmv[31] = 0xF3; rmv[32] = 0x48; rmv[33] = 0xA5;
    rmv[34] = 0x48; rmv[35] = 0xBB;
    wr64(rmv + 36, g_image_base + 0x2D80);
    rmv[44] = 0x48; rmv[45] = 0x8B; rmv[46] = 0x03;
    rmv[47] = 0xC3;

    BYTE *lp = g_dump + 0x2B40;
    lp[0] = 0x48; lp[1] = 0xC7; lp[2] = 0xC1; lp[3] = 0x40; lp[4] = 0;
    lp[5] = 0; lp[6] = 0;
    lp[7] = 0x48; lp[8] = 0xC7; lp[9] = 0xC0; lp[10] = 0; lp[11] = 0;
    lp[12] = 0; lp[13] = 0;
    lp[14] = 0x48; lp[15] = 0xFF; lp[16] = 0xC0;
    lp[17] = 0xE2; lp[18] = 0xFB;
    lp[19] = 0xC3;

    for (int i = 0; i < 16; i++) {
        g_dump[0x2C00 + i] = 0xAB;
        g_dump[0x2C10 + i] = 0xCC;
        g_dump[0x2D00 + i] = 0x11;
    }
    wr64(g_dump + 0x2D00, 0xDEADBEEFCAFE1234ULL);

    BYTE *slots = g_dump + SLOT_RVA;
    wr64(slots, g_image_base + STUB_RVA);
    wr64(slots + 0x10, g_image_base + BLOB_RVA);
    wr64(slots + 0x20, g_image_base + 0x2400);
    wr64(slots + 0x30, g_image_base + 0x2600);
    wr64(slots + 0x40, g_image_base + 0x2A00);
    wr64(slots + 0x50, g_image_base + 0x2A40);
    wr64(slots + 0x60, g_image_base + 0x2B00);
    wr64(slots + 0x70, g_image_base + 0x2B40);

    FILE *f = fopen("/tmp/smt_eng_test/target_dumped.bin", "wb");
    if (!f) {
        mkdir("/tmp/smt_eng_test", 0755);
        f = fopen("/tmp/smt_eng_test/target_dumped.bin", "wb");
    }
    if (!f) { printf("[-] cannot create /tmp/smt_eng_test\n"); exit(2); }
    fwrite(g_dump, 1, sizeof(g_dump), f);
    fclose(f);
}

int main(void)
{
    build_dump();

    g_import_count = 1;
    strcpy(g_imports[0].module, "kernel32.dll");
    strcpy(g_imports[0].function, "CreateFileW");
    g_imports[0].resolved_addr = 0x7FF800001234ULL;

    g_iat_slot_count = 4;
    g_iat_slots[0].slot_rva = SLOT_RVA;
    g_iat_slots[0].import_idx = 0;
    g_iat_slots[1].slot_rva = SLOT_RVA + 0x10;
    g_iat_slots[1].import_idx = 0;
    g_iat_slots[2].slot_rva = SLOT_RVA + 0x20;
    g_iat_slots[2].import_idx = -1;

    g_resolved_iat_count = 0;

    SmtCatalogEntry cat;
    memset(&cat, 0, sizeof(cat));
    strcpy(cat.module, "kernel32.dll");
    strcpy(cat.function, "CreateFileW");
    cat.addr = 0x7FF800001234ULL;

    SmtContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.image_base = g_image_base;
    ctx.image_size = g_size_of_image;
    ctx.machine = g_machine;
    ctx.ep_rva = 0x1000;
    strcpy(ctx.dump_path, "/tmp/smt_eng_test/target_dumped.bin");
    strcpy(ctx.output_dir, g_output_dir);
    strcpy(ctx.target_name, "target.exe");
    ctx.catalog = &cat;
    ctx.catalog_count = 1;
    static tu32 slots[8];
    slots[0] = SLOT_RVA;
    slots[1] = SLOT_RVA + 0x10;
    slots[2] = SLOT_RVA + 0x20;
    slots[3] = SLOT_RVA + 0x40;
    slots[4] = SLOT_RVA + 0x50;
    slots[5] = SLOT_RVA + 0x60;
    slots[6] = SLOT_RVA + 0x70;
    slots[7] = SLOT_RVA + 0x30;
    ctx.slot_rvas = slots;
    ctx.slot_count = 8;
    ctx.trace_enabled = 1;

    int r = smt_engine_run(&ctx);
    printf("engine result=%d fixes=%d\n", r, ctx.fix_count);
    for (int i = 0; i < ctx.fix_count; i++)
        printf("  fix slot=0x%08X addr=0x%llX name=%s\n",
               ctx.fixes[i].slot_rva,
               (unsigned long long)ctx.fixes[i].resolved_addr,
               ctx.fixes[i].name);

    FILE *smt2 = fopen("/tmp/smt_eng_test/smt_queries.smt2", "r");
    int smt2_ok = smt2 && fseek(smt2, 0, SEEK_END) >= 0 && ftell(smt2) > 0;
    if (smt2) fclose(smt2);

    FILE *tr = fopen("/tmp/smt_eng_test/smt_trace.txt", "r");
    int trace_ok = tr && fseek(tr, 0, SEEK_END) >= 0 && ftell(tr) > 0;
    if (tr) fclose(tr);

    int rep_ok = 0, no_sse_abort = 0, no_new_aborts = 0, loop_iters = 0,
        leave_rax = 0, repmovs_magic = 0, final_model = 0;
    tr = fopen("/tmp/smt_eng_test/smt_trace.txt", "r");
    if (tr) {
        char ln[512];
        while (fgets(ln, sizeof(ln), tr)) {
            if (strstr(ln, "[rep movs] 8 x 8")) rep_ok = 1;
            if (strstr(ln, "decode abort at 0x402A40")) no_sse_abort = 1;
            if (strstr(ln, "decode abort at 0x402B00") ||
                strstr(ln, "decode abort at 0x402B40") ||
                strstr(ln, "decode abort at 0x402A00")) no_new_aborts = 1;
            if (strstr(ln, "402B4E")) loop_iters++;
            if (strstr(ln, "STUB 0x402A00 STOP: returned to sentinel") &&
                strstr(ln, "rax=0000000000001234")) leave_rax = 1;
            if (strstr(ln, "final model")) final_model = 1;
        }
        fclose(tr);
    }
    FILE *jf2 = fopen("/tmp/smt_eng_test/smt_iat.json", "r");
    if (jf2) {
        char ln[512];
        while (fgets(ln, sizeof(ln), jf2))
            if (strstr(ln, "0xDEADBEEFCAFE1234")) repmovs_magic = 1;
        fclose(jf2);
    }
    printf("new-ops: rep=%d sse_no_abort=%d no_new_aborts=%d loop_iters=%d "
           "leave_rax=%d repmovs_magic=%d\n",
           rep_ok, !no_sse_abort, !no_new_aborts, loop_iters, leave_rax,
           repmovs_magic);
    int smt2_sat = 0;
    smt2 = fopen("/tmp/smt_eng_test/smt_queries.smt2", "r");
    if (smt2) {
        char ln[512];
        while (fgets(ln, sizeof(ln), smt2))
            if (strstr(ln, "(check-sat)")) smt2_sat++;
        fclose(smt2);
    }
    printf("smt2_file=%s trace_file=%s final_model=%d check_sat=%d\n",
           smt2_ok ? "OK" : "MISSING", trace_ok ? "OK" : "MISSING",
           final_model, smt2_sat);

    int fail = 0;
    if (!(r >= 1)) { printf("FAIL: expected >=1 resolved\n"); fail = 1; }
    if (!ctx.fix_count) { printf("FAIL: expected fixes\n"); fail = 1; }
    if (!smt2_ok) { printf("FAIL: smt2 file missing/empty\n"); fail = 1; }
    if (!trace_ok) { printf("FAIL: trace missing/empty\n"); fail = 1; }
    if (!final_model) { printf("FAIL: solver final model missing\n"); fail = 1; }
    if (!smt2_sat) { printf("FAIL: no check-sat queries emitted\n"); fail = 1; }
    if (!rep_ok) { printf("FAIL: rep movs not traced\n"); fail = 1; }
    if (no_sse_abort) { printf("FAIL: SSE stub still aborts\n"); fail = 1; }
    if (no_new_aborts) { printf("FAIL: new-op stubs abort decode\n"); fail = 1; }
    if (loop_iters < 64) { printf("FAIL: loop body executed %d (<64) times\n", loop_iters); fail = 1; }
    if (!leave_rax) { printf("FAIL: leave stub rax wrong\n"); fail = 1; }
    if (!repmovs_magic) { printf("FAIL: rep movsq did not copy magic qword\n"); fail = 1; }
    printf("ENGINE %s\n", fail ? "FAIL" : "PASS");
    return fail;
}
