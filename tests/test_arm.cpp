// ArmPattern tests. Exit code 0 = pass. Build with tests/CMakeLists.txt.
// The encoder and /d are checked on every platform against encodings produced by clang's assembler. On Apple arm64
// the test also re-assembles every table line to confirm the tables, and resolves /d on linker-relocated code.
#include <PatternScanner/ArmXORPattern.hpp>
#include <PatternScanner/RuntimeArmPattern.hpp>
#include <cstdio>
#include <cstdlib>

#define CHECK(x) do { if (!(x)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

// Fully specified instruction -> its encoding. The pattern must be exactly the encoding, every bit masked
#define CONCRETE(X) \
    X("NOP",                         0xD503201F) \
    X("STP X20, X19, [SP,#-0x20]!",  0xA9BE4FF4) \
    X("STP X29, X30, [SP,#0x10]",    0xA9017BFD) \
    X("STP X29, X30, [SP],#0x10",    0xA8817BFD) \
    X("STP W1, W2, [X0,#8]",         0x29010801) \
    X("LDP X29, X30, [SP,#0x10]",    0xA9417BFD) \
    X("MOV X19, X1",                 0xAA0103F3) \
    X("MOV X0, X30",                 0xAA1E03E0) \
    X("MOV W0, W1",                  0x2A0103E0) \
    X("MOV X29, SP",                 0x910003FD) \
    X("MOV SP, X29",                 0x910003BF) \
    X("MOV W0, #0x10",               0x52800200) \
    X("MOV X0, #0x10000",            0xD2A00020) \
    X("MOV W0, #-1",                 0x12800000) \
    X("MOV X0, #-2",                 0x92800020) \
    X("MOV W0, #0x10001",            0x320083E0) \
    X("MOV X0, #0xFFFF0000FFFF0000", 0xB2103FE0) \
    X("RET",                         0xD65F03C0) \
    X("BR X16",                      0xD61F0200) \
    X("BLR X8",                      0xD63F0100) \
    X("B #0x100",                    0x14000040) \
    X("B #-0x8",                     0x17FFFFFE) \
    X("BL #0x1000",                  0x94000400) \
    X("BL #-0x40",                   0x97FFFFF0) \
    X("ADR X0, #0x10",               0x10000080) \
    X("ADR X3, #-0x4",               0x10FFFFE3) \
    X("ADR X5, #0x5",                0x30000025) \
    X("ADRP X0, #0x1000",            0xB0000000) \
    X("ADRP X8, #0x7000",            0xF0000028) \
    X("ADRP X1, #-0x2000",           0xD0FFFFE1) \
    X("ADRP X2, #0x123000",          0xF0000902) \
    X("LDRH W0, [X1,#0x10]",         0x79402020) \
    X("LDRH W0, [X1]",               0x79400020) \
    X("LDRH W2, [X3,#2]!",           0x78402C62) \
    X("LDRH W2, [X3],#2",            0x78402462) \
    X("LDRH W4, [X5,X6]",            0x786668A4) \
    X("LDRH W4, [X5,X6,LSL#1]",      0x786678A4) \
    X("LDR W0, [X1,#0x18]",          0xB9401820) \
    X("LDR X0, [X1,#0x18]",          0xF9400C20) \
    X("LDR X0, [X1]",                0xF9400020) \
    X("LDR W9, [SP,#0x24]",          0xB94027E9) \
    X("LDR X0, [X1,#8]!",            0xF8408C20) \
    X("LDR X0, [X1],#8",             0xF8408420) \
    X("LDR W0, [X1,#-4]!",           0xB85FCC20) \
    X("LDR X2, [X3,X4]",             0xF8646862) \
    X("LDR X2, [X3,X4,LSL#3]",       0xF8647862) \
    X("LDR W2, [X3,W4,UXTW#2]",      0xB8645862) \
    X("LDR X2, [X3,W4,SXTW]",        0xF864C862) \
    X("LDR X0, #0x100",              0x58000800) \
    X("LDR W1, #-0x10",              0x18FFFF81) \
    X("MOVZ W0, #0x1234",            0x52824680) \
    X("MOVZ X0, #0x1234, LSL#16",    0xD2A24680) \
    X("MOVZ X3, #0xFFFF, LSL#48",    0xD2FFFFE3) \
    X("MOVN W1, #0",                 0x12800001) \
    X("MOVK X2, #0xBEEF, LSL#32",    0xF2D7DDE2) \
    X("ORR X0, X1, #0xFF",           0xB2401C20) \
    X("ORR W0, W1, #0x1",            0x32000020) \
    X("ORR X0, X1, #0xFFFF0000FFFF0000", 0xB2103C20) \
    X("ORR X0, X1, X2",              0xAA020020) \
    X("ORR W0, W1, W2, LSL#4",       0x2A021020) \
    X("ORR X0, X1, X2, ROR#7",       0xAAC21C20) \
    X("LDP X29, X30, [SP,#0x10]",    0xA9417BFD) \
    X("LDP W0, W1, [X2,#8]",         0x29410440) \
    X("LDP X29, X30, [SP],#0x20",    0xA8C27BFD) \
    X("LDP X0, X1, [X2,#-0x10]!",    0xA9FF0440) \
    X("ADD X0, X1, #0x10",           0x91004020) \
    X("ADD W0, W1, #0x10",           0x11004020) \
    X("ADD X0, X1, #1, LSL#12",      0x91400420) \
    X("ADD X0, SP, #0x20",           0x910083E0) \
    X("ADD X0, X1, X2",              0x8B020020) \
    X("ADD X0, X1, X2, LSL#3",       0x8B020C20) \
    X("ADD X0, X1, W2, UXTW",        0x8B224020) \
    X("ADD X0, X1, W2, SXTW#2",      0x8B22C820) \
    X("ADDS X0, X1, #4",             0xB1001020) \
    X("SUB SP, SP, #0x40",           0xD10103FF) \
    X("SUB X0, X1, X2",              0xCB020020) \
    X("SUBS W0, W1, #1",             0x71000420) \
    X("STR W0, [SP,#0x1C]",          0xB9001FE0) \
    X("STR X0, [X1,#0x18]",          0xF9000C20) \
    X("STR X0, [X1]",                0xF9000020) \
    X("STR X0, [SP,#-0x10]!",        0xF81F0FE0) \
    X("STR X0, [X1],#8",             0xF8008420) \
    X("STR W0, [X1,X2,LSL#2]",       0xB8227820) \
    X("CBZ X0, #0x40",               0xB4000200) \
    X("CBZ W0, #-0x8",               0x34FFFFC0) \
    X("CBNZ X1, #0x100",             0xB5000801) \
    X("LDR X0, [X1,#4]",             0xF8404020) \
    X("LDR X0, [X29,#-8]",           0xF85F83A0) \
    X("LDR W0, [X1,#-4]",            0xB85FC020) \
    X("STR X0, [X1,#-8]",            0xF81F8020) \
    X("STR WZR, [SP,#0xC]",          0xB9000FFF) \
    X("LDRH W0, [X1,#3]",            0x78403020) \
    X("LDUR X0, [X1,#0x10]",         0xF8410020) \
    X("STUR W0, [X29,#-4]",          0xB81FC3A0) \
    X("LDURB W0, [X1,#-1]",          0x385FF020) \
    X("STURH W0, [X1,#-2]",          0x781FE020) \
    X("LDURSW X0, [X1,#-4]",         0xB89FC020) \
    X("LDRB W0, [X1,#0x10]",         0x39404020) \
    X("LDRB W0, [X1,#3]",            0x39400C20) \
    X("LDRB W0, [X1,#1]!",           0x38401C20) \
    X("LDRB W0, [X1],#1",            0x38401420) \
    X("LDRB W0, [X1,X2]",            0x38626820) \
    X("LDRB W0, [X1,X2,LSL#0]",      0x38627820) \
    X("LDRB W0, [X1,W2,UXTW]",       0x38624820) \
    X("STRB W0, [X1,#0x10]",         0x39004020) \
    X("STRB WZR, [X1]",              0x3900003F) \
    X("STRH W0, [X1,#0x10]",         0x79002020) \
    X("STRH W0, [X1,#-2]!",          0x781FEC20) \
    X("LDRSW X0, [X1,#0x10]",        0xB9801020) \
    X("LDRSW X0, [X1,X2,LSL#2]",     0xB8A27820) \
    X("CMP X0, #0x10",               0xF100401F) \
    X("CMP W0, W1",                  0x6B01001F) \
    X("CMP X0, X1, LSL#2",           0xEB01081F) \
    X("CMP X0, W1, UXTW",            0xEB21401F) \
    X("CMP W0, #1, LSL#12",          0x7140041F) \
    X("CMN W0, #1",                  0x3100041F) \
    X("CMN X0, X1",                  0xAB01001F) \
    X("TST W0, #0xFF",               0x72001C1F) \
    X("TST X0, X1",                  0xEA01001F) \
    X("TST X0, #0x8000000000000000", 0xF241001F) \
    X("AND X0, X1, #0xFF",           0x92401C20) \
    X("AND W0, W1, #-0x1000",        0x12144C20) \
    X("BIC X0, X1, #0xFF",           0x9278DC20) \
    X("BICS W2, W3, #0xF0",          0x72186C62) \
    X("ORN X4, X5, #0xFFFF0000FFFF0000", 0xB2003CA4) \
    X("EON W6, W7, #1",              0x521F78E6) \
    X("AND W0, W1, W2",              0x0A020020) \
    X("ANDS X0, X1, X2, LSR#3",      0xEA420C20) \
    X("EOR W0, W1, #0x80000000",     0x52010020) \
    X("EOR X0, X1, X2",              0xCA020020) \
    X("B.EQ #0x10",                  0x54000080) \
    X("B.NE #-0x8",                  0x54FFFFC1) \
    X("B.HS #0x100",                 0x54000802) \
    X("B.CS #0x100",                 0x54000802) \
    X("B.LO #0x100",                 0x54000803) \
    X("B.GT #0x20",                  0x5400010C) \
    X("RETAA",                       0xD65F0BFF) \
    X("RETAB",                       0xD65F0FFF) \
    X("PACIASP",                     0xD503233F) \
    X("PACIBSP",                     0xD503237F) \
    X("AUTIASP",                     0xD50323BF) \
    X("AUTIBSP",                     0xD50323FF) \
    X("ORR X0, X1, X2, LSL #3",      0xAA020C20) \
    X("TST X0, X1, LSL #2",          0xEA01081F) \
    X("ORR X0, X1, X2, ROR #5",      0xAAC21420) \
    X("ADD X0, X1, #0x1000",         0x91400420) \
    X("SUB SP, SP, #0x1000",         0xD14007FF) \
    X("ADD X0, X1, #-8",             0xD1002020) \
    X("CMP X0, #-1",                 0xB100041F) \
    X("ADD X0, SP, X1",              0x8B2163E0) \
    X("ADD SP, SP, X1",              0x8B2163FF) \
    X("ADD X0, SP, X1, LSL #2",      0x8B216BE0) \
    X("ADD W0, WSP, W1",             0x0B2143E0) \
    X("LDP X29, X30, [SP]",          0xA9407BFD) \
    X("STP X29, X30, [SP]",          0xA9007BFD) \
    X("ADR X0, #-1",                 0x70FFFFE0) \
    X("TBZ W0, #3, #8",                0x36180040) \
    X("TBNZ X1, #40, #-8",             0xB747FFC1) \
    X("TBZ X5, #3, #0x100",            0x36180805) \
    X("TBNZ W30, #31, #-0x8000",       0x37FC001E) \
    X("SVC #0x80",                     0xD4001001) \
    X("SVC #0",                        0xD4000001) \
    X("BRK #1",                        0xD4200020) \
    X("BRK #0xF000",                   0xD43E0000) \
    X("HLT #0",                        0xD4400000) \
    X("UDF #0",                        0x00000000) \
    X("UDF #0x1234",                   0x00001234) \
    X("HVC #1",                        0xD4000022) \
    X("BTI",                           0xD503241F) \
    X("BTI C",                         0xD503245F) \
    X("BTI J",                         0xD503249F) \
    X("BTI JC",                        0xD50324DF) \
    X("BRAA X16, X17",                 0xD71F0A11) \
    X("BRAB X8, SP",                   0xD71F0D1F) \
    X("BLRAA X8, X9",                  0xD73F0909) \
    X("BLRAB X1, X2",                  0xD73F0C22) \
    X("BRAAZ X16",                     0xD61F0A1F) \
    X("BRABZ X3",                      0xD61F0C7F) \
    X("BLRAAZ X8",                     0xD63F091F) \
    X("BLRABZ X8",                     0xD63F0D1F) \
    X("LDRAA X0, [X1,#8]",             0xF8201420) \
    X("LDRAB X0, [X1,#-8]!",           0xF8FFFC20) \
    X("LDRAA X16, [X17]",              0xF8200630) \
    X("LDRAA X1, [SP,#4088]",          0xF83FF7E1) \
    X("LDRAB X1, [X2,#-4096]",         0xF8E00441) \
    X("PACIA X0, X1",                  0xDAC10020) \
    X("PACIB X16, SP",                 0xDAC107F0) \
    X("PACDA X3, X4",                  0xDAC10883) \
    X("PACDB X3, X4",                  0xDAC10C83) \
    X("AUTIA X16, X17",                0xDAC11230) \
    X("AUTIB X5, SP",                  0xDAC117E5) \
    X("AUTDA X1, X2",                  0xDAC11841) \
    X("AUTDB X1, X2",                  0xDAC11C41) \
    X("PACIZA X0",                     0xDAC123E0) \
    X("PACIZB X1",                     0xDAC127E1) \
    X("PACDZA X2",                     0xDAC12BE2) \
    X("PACDZB X3",                     0xDAC12FE3) \
    X("AUTIZA X4",                     0xDAC133E4) \
    X("AUTIZB X5",                     0xDAC137E5) \
    X("AUTDZA X6",                     0xDAC13BE6) \
    X("AUTDZB X7",                     0xDAC13FE7) \
    X("XPACI X0",                      0xDAC143E0) \
    X("XPACD X1",                      0xDAC147E1) \
    X("XPACLRI",                       0xD50320FF) \
    X("PACGA X0, X1, X2",              0x9AC23020) \
    X("PACIAZ",                        0xD503231F) \
    X("PACIBZ",                        0xD503235F) \
    X("AUTIAZ",                        0xD503239F) \
    X("AUTIBZ",                        0xD50323DF) \
    X("PACIA1716",                     0xD503211F) \
    X("PACIB1716",                     0xD503215F) \
    X("AUTIA1716",                     0xD503219F) \
    X("AUTIB1716",                     0xD50321DF) \
    X("LDRSB W0, [X1,#1]",             0x39C00420) \
    X("LDRSB X0, [X1,#1]",             0x39800420) \
    X("LDRSH W0, [X1,#2]",             0x79C00420) \
    X("LDRSH X0, [X1,#0x7E]",          0x7980FC20) \
    X("LDRSB W0, [X1,#-1]",            0x38DFF020) \
    X("LDRSH X2, [X3,#2]!",            0x78802C62) \
    X("LDRSB W2, [X3],#1",             0x38C01462) \
    X("LDRSH W4, [X5,X6,LSL#1]",       0x78E678A4) \
    X("LDURSB W0, [X1,#-1]",           0x38DFF020) \
    X("LDURSH X0, [X1,#3]",            0x78803020) \
    X("LDPSW X0, X1, [X2,#8]",         0x69410440) \
    X("LDPSW X0, X1, [SP,#-8]!",       0x69FF07E0) \
    X("LDPSW X0, X1, [X2],#16",        0x68C20440) \
    X("LDNP X0, X1, [X2,#16]",         0xA8410440) \
    X("STNP W0, W1, [X2,#-8]",         0x283F0440) \
    X("LDNP Q0, Q1, [X2,#32]",         0xAC410440) \
    X("STNP D0, D1, [SP]",             0x6C0007E0) \
    X("LDXR X0, [X1]",                 0xC85F7C20) \
    X("LDXR W0, [X1]",                 0x885F7C20) \
    X("STXR W2, X0, [X1]",             0xC8027C20) \
    X("LDAXR W0, [X1]",                0x885FFC20) \
    X("STLXR W2, W0, [X1]",            0x8802FC20) \
    X("LDAR X0, [X1]",                 0xC8DFFC20) \
    X("STLR W0, [X1]",                 0x889FFC20) \
    X("LDAPR X0, [X1]",                0xF8BFC020) \
    X("LDAXRB W0, [X1]",               0x085FFC20) \
    X("LDXRH W0, [X1]",                0x485F7C20) \
    X("LDARB W3, [SP]",                0x08DFFFE3) \
    X("LDARH W3, [X4]",                0x48DFFC83) \
    X("STLRB W3, [X4]",                0x089FFC83) \
    X("STLRH W3, [X4]",                0x489FFC83) \
    X("LDAPRB W0, [X1]",               0x38BFC020) \
    X("LDAPRH W0, [X1]",               0x78BFC020) \
    X("STXRB W2, W0, [X1]",            0x08027C20) \
    X("STXRH W2, W0, [X1]",            0x48027C20) \
    X("STLXRB W2, W0, [X1]",           0x0802FC20) \
    X("STLXRH W2, W0, [X1]",           0x4802FC20) \
    X("LDXP X0, X1, [X2]",             0xC87F0440) \
    X("LDAXP W0, W1, [X2]",            0x887F8440) \
    X("STXP W3, X0, X1, [X2]",         0xC8230440) \
    X("STLXP W3, W0, W1, [X2]",        0x88238440) \
    X("CAS X0, X1, [X2]",              0xC8A07C41) \
    X("CASA W0, W1, [X2]",             0x88E07C41) \
    X("CASL X0, X1, [SP]",             0xC8A0FFE1) \
    X("CASAL W0, W1, [X2]",            0x88E0FC41) \
    X("CASB W0, W1, [X2]",             0x08A07C41) \
    X("CASALH W0, W1, [X2]",           0x48E0FC41) \
    X("LDADD X0, X1, [X2]",            0xF8200041) \
    X("LDADDA W0, W1, [X2]",           0xB8A00041) \
    X("LDADDL W0, W1, [X2]",           0xB8600041) \
    X("LDADDAL X0, X1, [X2]",          0xF8E00041) \
    X("LDADDALB W0, W1, [X2]",         0x38E00041) \
    X("LDADDH W0, W1, [X2]",           0x78200041) \
    X("LDCLR W0, W1, [X2]",            0xB8201041) \
    X("LDEOR X0, X1, [X2]",            0xF8202041) \
    X("LDSET W0, W1, [X2]",            0xB8203041) \
    X("LDSMAX X0, X1, [X2]",           0xF8204041) \
    X("LDSMINAL W0, W1, [X2]",         0xB8E05041) \
    X("LDUMAXB W0, W1, [X2]",          0x38206041) \
    X("LDUMINLH W0, W1, [X2]",         0x78607041) \
    X("SWP X0, X1, [X2]",              0xF8208041) \
    X("SWPAL W0, W1, [X2]",            0xB8E08041) \
    X("SWPB W0, W1, [X2]",             0x38208041) \
    X("STADD W0, [X2]",                0xB820005F) \
    X("STADDL X0, [X2]",               0xF860005F) \
    X("STCLRB W0, [X2]",               0x3820105F) \
    X("STSETLH W0, [X2]",              0x7860305F) \
    X("STSMAX X0, [SP]",               0xF82043FF) \
    X("LSL X0, X1, #3",                0xD37DF020) \
    X("LSL W0, W1, #3",                0x531D7020) \
    X("LSL X0, X1, #63",               0xD3410020) \
    X("LSL W0, W1, #0",                0x53007C20) \
    X("LSR X0, X1, #3",                0xD343FC20) \
    X("LSR W0, W1, #31",               0x531F7C20) \
    X("ASR W0, W1, #31",               0x131F7C20) \
    X("ASR X0, X1, #1",                0x9341FC20) \
    X("ROR X0, X1, #7",                0x93C11C20) \
    X("ROR W0, W1, #31",               0x13817C20) \
    X("LSL X0, X1, X2",                0x9AC22020) \
    X("LSR W0, W1, W2",                0x1AC22420) \
    X("ASR X0, X1, X2",                0x9AC22820) \
    X("ROR W0, W1, W2",                0x1AC22C20) \
    X("LSLV X0, X1, X2",               0x9AC22020) \
    X("RORV W0, W1, W2",               0x1AC22C20) \
    X("UBFX X0, X1, #4, #8",           0xD3442C20) \
    X("UBFX W0, W1, #31, #1",          0x531F7C20) \
    X("SBFX X0, X1, #0, #32",          0x93407C20) \
    X("BFXIL W0, W1, #3, #2",          0x33031020) \
    X("UBFIZ X0, X1, #4, #8",          0xD37C1C20) \
    X("SBFIZ W0, W1, #2, #5",          0x131E1020) \
    X("BFI X0, X1, #8, #4",            0xB3780C20) \
    X("BFI W0, W1, #0, #32",           0x33007C20) \
    X("SXTB X0, W1",                   0x93401C20) \
    X("SXTB W0, W1",                   0x13001C20) \
    X("SXTH X0, W1",                   0x93403C20) \
    X("SXTH W0, W1",                   0x13003C20) \
    X("SXTW X0, W1",                   0x93407C20) \
    X("UXTB W0, W1",                   0x53001C20) \
    X("UXTH W0, W1",                   0x53003C20) \
    X("UBFM X0, X1, #4, #11",          0xD3442C20) \
    X("SBFM W0, W1, #1, #2",           0x13010820) \
    X("BFM X0, X1, #56, #3",           0xB3780C20) \
    X("EXTR X0, X1, X2, #8",           0x93C22020) \
    X("EXTR W0, W1, W2, #31",          0x13827C20) \
    X("CSEL X0, X1, X2, EQ",           0x9A820020) \
    X("CSEL W0, W1, W2, HS",           0x1A822020) \
    X("CSINC W0, W1, W2, NE",          0x1A821420) \
    X("CSINV X0, X1, XZR, LT",         0xDA9FB020) \
    X("CSNEG W0, W1, W2, AL",          0x5A82E420) \
    X("CSET W0, EQ",                   0x1A9F17E0) \
    X("CSET X0, HI",                   0x9A9F97E0) \
    X("CSETM X0, NE",                  0xDA9F03E0) \
    X("CINC X0, X1, LT",               0x9A81A420) \
    X("CINV W0, W1, CC",               0x5A812020) \
    X("CNEG W0, W1, GE",               0x5A81B420) \
    X("CCMP X0, X1, #4, NE",           0xFA411004) \
    X("CCMP W0, #5, #0, EQ",           0x7A450800) \
    X("CCMN X0, #1, #2, GT",           0xBA41C802) \
    X("CCMN W0, W1, #15, LO",          0x3A41300F) \
    X("MADD X0, X1, X2, X3",           0x9B020C20) \
    X("MADD W0, W1, W2, W3",           0x1B020C20) \
    X("MSUB X0, X1, X2, X3",           0x9B028C20) \
    X("MUL W0, W1, W2",                0x1B027C20) \
    X("MUL X0, X1, X2",                0x9B027C20) \
    X("MNEG X0, X1, X2",               0x9B02FC20) \
    X("SMADDL X0, W1, W2, X3",         0x9B220C20) \
    X("UMADDL X0, W1, W2, X3",         0x9BA20C20) \
    X("SMSUBL X0, W1, W2, X3",         0x9B228C20) \
    X("UMSUBL X0, W1, W2, X3",         0x9BA28C20) \
    X("SMULL X0, W1, W2",              0x9B227C20) \
    X("UMULL X0, W1, W2",              0x9BA27C20) \
    X("SMNEGL X0, W1, W2",             0x9B22FC20) \
    X("UMNEGL X0, W1, W2",             0x9BA2FC20) \
    X("SMULH X0, X1, X2",              0x9B427C20) \
    X("UMULH X0, X1, X2",              0x9BC27C20) \
    X("UDIV W0, W1, W2",               0x1AC20820) \
    X("SDIV X0, X1, X2",               0x9AC20C20) \
    X("ADC X0, X1, X2",                0x9A020020) \
    X("ADCS W0, W1, W2",               0x3A020020) \
    X("SBC X0, X1, X2",                0xDA020020) \
    X("SBCS W0, W1, W2",               0x7A020020) \
    X("NGC X0, X1",                    0xDA0103E0) \
    X("NGCS W0, W1",                   0x7A0103E0) \
    X("BIC X0, X1, X2",                0x8A220020) \
    X("BICS W0, W1, W2, LSR #3",       0x6A620C20) \
    X("ORN W0, W1, W2",                0x2A220020) \
    X("EON X0, X1, X2, LSL #3",        0xCA220C20) \
    X("BIC X0, X1, X2, ROR #63",       0x8AE2FC20) \
    X("MVN X0, X1",                    0xAA2103E0) \
    X("MVN W0, W1, LSL #4",            0x2A2113E0) \
    X("NEG X0, X1",                    0xCB0103E0) \
    X("NEG W0, W1, LSL #2",            0x4B010BE0) \
    X("NEGS W0, W1",                   0x6B0103E0) \
    X("NEGS X0, X1, ASR #3",           0xEB810FE0) \
    X("LDR S0, [X0,#8]",               0xBD400800) \
    X("LDR D0, [X0,#8]",               0xFD400400) \
    X("LDR Q0, [X0,#16]",              0x3DC00400) \
    X("LDR B0, [X0,#1]",               0x3D400400) \
    X("LDR H0, [X0,#2]",               0x7D400400) \
    X("STR D0, [SP,#8]",               0xFD0007E0) \
    X("STR Q1, [X2,#0x30]",            0x3D800C41) \
    X("STR S3, [X4,#-4]!",             0xBC1FCC83) \
    X("LDR D1, [X2],#8",               0xFC408441) \
    X("LDR Q0, [X1,X2,LSL#4]",         0x3CE27820) \
    X("LDR D0, [X1,X2]",               0xFC626820) \
    X("LDR S0, [X1,#-4]",              0xBC5FC020) \
    X("LDR D0, [X1,#3]",               0xFC403020) \
    X("LDUR Q0, [X0,#-16]",            0x3CDF0000) \
    X("STUR D0, [X29,#-8]",            0xFC1F83A0) \
    X("LDUR S0, [X0,#1]",              0xBC401000) \
    X("STP D9, D8, [SP,#-0x20]!",      0x6DBE23E9) \
    X("LDP D9, D8, [SP],#0x20",        0x6CC223E9) \
    X("LDP Q0, Q1, [X1]",              0xAD400420) \
    X("STP Q0, Q1, [X0,#0x20]",        0xAD010400) \
    X("LDP S0, S1, [X1,#8]",           0x2D410420) \
    X("STP D0, D1, [SP,#0x10]",        0x6D0107E0) \
    X("LDR D0, #0x100",                0x5C000800) \
    X("LDR Q0, #0x100",                0x9C000800) \
    X("LDR S1, #-8",                   0x1CFFFFC1) \
    X("FMOV D0, D1",                   0x1E604020) \
    X("FMOV S0, S1",                   0x1E204020) \
    X("FMOV H0, H1",                   0x1EE04020) \
    X("FMOV S0, W1",                   0x1E270020) \
    X("FMOV W0, S1",                   0x1E260020) \
    X("FMOV D0, X1",                   0x9E670020) \
    X("FMOV X0, D1",                   0x9E660020) \
    X("FMOV H0, W1",                   0x1EE70020) \
    X("FMOV W0, H1",                   0x1EE60020) \
    X("FMOV H0, X1",                   0x9EE70020) \
    X("FMOV X0, H1",                   0x9EE60020) \
    X("FMOV D0, XZR",                  0x9E6703E0) \
    X("FMOV S0, WZR",                  0x1E2703E0) \
    X("FMOV D0, #1.0",                 0x1E6E1000) \
    X("FMOV S0, #-2.5",                0x1E309000) \
    X("FMOV D1, #0.125",               0x1E681001) \
    X("FMOV S2, #31.0",                0x1E27F002) \
    X("FMOV H3, #0.5",                 0x1EEC1003) \
    X("FMOV D0, #-1",                  0x1E7E1000) \
    X("FMOV D0, #0.0",                 0x9E6703E0) \
    X("FMOV S0, #0.0",                 0x1E2703E0) \
    X("FMOV D4, #1.0625",              0x1E6E3004)

// Wildcard pattern, an instruction, its encoding, and whether the pattern must match it
#define WILDCARD(X) \
    X("STP X29, X30, [SP,#?]",   "STP X29, X30, [SP,#0x30]",    0xA9037BFD, 1) \
    X("STP X29, X30, [SP,#?]",   "LDP X29, X30, [SP,#0x10]",    0xA9417BFD, 0) \
    X("STP X29, X30, [SP,#?]",   "STP X29, X30, [SP],#0x10",    0xA8817BFD, 0) \
    X("STP X20, X19, [SP,#?]!",  "STP X20, X19, [SP,#-0x20]!",  0xA9BE4FF4, 1) \
    X("STP X20, X19, [SP,#?]!",  "SUB SP, SP, #0x20",           0xD10083FF, 0) \
    X("MOV X?, X1",              "MOV X5, X1",                  0xAA0103E5, 1) \
    X("MOV X19, X?",             "MOV X19, X1",                 0xAA0103F3, 1) \
    X("MOV W0, #?",              "MOV W0, #5",                  0x528000A0, 1) \
    X("MOV W0, #?",              "MOV W0, #-1",                 0x12800000, 1) \
    X("MOV W0, #?",              "MOV W0, W1",                  0x2A0103E0, 0) \
    X("LDR W?, [X?,#0x18]",      "LDR W3, [X9,#0x18]",          0xB9401923, 1) \
    X("LDR W?, [X?,#0x18]",      "LDR W3, [X9,#0x1C]",          0xB9401D23, 0) \
    X("LDR W?, [X?,#0x18]",      "LDR X3, [X9,#0x18]",          0xF9400D23, 0) \
    X("LDR W?, [X?,#0x18]",      "STR W3, [X9,#0x18]",          0xB9001923, 0) \
    X("LDR ?, [X?,#?]",          "LDR X3, [X9,#0x18]",          0xF9400D23, 1) \
    X("LDR ?, [X?,#?]",          "LDR W3, [SP,#0x40]",          0xB94043E3, 1) \
    X("LDR X?, [X?,#?]",         "LDR X0, [X1,#8]!",            0xF8408C20, 0) \
    X("LDR X?, [X?],#?",         "LDR X0, [X1],#8",             0xF8408420, 1) \
    X("LDR X?, [X?,#?]!",        "LDR X0, [X1,#-8]!",           0xF85F8C20, 1) \
    X("LDR X?, [X?,X?,LSL#3]",   "LDR X0, [X1,X2,LSL#3]",       0xF8627820, 1) \
    X("LDR X?, #?",              "LDR X0, #0x100",              0x58000800, 1) \
    X("LDR X?, #?",              "LDR X0, [X1]",                0xF9400020, 0) \
    X("LDR W0, [X1, #0x18]",     "LDR W0, [X1,#0x18]",          0xB9401820, 1) \
    X("LDRH W?, [X?,#?]",        "LDRH W1, [X2,#0x10]",         0x79402041, 1) \
    X("LDRH W?, [X?,#?]",        "STRH W1, [X2,#0x10]",         0x79002041, 0) \
    X("LDRH W?, [X?,#?]",        "LDRB W1, [X2,#0x10]",         0x39404041, 0) \
    X("STR X?, [SP,#?]",         "STR X5, [SP,#0x30]",          0xF9001BE5, 1) \
    X("STR X?, [SP,#?]",         "STR X5, [X1,#0x30]",          0xF9001825, 0) \
    X("STR ?, [X?,#?]",          "STR W5, [X1,#0x30]",          0xB9003025, 1) \
    X("STR W?, [X?,#0x1C]",      "STR W5, [X1,#0x1C]",          0xB9001C25, 1) \
    X("STR X?, [X?,#?]!",        "STR X0, [SP,#-0x10]!",        0xF81F0FE0, 1) \
    X("ADRP X?, #?",             "ADRP X8, #0x5000",            0xB0000028, 1) \
    X("ADRP X?, #?",             "ADR X8, #0x50",               0x10000288, 0) \
    X("ADRP X8, #?",             "ADRP X9, #0x5000",            0xB0000029, 0) \
    X("ADR X?, #?",              "ADR X1, #-0x40",              0x10FFFE01, 1) \
    X("ADD X?, X?, #?",          "ADD X0, X1, #0x3A0",          0x910E8020, 1) \
    X("ADD X?, X?, #?",          "SUB X0, X1, #0x3A0",          0xD10E8020, 0) \
    X("ADD X?, X?, #?",          "ADD X0, X1, X2",              0x8B020020, 0) \
    X("ADD X?, X?, #?",          "ADDS X0, X1, #1",             0xB1000420, 0) \
    X("ADD W?, W?, #?",          "ADD W0, W1, #1",              0x11000420, 1) \
    X("ADD X?, X?, #?, LSL#12",  "ADD X0, X1, #1, LSL#12",      0x91400420, 1) \
    X("ADD X?, X?, X?",          "ADD X0, X1, X2",              0x8B020020, 1) \
    X("ADD X?, X?, X?",          "ADD X0, X1, X3",              0x8B030020, 1) \
    X("ADD X?, X?, X?",          "ADD X0, X1, #2",              0x91000820, 0) \
    X("SUB SP, SP, #?",          "SUB SP, SP, #0x80",           0xD10203FF, 1) \
    X("SUB X?, X?, #?",          "ADD X0, X1, #1",              0x91000420, 0) \
    X("SUBS W?, W?, #?",         "SUBS W0, W1, #1",             0x71000420, 1) \
    X("SUBS W?, W?, #?",         "SUB W0, W1, #1",              0x51000420, 0) \
    X("ADD X0, X1, #1, LSL #12", "ADD X0, X1, #1, LSL#12",      0x91400420, 1) \
    X("ADD X0, X1, #1, LSL #12", "ADD X0, X1, #1",              0x91000420, 0) \
    X("BL ?",                    "BL #0x2000",                  0x94000800, 1) \
    X("BL #?",                   "BL #0x2000",                  0x94000800, 1) \
    X("BL #?",                   "B #0x2000",                   0x14000800, 0) \
    X("B #?",                    "B #-0x10",                    0x17FFFFFC, 1) \
    X("B ?",                     "BL #0x10",                    0x94000004, 0) \
    X("CBZ ?, #?",               "CBZ W0, #0x20",               0x34000100, 1) \
    X("CBZ ?, #?",               "CBNZ W0, #0x20",              0x35000100, 0) \
    X("CBNZ X?, #?",             "CBNZ X1, #-0x20",             0xB5FFFF01, 1) \
    X("CBZ X?, #?",              "CBZ W1, #0x20",               0x34000101, 0) \
    X("MOVZ W?, #?",             "MOVZ W0, #0x10",              0x52800200, 1) \
    X("MOVZ W?, #?",             "MOVK W0, #0x10",              0x72800200, 0) \
    X("MOVK X?, #?, LSL#?",      "MOVK X0, #0x10, LSL#16",      0xF2A00200, 1) \
    X("MOVZ X?, #0x10",          "MOVZ X0, #0x10, LSL#16",      0xD2A00200, 0) \
    X("ORR X?, X?, X?",          "ORR X0, X1, X2",              0xAA020020, 1) \
    X("ORR X?, X?, #?",          "ORR X0, X1, #0xFF",           0xB2401C20, 1) \
    X("ORR X?, X?, X?",          "AND X0, X1, X2",              0x8A020020, 0) \
    X("ORR X0, XZR, X1",         "MOV X0, X1",                  0xAA0103E0, 1) \
    X("LDP X?, X?, [SP,#?]",     "LDP X29, X30, [SP,#0x10]",    0xA9417BFD, 1) \
    X("LDP X?, X?, [SP,#?]",     "STP X29, X30, [SP,#0x10]",    0xA9017BFD, 0) \
    X("LDP X?, X?, [SP],#?",     "LDP X29, X30, [SP],#0x30",    0xA8C37BFD, 1) \
    X("LDP X?, X?, [SP,#?]!",    "LDP X29, X30, [SP,#-0x30]!",  0xA9FD7BFD, 1) \
    X("BR X?",                   "BR X16",                      0xD61F0200, 1) \
    X("BR X?",                   "BLR X16",                     0xD63F0200, 0) \
    X("BLR X?",                  "BLR X8",                      0xD63F0100, 1) \
    X("RET",                     "RET X1",                      0xD65F0020, 0) \
    X("NOP",                     "NOP",                         0xD503201F, 1) \
    X("RET",                     "RETAA",                       0xD65F0BFF, 0) \
    X("LDR X?, [X29,#-8]",       "LDUR X3, [X29,#-8]",          0xF85F83A3, 1) \
    X("LDR ?, [X29,#-8]",        "LDUR W0, [X29,#-8]",          0xB85F83A0, 1) \
    X("LDR ?, [X29,#-8]",        "LDR X0, [X29,#8]",            0xF94007A0, 0) \
    X("LDR ?, [X1,#0x81]",       "LDUR W0, [X1,#0x81]",         0xB8481020, 1) \
    X("LDR ?, [X1,#0x81]",       "LDUR X0, [X1,#0x81]",         0xF8481020, 1) \
    X("LDR ?, [X1,#0xC]",        "LDR W0, [X1,#0xC]",           0xB9400C20, 1) \
    X("LDR ?, [X1,#0xC]",        "LDUR X0, [X1,#0xC]",          0xF840C020, 1) \
    X("LDR ?, [X1,#0xC]",        "STR W0, [X1,#0xC]",           0xB9000C20, 0) \
    X("LDR ?, [X1,#0x4000]",     "LDR X0, [X1,#0x4000]",        0xF9600020, 1) \
    X("LDR X?, [X?,X?,?]",       "LDR X2, [X3,W4,SXTW]",        0xF864C862, 1) \
    X("LDR X?, [X?,X?,?]",       "LDR X2, [X3,X4,LSL#3]",       0xF8647862, 1) \
    X("LDR X?, [X?,X?,? #3]",    "LDR X2, [X3,W4,SXTW#3]",      0xF864D862, 1) \
    X("LDR X?, [X?,X?,? #3]",    "LDR X2, [X3,X4]",             0xF8646862, 0) \
    X("LDR X?, [X?,X?,LSL#?]",   "LDR X2, [X3,X4]",             0xF8646862, 1) \
    X("LDUR X?, [X?,#?]",        "LDUR X0, [X1,#0x10]",         0xF8410020, 1) \
    X("LDUR X?, [X?,#?]",        "LDR X0, [X1,#0x10]",          0xF9400820, 0) \
    X("LDUR X?, [X?,#?]",        "LDR X0, [X1,#8]!",            0xF8408C20, 0) \
    X("STUR ?, [X?,#?]",         "STUR W0, [X29,#-4]",          0xB81FC3A0, 1) \
    X("STUR ?, [X?,#?]",         "LDUR W0, [X29,#-4]",          0xB85FC3A0, 0) \
    X("LDRB W?, [X?,#?]",        "LDRB W0, [X1,#0x10]",         0x39404020, 1) \
    X("LDRB W?, [X?,#?]",        "LDRH W0, [X1,#0x10]",         0x79402020, 0) \
    X("LDRB W?, [X?,#?]",        "STRB W0, [X1,#0x10]",         0x39004020, 0) \
    X("LDRB W?, [X?,X?,LSL#?]",  "LDRB W0, [X1,X2,LSL#0]",      0x38627820, 1) \
    X("LDRB W?, [X?,X?,LSL#?]",  "LDRB W0, [X1,X2]",            0x38626820, 1) \
    X("STRB ?, [X?,#?]",         "STRB WZR, [X1]",              0x3900003F, 1) \
    X("STRH W?, [X?,#?]!",       "STRH W0, [X1,#-2]!",          0x781FEC20, 1) \
    X("STRH W?, [X?,#?]!",       "STRH W0, [X1,#0x10]",         0x79002020, 0) \
    X("LDRSW X?, [X?,#?]",       "LDRSW X0, [X1,#0x10]",        0xB9801020, 1) \
    X("LDRSW X?, [X?,#?]",       "LDR W0, [X1,#0x10]",          0xB9401020, 0) \
    X("CMP X?, #?",              "CMP X0, #0x10",               0xF100401F, 1) \
    X("CMP X?, #?",              "SUBS X1, X0, #0x10",          0xF1004001, 0) \
    X("CMP X?, #?",              "CMP W0, #1",                  0x7100041F, 0) \
    X("CMP ?, #?",               "CMP W0, #1",                  0x7100041F, 1) \
    X("CMP W?, W?",              "CMP W0, W1",                  0x6B01001F, 1) \
    X("CMP W?, W?",              "CMN W0, W1",                  0x2B01001F, 0) \
    X("CMP X?, X?, LSL#?",       "CMP X0, X1, LSL#2",           0xEB01081F, 1) \
    X("CMN W?, #?",              "CMN W0, #1",                  0x3100041F, 1) \
    X("TST W?, #?",              "TST W0, #0xFF",               0x72001C1F, 1) \
    X("TST W?, #?",              "ANDS W1, W0, #0xFF",          0x72001C01, 0) \
    X("TST X?, X?",              "TST X0, X1",                  0xEA01001F, 1) \
    X("AND X?, X?, #?",          "AND X0, X1, #0xFF",           0x92401C20, 1) \
    X("AND X?, X?, #?",          "ORR X0, X1, #0xFF",           0xB2401C20, 0) \
    X("EOR X?, X?, X?",          "EOR X0, X1, X2",              0xCA020020, 1) \
    X("EOR X?, X?, X?",          "ORR X0, X1, X2",              0xAA020020, 0) \
    X("ANDS X?, X?, X?, LSR#?",  "ANDS X0, X1, X2, LSR#3",      0xEA420C20, 1) \
    X("B.EQ #?",                 "B.EQ #0x10",                  0x54000080, 1) \
    X("B.EQ #?",                 "B.NE #0x10",                  0x54000081, 0) \
    X("B.? #?",                  "B.GT #0x20",                  0x5400010C, 1) \
    X("B.? #?",                  "B #0x10",                     0x14000004, 0) \
    X("B.? ?",                   "CBZ W0, #0x10",               0x34000080, 0) \
    X("B.HS ?",                  "B.CS #0x100",                 0x54000802, 1) \
    X("EOR X0, X1, X2, LSR #?",  "EOR X0, X1, X2, LSR #3",      0xCA420C20, 1) \
    X("SUB SP, SP, #?",          "SUB SP, SP, #1, LSL #12",     0xD14007FF, 1) \
    X("SUB SP, SP, #?",          "SUB SP, SP, #0x20",           0xD10083FF, 1) \
    X("CMP X0, #?",              "CMP X0, #1, LSL #12",         0xF140041F, 1) \
    X("MOV X0, #?",              "MOVN X0, #5",                 0x928000A0, 1) \
    X("MOV X0, #?",              "MOVK X0, #5",                 0xF28000A0, 0) \
    X("LDP X29, X30, [SP]",      "LDP X29, X30, [SP],#0x20",    0xA8C27BFD, 0) \
    X("ADD ?, X1, #8",           "ADD W0, W1, #8",              0x11002020, 0) \
    X("STP ?, X30, [SP,#-0x10]!", "STP W29, W30, [SP,#-8]!",    0x29BF7BFD, 0) \
    X("TBZ W?, #?, #?",        "TBZ W5, #7, #0x40",           0x36380205, 1) \
    X("TBZ W?, #?, #?",        "TBNZ W5, #7, #0x40",          0x37380205, 0) \
    X("TBZ W?, #?, #?",        "TBZ X5, #33, #0x40",          0xB6080205, 0) \
    X("TBZ X?, #?, #?",        "TBZ X5, #33, #0x40",          0xB6080205, 1) \
    X("TBZ ?, #?, #?",         "TBZ X5, #33, #0x40",          0xB6080205, 1) \
    X("TBZ X0, #40, #?",       "TBZ X0, #40, #-0x100",        0xB647F800, 1) \
    X("TBZ X0, #40, #?",       "TBZ X0, #8, #-0x100",         0x3647F800, 0) \
    X("SVC #?",                "SVC #0x80",                   0xD4001001, 1) \
    X("SVC #?",                "BRK #0x80",                   0xD4201000, 0) \
    X("BRK #?",                "BRK #1",                      0xD4200020, 1) \
    X("UDF #?",                "UDF #0x1234",                 0x00001234, 1) \
    X("BTI ?",                 "BTI C",                       0xD503245F, 1) \
    X("BTI ?",                 "BTI JC",                      0xD50324DF, 1) \
    X("BTI ?",                 "NOP",                         0xD503201F, 0) \
    X("BTI C",                 "BTI J",                       0xD503249F, 0) \
    X("BRAA X?, X?",           "BRAA X16, X17",               0xD71F0A11, 1) \
    X("BRAA X?, X?",           "BRAB X16, X17",               0xD71F0E11, 0) \
    X("BLRAA X8, X?",          "BLRAA X8, SP",                0xD73F091F, 1) \
    X("BLRAAZ X?",             "BLRAAZ X8",                   0xD63F091F, 1) \
    X("BLRAAZ X?",             "BLRAA X8, X9",                0xD73F0909, 0) \
    X("LDRAA X?, [X?,#?]",     "LDRAA X0, [X1,#-8]",          0xF87FF420, 1) \
    X("LDRAA X?, [X?,#?]",     "LDRAA X0, [X1,#8]!",          0xF8201C20, 0) \
    X("LDRAA X?, [X?,#?]!",    "LDRAA X0, [X1,#8]!",          0xF8201C20, 1) \
    X("LDRAA X?, [X?,#?]",     "LDRAB X0, [X1,#8]",           0xF8A01420, 0) \
    X("PACIA X?, X?",          "PACIA X16, SP",               0xDAC103F0, 1) \
    X("PACIA X?, X?",          "PACIB X16, SP",               0xDAC107F0, 0) \
    X("AUTIZA X?",             "AUTIZA X3",                   0xDAC133E3, 1) \
    X("LDRSB W?, [X?,#?]",     "LDRSB W0, [X1,#5]",           0x39C01420, 1) \
    X("LDRSB W?, [X?,#?]",     "LDRSB X0, [X1,#5]",           0x39801420, 0) \
    X("LDRSB ?, [X?,#?]",      "LDRSB X0, [X1,#5]",           0x39801420, 1) \
    X("LDRSB ?, [X?,#?]",      "LDRB W0, [X1,#5]",            0x39401420, 0) \
    X("LDRSH X?, [X?,#?]!",    "LDRSH X0, [X1,#-2]!",         0x789FEC20, 1) \
    X("LDURSH ?, [X?,#?]",     "LDURSH W0, [X1,#-2]",         0x78DFE020, 1) \
    X("LDPSW X?, X?, [SP,#?]", "LDPSW X1, X2, [SP,#0x10]",    0x69420BE1, 1) \
    X("LDPSW X?, X?, [SP,#?]", "LDP X1, X2, [SP,#0x10]",      0xA9410BE1, 0) \
    X("LDNP X?, X?, [X?,#?]",  "LDNP X1, X2, [X3,#0x10]",     0xA8410861, 1) \
    X("LDNP X?, X?, [X?,#?]",  "LDP X1, X2, [X3,#0x10]",      0xA9410861, 0) \
    X("LDXR ?, [X?]",          "LDXR X0, [X1]",               0xC85F7C20, 1) \
    X("LDXR ?, [X?]",          "LDXR W0, [X1]",               0x885F7C20, 1) \
    X("LDXR ?, [X?]",          "LDAXR W0, [X1]",              0x885FFC20, 0) \
    X("LDXR W?, [X?]",         "LDXR X0, [X1]",               0xC85F7C20, 0) \
    X("STXR W?, X?, [X?]",     "STXR W2, X0, [X1]",           0xC8027C20, 1) \
    X("STXR W?, X?, [X?]",     "STXR W2, W0, [X1]",           0x88027C20, 0) \
    X("STXR ?, ?, [X?]",       "STXR W2, W0, [X1]",           0x88027C20, 1) \
    X("STLR ?, [X?]",          "STLR X0, [SP]",               0xC89FFFE0, 1) \
    X("LDARB W?, [X?]",        "LDARB W0, [X1]",              0x08DFFC20, 1) \
    X("LDARB W?, [X?]",        "LDAR W0, [X1]",               0x88DFFC20, 0) \
    X("CAS ?, ?, [X?]",        "CAS X0, X1, [X2]",            0xC8A07C41, 1) \
    X("CAS ?, ?, [X?]",        "CASA X0, X1, [X2]",           0xC8E07C41, 0) \
    X("CAS ?, ?, [X?]",        "CASB W0, W1, [X2]",           0x08A07C41, 0) \
    X("CASAL W?, W?, [X?]",    "CASAL W0, W1, [X2]",          0x88E0FC41, 1) \
    X("LDADDAL ?, ?, [X?]",    "LDADDAL X0, X1, [X2]",        0xF8E00041, 1) \
    X("LDADDAL ?, ?, [X?]",    "LDADDAL W0, W1, [X2]",        0xB8E00041, 1) \
    X("LDADDAL ?, ?, [X?]",    "LDADD W0, W1, [X2]",          0xB8200041, 0) \
    X("LDADDAL ?, ?, [X?]",    "LDCLRAL W0, W1, [X2]",        0xB8E01041, 0) \
    X("STADD W?, [X?]",        "STADD W0, [X2]",              0xB820005F, 1) \
    X("STADD W?, [X?]",        "LDADD W0, W1, [X2]",          0xB8200041, 0) \
    X("SWP X?, X?, [X?]",      "SWP X0, X1, [X2]",            0xF8208041, 1) \
    X("SWP X?, X?, [X?]",      "LDADD X0, X1, [X2]",          0xF8200041, 0) \
    X("LSL X?, X?, #?",        "LSL X0, X1, #3",              0xD37DF020, 1) \
    X("LSL X?, X?, #?",        "LSR X0, X1, #3",              0xD343FC20, 1) \
    X("LSL X?, X?, #?",        "LSL W0, W1, #3",              0x531D7020, 0) \
    X("LSL X?, X?, #?",        "ASR X0, X1, #3",              0x9343FC20, 0) \
    X("LSL ?, ?, #3",          "LSL X0, X1, #3",              0xD37DF020, 1) \
    X("LSL ?, ?, #3",          "LSL W0, W1, #3",              0x531D7020, 1) \
    X("LSL ?, ?, #3",          "LSL X0, X1, #4",              0xD37CEC20, 0) \
    X("LSL ?, ?, #40",         "LSL X0, X1, #40",             0xD3585C20, 1) \
    X("LSR X?, X?, #?",        "LSR X0, X1, #3",              0xD343FC20, 1) \
    X("LSR X?, X?, #?",        "LSL X0, X1, #3",              0xD37DF020, 0) \
    X("LSR X?, X?, #?",        "UBFX X0, X1, #3, #8",         0xD3432820, 0) \
    X("LSR ?, ?, #?",          "LSR W0, W1, #3",              0x53037C20, 1) \
    X("ASR W?, W?, #?",        "ASR W0, W1, #31",             0x131F7C20, 1) \
    X("ASR W?, W?, #?",        "LSR W0, W1, #31",             0x531F7C20, 0) \
    X("ROR X?, X?, #?",        "ROR X0, X1, #7",              0x93C11C20, 1) \
    X("ROR X?, X?, #?",        "EXTR X0, X1, X2, #7",         0x93C21C20, 1) \
    X("ROR X0, X1, #?",        "EXTR X0, X1, X2, #7",         0x93C21C20, 0) \
    X("LSL X?, X?, X?",        "LSL X0, X1, X2",              0x9AC22020, 1) \
    X("LSL X?, X?, X?",        "LSR X0, X1, X2",              0x9AC22420, 0) \
    X("LSL X?, X?, X?",        "LSL X0, X1, #2",              0xD37EF420, 0) \
    X("UBFX X?, X?, #?, #8",   "UBFX X0, X1, #4, #8",         0xD3442C20, 1) \
    X("UBFX X?, X?, #4, #?",   "UBFX X0, X1, #4, #9",         0xD3443020, 1) \
    X("UBFX X?, X?, #4, #?",   "UBFX X0, X1, #5, #9",         0xD3453420, 0) \
    X("UBFX X?, X?, #?, #?",   "SBFX X0, X1, #4, #9",         0x93443020, 0) \
    X("UBFIZ W?, W?, #?, #5",  "UBFIZ W0, W1, #3, #5",        0x531D1020, 1) \
    X("UBFIZ W?, W?, #?, #5",  "UBFIZ W0, W1, #3, #6",        0x531D1420, 0) \
    X("BFI X?, X?, #8, #?",    "BFI X0, X1, #8, #4",          0xB3780C20, 1) \
    X("SXTB ?, W?",            "SXTB X0, W1",                 0x93401C20, 1) \
    X("SXTB ?, W?",            "SXTB W0, W1",                 0x13001C20, 1) \
    X("SXTB ?, W?",            "SXTH W0, W1",                 0x13003C20, 0) \
    X("SXTW ?, W?",            "SXTW X0, W1",                 0x93407C20, 1) \
    X("UXTB ?, W?",            "UXTB W0, W1",                 0x53001C20, 1) \
    X("UXTB ?, W?",            "UXTH W0, W1",                 0x53003C20, 0) \
    X("UBFM X?, X?, #?, #?",   "UBFM X0, X1, #4, #11",        0xD3442C20, 1) \
    X("UBFM X?, X?, #?, #?",   "SBFM X0, X1, #4, #11",        0x93442C20, 0) \
    X("CSEL X?, X?, X?, ?",    "CSEL X0, X1, X2, LT",         0x9A82B020, 1) \
    X("CSEL X?, X?, X?, ?",    "CSINC X0, X1, X2, LT",        0x9A82B420, 0) \
    X("CSEL X?, X?, X?, EQ",   "CSEL X0, X1, X2, NE",         0x9A821020, 0) \
    X("CSET W?, ?",            "CSET W0, EQ",                 0x1A9F17E0, 1) \
    X("CSET W?, ?",            "CSET W0, LE",                 0x1A9FC7E0, 1) \
    X("CSET W?, ?",            "CSINC W0, W1, W2, EQ",        0x1A820420, 0) \
    X("CSET W?, EQ",           "CSET W0, NE",                 0x1A9F07E0, 0) \
    X("CSET W?, EQ",           "CSINC W0, WZR, WZR, NE",      0x1A9F17E0, 1) \
    X("CSETM ?, ?",            "CSETM X0, NE",                0xDA9F03E0, 1) \
    X("CINC X?, X?, ?",        "CINC X0, X1, LT",             0x9A81A420, 1) \
    X("CINC X0, X1, ?",        "CSINC X0, X1, X2, LT",        0x9A82B420, 0) \
    X("CNEG W?, W?, GE",       "CNEG W0, W1, GE",             0x5A81B420, 1) \
    X("CCMP X?, X?, #?, ?",    "CCMP X0, X1, #4, NE",         0xFA411004, 1) \
    X("CCMP X?, X?, #?, ?",    "CCMP X0, #1, #4, NE",         0xFA411804, 0) \
    X("CCMP X?, #?, #?, ?",    "CCMP X0, #1, #4, NE",         0xFA411804, 1) \
    X("CCMP X?, #?, #?, ?",    "CCMN X0, #1, #4, NE",         0xBA411804, 0) \
    X("CCMP W0, #5, #?, EQ",   "CCMP W0, #5, #8, EQ",         0x7A450808, 1) \
    X("MADD X?, X?, X?, X?",   "MADD X0, X1, X2, X3",         0x9B020C20, 1) \
    X("MADD X?, X?, X?, X?",   "MSUB X0, X1, X2, X3",         0x9B028C20, 0) \
    X("MADD X?, X?, X?, X?",   "MUL X0, X1, X2",              0x9B027C20, 1) \
    X("MUL ?, ?, ?",           "MUL W0, W1, W2",              0x1B027C20, 1) \
    X("MUL ?, ?, ?",           "MADD W0, W1, W2, W3",         0x1B020C20, 0) \
    X("SMULL X?, W?, W?",      "SMULL X0, W1, W2",            0x9B227C20, 1) \
    X("SMULL X?, W?, W?",      "UMULL X0, W1, W2",            0x9BA27C20, 0) \
    X("UDIV ?, ?, ?",          "UDIV X0, X1, X2",             0x9AC20820, 1) \
    X("UDIV ?, ?, ?",          "SDIV X0, X1, X2",             0x9AC20C20, 0) \
    X("BIC X?, X?, X?",        "BIC X0, X1, X2",              0x8A220020, 1) \
    X("BIC X?, X?, X?",        "AND X0, X1, X2",              0x8A020020, 0) \
    X("BIC X?, X?, X?, ?",     "BIC X0, X1, X2, ROR #3",      0x8AE20C20, 1) \
    X("MVN X?, X?",            "MVN X0, X1",                  0xAA2103E0, 1) \
    X("MVN X?, X?",            "MOV X0, X1",                  0xAA0103E0, 0) \
    X("NEG X?, X?",            "NEG X0, X1",                  0xCB0103E0, 1) \
    X("NEG X?, X?",            "SUB X0, X1, X2",              0xCB020020, 0) \
    X("NEGS ?, ?",             "NEGS W0, W1",                 0x6B0103E0, 1) \
    X("ADC ?, ?, ?",           "ADC W0, W1, W2",              0x1A020020, 1) \
    X("ADC ?, ?, ?",           "ADCS W0, W1, W2",             0x3A020020, 0) \
    X("ORR X?, X?, X?, ?",     "ORR X0, X1, X2, ROR #7",      0xAAC21C20, 1) \
    X("ORR X?, X?, X?, ?",     "ORR X0, X1, X2",              0xAA020020, 1) \
    X("ORR X?, X?, X?, ?",     "ORN X0, X1, X2",              0xAA220020, 0) \
    X("ADD X?, X?, X?, ?",     "ADD X0, X1, X2, ASR #3",      0x8B820C20, 1) \
    X("ADD X?, X?, X?, ?",     "ADD X0, X1, W2, UXTW #2",     0x8B224820, 1) \
    X("LDR D?, [X?,#?]",       "LDR D0, [X1,#8]",             0xFD400420, 1) \
    X("LDR D?, [X?,#?]",       "LDR X0, [X1,#8]",             0xF9400420, 0) \
    X("LDR D?, [X?,#?]",       "LDR S0, [X1,#8]",             0xBD400820, 0) \
    X("LDR D?, [X?,#?]",       "STR D0, [X1,#8]",             0xFD000420, 0) \
    X("LDR Q?, [X?,#?]",       "LDR Q0, [X1,#0x10]",          0x3DC00420, 1) \
    X("LDR Q?, [X?,#?]",       "LDR B0, [X1,#0x10]",          0x3D404020, 0) \
    X("LDR ?, [X?,#?]",        "LDR D0, [X1,#8]",             0xFD400420, 0) \
    X("LDR S0, [X1,#?]",       "LDR S0, [X1,#0x40]",          0xBD404020, 1) \
    X("STR D?, [SP,#?]!",      "STR D8, [SP,#-0x10]!",        0xFC1F0FE8, 1) \
    X("LDUR Q?, [X?,#?]",      "LDUR Q0, [X0,#-16]",          0x3CDF0000, 1) \
    X("LDR D?, #?",            "LDR D0, #0x100",              0x5C000800, 1) \
    X("LDR D?, #?",            "LDR X0, #0x100",              0x58000800, 0) \
    X("LDR D?, #?",            "LDR Q0, #0x100",              0x9C000800, 0) \
    X("STP D?, D?, [SP,#?]!",  "STP D9, D8, [SP,#-0x20]!",    0x6DBE23E9, 1) \
    X("STP D?, D?, [SP,#?]!",  "STP X9, X8, [SP,#-0x20]!",    0xA9BE23E9, 0) \
    X("STP D?, D?, [SP,#?]!",  "STP Q9, Q8, [SP,#-0x20]!",    0xADBF23E9, 0) \
    X("LDP Q?, Q?, [X?]",      "LDP Q0, Q1, [X1]",            0xAD400420, 1) \
    X("LDP Q?, Q?, [X?,#?]",   "LDP Q0, Q1, [X1,#0x20]",      0xAD410420, 1) \
    X("LDP ?, ?, [X?,#?]",     "LDP D0, D1, [X1,#0x20]",      0x6D420420, 0) \
    X("FMOV D?, D?",           "FMOV D0, D1",                 0x1E604020, 1) \
    X("FMOV D?, D?",           "FMOV S0, S1",                 0x1E204020, 0) \
    X("FMOV D?, ?",            "FMOV D0, D1",                 0x1E604020, 1) \
    X("FMOV ?, ?",             "FMOV S0, S1",                 0x1E204020, 1) \
    X("FMOV D?, X?",           "FMOV D0, X1",                 0x9E670020, 1) \
    X("FMOV D?, X?",           "FMOV X0, D1",                 0x9E660020, 0) \
    X("FMOV D?, #?",           "FMOV D0, #1.0",               0x1E6E1000, 1) \
    X("FMOV D?, #?",           "FMOV S0, #1.0",               0x1E2E1000, 0) \
    X("FMOV D?, #?",           "FMOV D0, D1",                 0x1E604020, 0) \
    X("ADD X?, X?, #0x123, LSL #?", "ADD X0, X1, #0x123, LSL #12", 0x91448C20, 1) \
    X("ADD X?, X?, #0x123, LSL #?", "ADD X0, X1, #0x123",       0x91048C20, 1) \
    X("SUB ?, ?, #0x123, LSL #?", "SUB W2, W3, #0x123, LSL #12", 0x51448C62, 1) \
    X("TST ?, #0x3FFFC0",        "TST X0, #0x3FFFC0",           0xF27A3C1F, 1) \
    X("TST ?, #0x3FFFC0",        "TST W0, #0x3FFFC0",           0x721A3C1F, 1) \
    X("MOV ?, #0xFFFFFFFF00000000", "MOV X0, #0xFFFFFFFF00000000", 0xB2607FE0, 1) \
    X("MOV ?, #0xFFFFFFFF00000000", "MOV X0, #0",               0xD2800000, 0) \
    X("MOV ?, #0x1FFFE00",       "MOV X1, #0x1FFFE00",          0xB2773FE1, 1) \
    X("MOV ?, #0x1FFFE00",       "MOV W1, #0x1FFFE00",          0x32173FE1, 1) \
    X("MOV ?, #0xFFFFFFFF",      "MOV W0, #-1",                 0x12800000, 1) \
    X("MOV ?, #0xFFFFFFFF",      "MOV X0, #0xFFFFFFFF",         0xB2407FE0, 1) \
    X("FMOV D0, #1.0",         "FMOV D0, #-1.0",              0x1E7E1000, 0)

struct Word { uint32_t pat, mask; };
template <class P> static Word word(const P& p, size_t idx = 0) {
    Word w;
    memcpy(&w.pat, p.pattern() + idx * 4, 4);
    memcpy(&w.mask, p.mask() + idx * 4, 4);
    return w;
}

static void concrete() {
    int n = 0;
#define CASE(text, enc) { \
        const auto w = word(ARM_PATTERN(text)); \
        if (w.pat != (enc) || w.mask != 0xFFFFFFFF) { \
            printf("FAIL %s: pat=%08X mask=%08X, want %08X/FFFFFFFF\n", text, w.pat, w.mask, (enc)); exit(1); \
        } ++n; }
    CONCRETE(CASE)
#undef CASE
    printf("  concrete encodings ok (%d)\n", n);
}

static void wildcards() {
    int n = 0;
#define CASE(ptext, itext, enc, want) { \
        const auto w = word(ARM_PATTERN(ptext)); \
        if ((((enc) & w.mask) == w.pat) != (want)) { \
            printf("FAIL %s vs %s: should%s match (pat=%08X mask=%08X enc=%08X)\n", ptext, itext, (want) ? "" : " not", w.pat, w.mask, (enc)); exit(1); \
        } ++n; }
    WILDCARD(CASE)
#undef CASE
    printf("  wildcard matching ok (%d)\n", n);
}

// A bad operand (out of range, the wrong register, missing or extra) is an error: a compile error for ArmPattern
// (tests/CMakeLists.txt checks one), a throw for RuntimeArmPattern. Only an unknown mnemonic becomes a whole-word
// wildcard (mask 0), which the IDA plugin warns about
static void bad_operands() {
    static const char* const bad[] = {
        // Registers: out of range, not one, the wrong kind or size, SP where 31 is the zero register and back
        "ADD X0, X1, X32", "ADD X0, X1, X31", "ADD X0, X1, FOO", "ADD X0, W1, X2", "ADD XZR, X1, #1", "ADDS SP, X1, #1",
        "ADD X0, XZR, X1, UXTX", "ORR SP, X1, X2", "ORR X0, SP, #1", "MOV SP, XZR", "MOV X0, W1", "LDR SP, [X1]",
        "LDR X0, [XZR]", "LDR X0, [W1]", "LDR X0, [X1, W2]", "LDR X0, [X1, X2, UXTW]", "LDRB X0, [X1]", "LDRSW W0, [X1]",
        "LDRB D0, [X1]", "LDRSB D0, [X1]", "LDRAA W0, [X1]", "LDR B0, #0x10", "STP X0, W1, [SP]", "STP X0, D1, [SP]",
        "LDP B0, B1, [X2]", "LDPSW W0, W1, [X2]", "ADR W0, #8", "BR W0", "PACIA X0, XZR", "CSEL X0, X1, W2, EQ",
        "CCMP X0, W1, #0, EQ", "SXTB X0, X1", "SXTW W0, W1", "UXTB X0, W1", "SMADDL X0, X1, W2, X3",
        "STXR X0, X1, [X2]", "LDADD W0, X1, [X2]", "LDADDB X0, X1, [X2]", "SWP W0, W1, [XZR]", "FMOV D0, SP",
        "FMOV S0, X1", "FMOV D0, W1", "FMOV D0, S1",
        // Immediates: not a number, out of range, unaligned
        "BL _printf", "B #2", "B #0x8000000", "B.EQ #1", "CBZ X0, #0x100000", "TBZ X0, #3, #0x8000", "LDR X0, #3",
        "ADR X0, #0x100000", "ADRP X0, #0x100000000", "ADD X0, X1, #0x1001", "ADD X0, X1, #1, LSL #3",
        "ORR X0, X1, #0", "BIC X0, X1, #-1", "MOV X0, #0x123456789", "MOVZ X0, #0x10000", "MOVZ W0, #1, LSL #32",
        "MOVZ X0, #1, LSL #8", "LDR W0, [X1,#0x4000]", "LDUR X0, [X1,#0x100]", "LDR X0, [X1, X2, LSL #2]",
        "STP X0, X1, [SP, #4]", "STP X0, X1, [SP, #0x200]", "LDRAA X0, [X1,#4]", "LDRAA X0, [X1,#4096]",
        "TBZ W0, #32, #8", "TBZ X0, #64, #8", "TBZ X0, #4294967299, #8", "SVC #0x10000", "SVC #-1",
        "CCMP X0, #32, #0, EQ", "CCMP X0, #1, #16, EQ", "LSL X0, X1, #64", "LSL W0, W1, #32", "UBFX W0, W1, #30, #4",
        "FMOV D0, #0.1", "FMOV D0, #32.0", "FMOV D0, #-0.0", "FMOV Q0, #1.0",
        // Shifts, extends and conditions
        "ADD X0, X1, X2, ROR #3", "ADD X0, X1, X2, LSL", "CMP SP, X5, LSL", "LDR X0, [X1, X2, ROR #3]", "B.XX #0x10",
        "CSET W0, AL", "CINC X0, X1, NV", "CSEL X0, X1, X2, XX", "BTI X",
        // Missing or extra operands, brackets
        "ADD X0, X1", "ADD X0, X1, X2, X3", "MOV X0", "LDR X0, X1", "LDR X0, [X1, #8", "LDR X0, [X1, #8] junk",
        "LDUR X0, [X1, #8]!", "LDP X0, X1, [SP]!", "LDNP X0, X1, [X2,#16]!", "STP X0, X1", "BR", "RET X0, X1",
        "NOP X0", "SVC", "CSEL X0, X1, X2", "LSL X0, X1", "UBFX X0, X1, #3", "MADD X0, X1, X2", "LDXR X0, X1",
        "LDXR X0, [X1",
    };
    int n = 0;
    for (const char* text : bad) {
        bool threw = false;
        try { patterns::RuntimeArmPattern p(text); } catch (const std::logic_error&) { threw = true; }
        if (!threw) { printf("FAIL %s: accepted\n", text); exit(1); }
        ++n;
    }
    // The error names the line
    try { patterns::RuntimeArmPattern p("NOP\nADD X0, X1, X32"); } catch (const std::logic_error& e) { CHECK(strstr(e.what(), "(ADD X0, X1, X32)")); }
    CHECK(word(ARM_PATTERN("FOO X0, X1")).mask == 0);
    CHECK(word(ARM_PATTERN("LDADDX W0, W1, [X2]")).mask == 0);
    CHECK(word(ARM_PATTERN("STADDA W0, [X2]")).mask == 0);
    CHECK(word(ARM_PATTERN("CASP X0, X1, X2, X3, [X4]")).mask == 0);
    printf("  bad operands ok (%d)\n", n);
}

template <class A, class B> static bool same(const A& a, const B& b) {
    return a.length() == b.length() && a.offset() == b.offset() && a.deref() == b.deref() && a.aligned() == b.aligned()
        && !memcmp(a.pattern(), b.pattern(), a.length()) && !memcmp(a.mask(), b.mask(), a.length());
}

// Each line is parsed on its own: no instruction may turn into a wildcard because of what follows it
static void line_formats() {
    constexpr auto canon = ARM_PATTERN("NOP\nX LDR W8, [X8,#0x18]\nRET\n/d");
    CHECK(canon.length() == 12 && canon.offset() == 4 && canon.deref() && canon.aligned());
    CHECK(word(canon, 0).pat == 0xD503201F && word(canon, 1).pat == 0xB9401908 && word(canon, 2).pat == 0xD65F03C0);
    for (size_t k = 0; k < 3; ++k) CHECK(word(canon, k).mask == 0xFFFFFFFF);
    CHECK(same(canon, ARM_PATTERN("\tNOP\r\n\tX LDR W8, [X8,#0x18]\r\n\tRET\r\n/d")));         // tabs, CRLF
    CHECK(same(canon, ARM_PATTERN("  NOP  \n\n  X LDR W8, [X8, #0x18]  \n\n  RET\n/d")));     // padding, blank lines
    CHECK(same(canon, ARM_PATTERN("nop\nx ldr    w8, [x8, #0x18]\nret\n/d")));               // lowercase, as lldb prints it
    CHECK(same(ARM_PATTERN("ADD X0, X1, #1, LSL#12"), ARM_PATTERN("ADD X0, X1, #1, LSL #12")));
    CHECK(same(ARM_PATTERN("BL #?"), ARM_PATTERN("BL ?")));
    CHECK(same(ARM_PATTERN("NOP\nRET"), ARM_PATTERN("NOP\nRET\n")));
    CHECK(same(ARM_PATTERN("NOP\nRET"), ARM_PATTERN("NOP ; comment\nRET    ; as IDA and lldb print them")));
    CHECK(ARM_PATTERN("NOP\nRET\n/a").length() == 8);
    puts("  line formats ok");
}

// A function prologue as IDA prints it (STP, MOV): must skip a similar prologue, not treat STP/MOV as wildcards
static void prologue() {
    alignas(4) static const uint32_t code[] = {
        0xD10083FF, 0xA9017BFD, 0x910043FD, 0xAA0103F3, 0xAA1E03E0,   // SUB SP, SP, #0x20; STP; ADD X29; MOV; MOV
        0xA9BE4FF4, 0xA9017BFD, 0x910043FD, 0xAA0103F3, 0xAA1E03E0,   // STP X20, X19, [SP,#-0x20]!; ... the one wanted
    };
    const auto bytes = reinterpret_cast<const uint8_t*>(code);
#define PROLOGUE "STP             X20, X19, [SP,#?]!\n" \
                 "STP             X29, X30, [SP,#?]\n" \
                 "ADD             X29, SP, #0x10\n" \
                 "MOV             X19, X1\n" \
                 "MOV             X0, X30"
    CHECK(ARM_PATTERN(PROLOGUE).find<const uint32_t*>(bytes, sizeof code) == code + 5);
    CHECK(patterns::RuntimeArmPattern(PROLOGUE).find<const uint32_t*>(bytes, sizeof code) == code + 5);
#undef PROLOGUE
    puts("  prologue ok");
}

// RuntimeArmPattern: the same parse as ArmPattern, from text only known at runtime
static void runtime_patterns() {
    int n = 0;
#define CASE(text, ...) { CHECK(same(ARM_PATTERN(text), patterns::RuntimeArmPattern(text))); ++n; }
    CONCRETE(CASE)
#undef CASE
#define CASE(ptext, ...) { CHECK(same(ARM_PATTERN(ptext), patterns::RuntimeArmPattern(ptext))); ++n; }
    WILDCARD(CASE)
#undef CASE
    constexpr auto canon = ARM_PATTERN("NOP\nX LDR W8, [X8,#0x18]\nRET\n/d");
    CHECK(same(canon, patterns::RuntimeArmPattern("nop\r\n  x ldr    w8, [x8, #0x18]\n\nret\n/d")));
    CHECK(same(ARM_PATTERN("NOP\nRET\n/a"), patterns::RuntimeArmPattern("NOP\nRET\n/a")));
    const char unterminated[] = { 'N', 'O', 'P', '\n', 'R', 'E', 'T', 'X' };   // the length bounds the text
    CHECK(same(ARM_PATTERN("NOP\nRET"), patterns::RuntimeArmPattern(unterminated, 7)));
    CHECK(patterns::RuntimeArmPattern("").length() == 0 && patterns::RuntimeArmPattern("/d").length() == 0);
    printf("  runtime patterns ok (%d)\n", n);
}

// ArmXORPattern: the same encoding and results as ArmPattern, different stored words per definition site
static void xor_patterns() {
    constexpr auto plain = ARM_PATTERN("NOP\nX LDR W8, [X8,#0x18]\nRET\n/d");
    constexpr auto a = "NOP\nX LDR W8, [X8,#0x18]\nRET\n/d"_armxorpattern;
    constexpr auto b = "NOP\nX LDR W8, [X8,#0x18]\nRET\n/d"_armxorpattern;
    auto m = ARM_XOR_PATTERN("NOP\nX LDR W8, [X8,#0x18]\nRET\n/d");   // deliberately not constexpr: still built at compile time
    static_assert(a.length() == 12 && a.offset() == 4 && a.deref() && a.aligned());
    CHECK(memcmp(a.pattern(), b.pattern(), 12) != 0 && memcmp(a.pattern(), m.pattern(), 12) != 0);
    CHECK(memcmp(a.mask(), b.mask(), 12) != 0 && memcmp(a.mask(), plain.mask(), 12) != 0);
    for (size_t k = 0; k < 12; ++k) CHECK(a[k] == plain[k] && m[k] == plain[k] && a.unmask(k) == plain.mask()[k]);

    alignas(4) static const uint32_t code[] = { 0x52800000, 0xD503201F, 0xB9401908, 0xD65F03C0, 0 };
    const auto bytes = reinterpret_cast<const uint8_t*>(code);
    CHECK(a.match(bytes, sizeof code) == bytes + 4);
    CHECK(b.match(bytes, sizeof code) == bytes + 4);
    CHECK(m.match(bytes, sizeof code) == plain.match(bytes, sizeof code));
    CHECK(ARM_XOR_PATTERN("NOP\nX LDR W?, [X?,#?]").find<const uint8_t*>(bytes, sizeof code) == bytes + 8);
    puts("  xor patterns ok");
}

// /d on hand-built code: ADRP beyond 2GB, and ADRP followers bounded by the scanned size
static void deref_synthetic() {
    static const uint32_t far_code[] = { 0x528EEEE9, 0x90480000, 0x91004000, 0 };   // MOVZ W9, #0x7777; ADRP X0, #0x90000000; ADD X0, X0, #0x10
    const auto far_page = reinterpret_cast<uintptr_t>(&far_code[1]) & ~uintptr_t(0xFFF);
    constexpr auto adrl = ARM_PATTERN("MOVZ W9, #0x7777\nX ADRP X?, #?\n/d");
    CHECK(adrl.find<uintptr_t>(reinterpret_cast<const uint8_t*>(far_code), sizeof far_code) == far_page + 0x90000000 + 0x10);

    static const uint32_t neg_code[] = { 0x528EEEE9, 0x90B80000, 0 };               // ADRP X0, #-0x90000000
    const auto neg_page = reinterpret_cast<uintptr_t>(&neg_code[1]) & ~uintptr_t(0xFFF);
    CHECK(adrl.find<uintptr_t>(reinterpret_cast<const uint8_t*>(neg_code), sizeof neg_code) == neg_page - 0x90000000);

    static const uint32_t adr_back[] = { 0x528EEEE9, 0x10FFFFE3, 0 };               // ADR X3, #-0x4
    CHECK(ARM_PATTERN("MOVZ W9, #0x7777\nX ADR X?, #?\n/d").find<const uint32_t*>(reinterpret_cast<const uint8_t*>(adr_back), sizeof adr_back) == adr_back);

    // ADRP X0, #0x1000; ADD X1, X0, #0x10; LDR X2, [X1,#8]: ADD into another register, then a load through it
    static const uint32_t chain[] = { 0x528EEEE9, 0xB0000000, 0x91004001, 0xF9400422, 0 };
    const auto page = reinterpret_cast<uintptr_t>(&chain[1]) & ~uintptr_t(0xFFF);
    const auto bytes = reinterpret_cast<const uint8_t*>(chain);
    CHECK(adrl.find<uintptr_t>(bytes, sizeof chain) == page + 0x1000 + 0x10 + 8);
    CHECK(adrl.find<uintptr_t>(bytes, 12) == page + 0x1000 + 0x10);   // the LDR is past the end: not read
    CHECK(adrl.find<uintptr_t>(bytes, 8) == page + 0x1000);           // ADRP is the last word scanned
    const patterns::RuntimeArmPattern rt("MOVZ W9, #0x7777\nX ADRP X?, #?\n/d");
    bool is_value = true;
    CHECK(rt.resolve(rt.match(bytes, sizeof chain), bytes + sizeof chain, &is_value) == reinterpret_cast<void*>(page + 0x1000 + 0x10 + 8));
    CHECK(!is_value);

    // Values rather than addresses: the immediate of MOVZ, the offset of a lone LDR
    const auto movz = ARM_PATTERN("X MOVZ W9, #0x7777\n/d");
    CHECK(movz.resolve(movz.match(bytes, sizeof chain), bytes + sizeof chain, &is_value) == reinterpret_cast<void*>(0x7777) && is_value);
    const auto ldr = ARM_PATTERN("ADD X1, X0, #0x10\nX LDR X2, [X1,#?]\n/d");
    CHECK(ldr.resolve(ldr.match(bytes, sizeof chain), bytes + sizeof chain, &is_value) == reinterpret_cast<void*>(8) && is_value);

    // MOVZ/MOVN shifts, and /d values of loads/stores the old decoders missed (LDUR, LDRB, big STR offsets)
    static const uint32_t vals[] = {
        0xD2A00020,   // MOVZ X0, #1, LSL #16
        0xD2C00020,   // MOVZ X0, #1, LSL #32
        0x92800000,   // MOVN X0, #0 (MOV X0, #-1)
        0xF85F83A0,   // LDUR X0, [X29,#-8]
        0x39448C20,   // LDRB W0, [X1,#0x123]
        0xF9200020,   // STR X0, [X1,#0x4000]
    };
    const int64_t want[] = { 0x10000, 0x100000000, -1, -8, 0x123, 0x4000 };
    for (size_t k = 0; k < 6; ++k) {
        const patterns::RuntimeArmPattern p("X ?\n/d");
        const auto at = reinterpret_cast<const uint8_t*>(&vals[k]);
        CHECK(p.resolve(at, at + 4, &is_value) == reinterpret_cast<void*>(want[k]) && is_value);
    }
    // Branches and literal loads resolve to their target
    static const uint32_t imm19[] = {
        0x54000100, 0xB4000100, 0x58000100,   // B.EQ, CBZ X0, LDR X0 (literal): #0x20
        0x5C000100, 0x9C000100,               // LDR D0, LDR Q0 (literal): #0x20
        0x36180100, 0xB7400101,               // TBZ W0, #3 and TBNZ X1, #40: #0x20
    };
    for (auto& w : imm19) {
        const auto at = reinterpret_cast<const uint8_t*>(&w);
        CHECK(patterns::RuntimeArmPattern("X ?\n/d").resolve(at, at + 4) == at + 0x20);
    }

    // ADRP X8, #0x5000 followed by: LDRB, LDRSW, pre-index with a negative offset, post-index, an unrelated
    // ADRP between ADRP and its ADD, and NOPs in the chain
    struct { uint32_t next[2]; int64_t add; } follow[] = {
        { { 0x39448D00, 0 }, 0x123 },        // LDRB W0, [X8,#0x123]
        { { 0xB9801100, 0 }, 0x10 },         // LDRSW X0, [X8,#0x10]
        { { 0xF85F8D00, 0 }, -8 },           // LDR X0, [X8,#-8]!
        { { 0xF8408500, 0 }, 0 },            // LDR X0, [X8],#8
        { { 0x90000009, 0x91004108 }, 0x10 },  // ADRP X9, #0; ADD X8, X8, #0x10
        { { 0xD503201F, 0x91004108 }, 0x10 },  // NOP; ADD X8, X8, #0x10
        { { 0xD503201F, 0x39448D00 }, 0x123 }, // NOP; LDRB W0, [X8,#0x123]
        { { 0xFD400D00, 0 }, 0x18 },         // LDR D0, [X8,#0x18]
        { { 0x3DC00901, 0 }, 0x20 },         // LDR Q1, [X8,#0x20]
        { { 0xBC5FC102, 0 }, -4 },           // LDUR S2, [X8,#-4]
        { { 0xFD400128, 0x39448D00 }, 0x123 }, // LDR D8, [X9] (not X8); LDRB W0, [X8,#0x123]
        { { 0xF90003E8, 0x39448D00 }, 0x123 }, // STR X8, [SP]; LDRB W0, [X8,#0x123]
    };
    for (auto& f : follow) {
        alignas(4) uint32_t code[4] = { 0x528EEEE9, 0xB0000028, f.next[0], f.next[1] };   // MOVZ W9; ADRP X8, #0x5000
        const auto b = reinterpret_cast<const uint8_t*>(code);
        const auto pg = (reinterpret_cast<uintptr_t>(&code[1]) & ~uintptr_t(0xFFF)) + 0x5000;
        CHECK(adrl.find<uintptr_t>(b, sizeof code) == pg + f.add);
    }
    // An instruction /d can't resolve (STP X29, X30, [SP,#-0x10]!): no result, not an exception
    alignas(4) const uint32_t stp[] = { 0xA9BF7BFD };
    CHECK(patterns::RuntimeArmPattern("X ?\n/d").find<void*>(reinterpret_cast<const uint8_t*>(stp), 4) == nullptr);
    puts("  /d on synthetic code ok");
}

#if defined(PATTERNS_ARM64) && defined(__APPLE__)
#define SYM(x) "_" x
#define ASM_LINE(text, ...) text "\n"
#define ASM_WILD(ptext, itext, ...) itext "\n"
__asm__(".data\n.p2align 2\n.arch armv8.5-a+fp16+lse+rcpc+pauth\n.globl " SYM("asm_concrete") "\n" SYM("asm_concrete") ":\n" CONCRETE(ASM_LINE)
        ".globl " SYM("asm_wildcard") "\n" SYM("asm_wildcard") ":\n" WILDCARD(ASM_WILD));
extern "C" const uint32_t asm_concrete[], asm_wildcard[];

// The tables' encodings must still be what the assembler produces
static void assembler_agrees() {
    size_t i = 0;
#define CASE(text, enc) if (asm_concrete[i++] != (enc)) { printf("FAIL table: %s assembles to %08X\n", text, asm_concrete[i - 1]); exit(1); }
    CONCRETE(CASE)
#undef CASE
    i = 0;
#define CASE(ptext, itext, enc, want) if (asm_wildcard[i++] != (enc)) { printf("FAIL table: %s assembles to %08X\n", itext, asm_wildcard[i - 1]); exit(1); }
    WILDCARD(CASE)
#undef CASE
    puts("  tables match the assembler ok");
}

// /d against code whose ADRP/ADD/LDR/BL operands were filled in by the linker
extern "C" int arm_target_data;
int arm_target_data = 0x1234;
extern "C" void arm_target_func() {}
extern "C" const uint32_t arm_reloc_code[];
__asm__(".text\n.p2align 2\n.globl " SYM("arm_reloc_code") "\n" SYM("arm_reloc_code") ":\n"
        "  movz w9, #0x7777\n"
        "  adrp x0, " SYM("arm_target_data") "@PAGE\n"
        "  add  x0, x0, " SYM("arm_target_data") "@PAGEOFF\n"
        "  movz w9, #0x6666\n"
        "  adrp x8, " SYM("arm_target_data") "@PAGE\n"
        "  add  x1, x8, " SYM("arm_target_data") "@PAGEOFF\n"      // different destination register
        "  movz w9, #0x5555\n"
        "  adrp x8, " SYM("arm_target_data") "@PAGE\n"
        "  ldr  w2, [x8, " SYM("arm_target_data") "@PAGEOFF]\n"
        "  movz w9, #0x4444\n"
        "  bl   " SYM("arm_target_func") "\n"
        "  movz w9, #0x3333\n"
        "  b    " SYM("arm_target_func") "\n"
        "  ret\n");

static void deref_relocated() {
    const auto code = reinterpret_cast<const uint8_t*>(arm_reloc_code);
    const size_t n = 14 * 4;
    const void* data = &arm_target_data;
    const void* func = reinterpret_cast<const void*>(&arm_target_func);
    CHECK(ARM_PATTERN("MOVZ W9, #0x7777\nX ADRP X?, #?\nADD X?, X?, #?\n/d").find<void*>(code, n) == data);
    CHECK(ARM_PATTERN("MOVZ W9, #0x6666\nX ADRP X?, #?\nADD X?, X?, #?\n/d").find<void*>(code, n) == data);
    CHECK(ARM_PATTERN("MOVZ W9, #0x5555\nX ADRP X?, #?\nLDR W?, [X?,#?]\n/d").find<void*>(code, n) == data);
    CHECK(ARM_PATTERN("MOVZ W9, #0x4444\nX BL ?\n/d").find<void*>(code, n) == func);
    CHECK(ARM_PATTERN("MOVZ W9, #0x3333\nX B #?\n/d").find<void*>(code, n) == func);
    CHECK(ARM_PATTERN("MOVZ W9, #0x4444\nX BL ?").find<const uint8_t*>(code, n) == code + 40);   // no /d: the X address
    puts("  /d on relocated code ok");
}
#endif

int main() {
    concrete();
    wildcards();
    bad_operands();
    line_formats();
    prologue();
    runtime_patterns();
    xor_patterns();
    deref_synthetic();
#if defined(PATTERNS_ARM64) && defined(__APPLE__)
    assembler_agrees();
    deref_relocated();
#endif
    puts("all arm tests passed");
}
