// Original instruction templates for typed address relocation recipes.
// Synthetic operands are replaced only through public SHARC field definitions.
.SECTION/PM seg_pmco;
.GLOBAL x_i0;
x_i0:
I0 = 0x12345678;
.GLOBAL x_i1;
x_i1:
I1 = 0x12345678;
.GLOBAL x_i2;
x_i2:
I2 = 0x12345678;
.GLOBAL x_i3;
x_i3:
I3 = 0x12345678;
.GLOBAL x_i4;
x_i4:
I4 = 0x12345678;
.GLOBAL x_i5;
x_i5:
I5 = 0x12345678;
.GLOBAL x_i6;
x_i6:
I6 = 0x12345678;
.GLOBAL x_i7;
x_i7:
I7 = 0x12345678;
.GLOBAL x_i8;
x_i8:
I8 = 0x12345678;
.GLOBAL x_i9;
x_i9:
I9 = 0x12345678;
.GLOBAL x_i10;
x_i10:
I10 = 0x12345678;
.GLOBAL x_i11;
x_i11:
I11 = 0x12345678;
.GLOBAL x_i12;
x_i12:
I12 = 0x12345678;
.GLOBAL x_i13;
x_i13:
I13 = 0x12345678;
.GLOBAL x_i14;
x_i14:
I14 = 0x12345678;
.GLOBAL x_i15;
x_i15:
I15 = 0x12345678;
.GLOBAL x_i16;
x_i16:
JUMP 0x123456;
.GLOBAL x_i17;
x_i17:
CJUMP 0x123456 (DB);
.GLOBAL x_i18;
x_i18:
DM(I7, M7) = 0x12345678;

.GLOBAL x_i19;
x_i19:
RTS;
.GLOBAL x_i20;
x_i20:
NOP;
