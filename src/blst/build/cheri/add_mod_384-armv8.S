.text

.globl	add_mod_384
.hidden	add_mod_384
.type	add_mod_384,%function
.align	5
add_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

	bl	__add_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	add_mod_384,.-add_mod_384

.type	__add_mod_384,%function
.align	5
__add_mod_384:
	ldp	x10,x11,[c1]
	ldp	x16,x17,[c2]
	ldp	x12,x13,[c1,#16]
	ldp	x19,x20,[c2,#16]
	ldp	x14,x15,[c1,#32]
	ldp	x21,x22,[c2,#32]

__add_mod_384_ab_are_loaded:
	adds	x10,x10,x16
	adcs	x11,x11,x17
	adcs	x12,x12,x19
	adcs	x13,x13,x20
	adcs	x14,x14,x21
	adcs	x15,x15,x22
	adc	x3,xzr,xzr

	subs	x16,x10,x4
	sbcs	x17,x11,x5
	sbcs	x19,x12,x6
	sbcs	x20,x13,x7
	sbcs	x21,x14,x8
	sbcs	x22,x15,x9
	sbcs	xzr,x3,xzr

	csel	x10,x10,x16,lo
	csel	x11,x11,x17,lo
	csel	x12,x12,x19,lo
	csel	x13,x13,x20,lo
	csel	x14,x14,x21,lo
	csel	x15,x15,x22,lo

	ret
.size	__add_mod_384,.-__add_mod_384

.globl	add_mod_384x
.hidden	add_mod_384x
.type	add_mod_384x,%function
.align	5
add_mod_384x:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

	bl	__add_mod_384

	stp	x10,x11,[c0]
	add	c1,c1,#48
	stp	x12,x13,[c0,#16]
	add	c2,c2,#48
	stp	x14,x15,[c0,#32]

	bl	__add_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0,#48]
	stp	x12,x13,[c0,#64]
	stp	x14,x15,[c0,#80]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	add_mod_384x,.-add_mod_384x

.globl	rshift_mod_384
.hidden	rshift_mod_384
.type	rshift_mod_384,%function
.align	5
rshift_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

.Loop_rshift_mod_384:
	sub	x2,x2,#1
	bl	__rshift_mod_384
	cbnz	x2,.Loop_rshift_mod_384

	ldr	c30,[csp,#__SIZEOF_POINTER__]
	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	rshift_mod_384,.-rshift_mod_384

.type	__rshift_mod_384,%function
.align	5
__rshift_mod_384:
	sbfx	x22,x10,#0,#1
	and	x16,x22,x4
	and	x17,x22,x5
	adds	x10,x10,x16
	and	x19,x22,x6
	adcs	x11,x11,x17
	and	x20,x22,x7
	adcs	x12,x12,x19
	and	x21,x22,x8
	adcs	x13,x13,x20
	and	x22,x22,x9
	adcs	x14,x14,x21
	extr	x10,x11,x10,#1	// a[0:5] >>= 1
	adcs	x15,x15,x22
	extr	x11,x12,x11,#1
	adc	x22,xzr,xzr
	extr	x12,x13,x12,#1
	extr	x13,x14,x13,#1
	extr	x14,x15,x14,#1
	extr	x15,x22,x15,#1
	ret
.size	__rshift_mod_384,.-__rshift_mod_384

.globl	div_by_2_mod_384
.hidden	div_by_2_mod_384
.type	div_by_2_mod_384,%function
.align	5
div_by_2_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]

	bl	__rshift_mod_384

	ldr	c30,[csp,#__SIZEOF_POINTER__]
	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	div_by_2_mod_384,.-div_by_2_mod_384

.globl	lshift_mod_384
.hidden	lshift_mod_384
.type	lshift_mod_384,%function
.align	5
lshift_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

.Loop_lshift_mod_384:
	sub	x2,x2,#1
	bl	__lshift_mod_384
	cbnz	x2,.Loop_lshift_mod_384

	ldr	c30,[csp,#__SIZEOF_POINTER__]
	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	lshift_mod_384,.-lshift_mod_384

.type	__lshift_mod_384,%function
.align	5
__lshift_mod_384:
	adds	x10,x10,x10
	adcs	x11,x11,x11
	adcs	x12,x12,x12
	adcs	x13,x13,x13
	adcs	x14,x14,x14
	adcs	x15,x15,x15
	adc	x3,xzr,xzr

	subs	x16,x10,x4
	sbcs	x17,x11,x5
	sbcs	x19,x12,x6
	sbcs	x20,x13,x7
	sbcs	x21,x14,x8
	sbcs	x22,x15,x9
	sbcs	xzr,x3,xzr

	csel	x10,x10,x16,lo
	csel	x11,x11,x17,lo
	csel	x12,x12,x19,lo
	csel	x13,x13,x20,lo
	csel	x14,x14,x21,lo
	csel	x15,x15,x22,lo

	ret
.size	__lshift_mod_384,.-__lshift_mod_384

.globl	mul_by_3_mod_384
.hidden	mul_by_3_mod_384
.type	mul_by_3_mod_384,%function
.align	5
mul_by_3_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]

	bl	__lshift_mod_384

	ldp	x16,x17,[c1]
	ldp	x19,x20,[c1,#16]
	ldp	x21,x22,[c1,#32]

	bl	__add_mod_384_ab_are_loaded
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	mul_by_3_mod_384,.-mul_by_3_mod_384

.globl	mul_by_8_mod_384
.hidden	mul_by_8_mod_384
.type	mul_by_8_mod_384,%function
.align	5
mul_by_8_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]

	bl	__lshift_mod_384
	bl	__lshift_mod_384
	bl	__lshift_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	mul_by_8_mod_384,.-mul_by_8_mod_384

.globl	mul_by_3_mod_384x
.hidden	mul_by_3_mod_384x
.type	mul_by_3_mod_384x,%function
.align	5
mul_by_3_mod_384x:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]

	bl	__lshift_mod_384

	ldp	x16,x17,[c1]
	ldp	x19,x20,[c1,#16]
	ldp	x21,x22,[c1,#32]

	bl	__add_mod_384_ab_are_loaded

	stp	x10,x11,[c0]
	ldp	x10,x11,[c1,#48]
	stp	x12,x13,[c0,#16]
	ldp	x12,x13,[c1,#64]
	stp	x14,x15,[c0,#32]
	ldp	x14,x15,[c1,#80]

	bl	__lshift_mod_384

	ldp	x16,x17,[c1,#48]
	ldp	x19,x20,[c1,#64]
	ldp	x21,x22,[c1,#80]

	bl	__add_mod_384_ab_are_loaded
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0,#48]
	stp	x12,x13,[c0,#64]
	stp	x14,x15,[c0,#80]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	mul_by_3_mod_384x,.-mul_by_3_mod_384x

.globl	mul_by_8_mod_384x
.hidden	mul_by_8_mod_384x
.type	mul_by_8_mod_384x,%function
.align	5
mul_by_8_mod_384x:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x12,x13,[c1,#16]
	ldp	x14,x15,[c1,#32]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]

	bl	__lshift_mod_384
	bl	__lshift_mod_384
	bl	__lshift_mod_384

	stp	x10,x11,[c0]
	ldp	x10,x11,[c1,#48]
	stp	x12,x13,[c0,#16]
	ldp	x12,x13,[c1,#64]
	stp	x14,x15,[c0,#32]
	ldp	x14,x15,[c1,#80]

	bl	__lshift_mod_384
	bl	__lshift_mod_384
	bl	__lshift_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0,#48]
	stp	x12,x13,[c0,#64]
	stp	x14,x15,[c0,#80]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	mul_by_8_mod_384x,.-mul_by_8_mod_384x

.globl	cneg_mod_384
.hidden	cneg_mod_384
.type	cneg_mod_384,%function
.align	5
cneg_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x10,x11,[c1]
	ldp	x4,x5,[c3]
	ldp	x12,x13,[c1,#16]
	ldp	x6,x7,[c3,#16]

	subs	x16,x4,x10
	ldp	x14,x15,[c1,#32]
	ldp	x8,x9,[c3,#32]
	orr	x3,x10,x11
	sbcs	x17,x5,x11
	orr	x3,x3,x12
	sbcs	x19,x6,x12
	orr	x3,x3,x13
	sbcs	x20,x7,x13
	orr	x3,x3,x14
	sbcs	x21,x8,x14
	orr	x3,x3,x15
	sbc	x22,x9,x15

	cmp	x3,#0
	csetm	x3,ne
	ands	x2,x2,x3

	csel	x10,x10,x16,eq
	csel	x11,x11,x17,eq
	csel	x12,x12,x19,eq
	csel	x13,x13,x20,eq
	stp	x10,x11,[c0]
	csel	x14,x14,x21,eq
	stp	x12,x13,[c0,#16]
	csel	x15,x15,x22,eq
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	cneg_mod_384,.-cneg_mod_384

.globl	sub_mod_384
.hidden	sub_mod_384
.type	sub_mod_384,%function
.align	5
sub_mod_384:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

	bl	__sub_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0]
	stp	x12,x13,[c0,#16]
	stp	x14,x15,[c0,#32]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	sub_mod_384,.-sub_mod_384

.type	__sub_mod_384,%function
.align	5
__sub_mod_384:
	ldp	x10,x11,[c1]
	ldp	x16,x17,[c2]
	ldp	x12,x13,[c1,#16]
	ldp	x19,x20,[c2,#16]
	ldp	x14,x15,[c1,#32]
	ldp	x21,x22,[c2,#32]

	subs	x10,x10,x16
	sbcs	x11,x11,x17
	sbcs	x12,x12,x19
	sbcs	x13,x13,x20
	sbcs	x14,x14,x21
	sbcs	x15,x15,x22
	sbc	x3,xzr,xzr

	and	x16,x4,x3
	and	x17,x5,x3
	adds	x10,x10,x16
	and	x19,x6,x3
	adcs	x11,x11,x17
	and	x20,x7,x3
	adcs	x12,x12,x19
	and	x21,x8,x3
	adcs	x13,x13,x20
	and	x22,x9,x3
	adcs	x14,x14,x21
	adc	x15,x15,x22

	ret
.size	__sub_mod_384,.-__sub_mod_384

.globl	sub_mod_384x
.hidden	sub_mod_384x
.type	sub_mod_384x,%function
.align	5
sub_mod_384x:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x4,x5,[c3]
	ldp	x6,x7,[c3,#16]
	ldp	x8,x9,[c3,#32]

	bl	__sub_mod_384

	stp	x10,x11,[c0]
	add	c1,c1,#48
	stp	x12,x13,[c0,#16]
	add	c2,c2,#48
	stp	x14,x15,[c0,#32]

	bl	__sub_mod_384
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0,#48]
	stp	x12,x13,[c0,#64]
	stp	x14,x15,[c0,#80]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	sub_mod_384x,.-sub_mod_384x

.globl	mul_by_1_plus_i_mod_384x
.hidden	mul_by_1_plus_i_mod_384x
.type	mul_by_1_plus_i_mod_384x,%function
.align	5
mul_by_1_plus_i_mod_384x:
	.inst	0xd503233f
	stp	c29,c30,[csp,#-6*__SIZEOF_POINTER__]!
	add	c29,csp,#0
	stp	c19,c20,[csp,#2*__SIZEOF_POINTER__]
	stp	c21,c22,[csp,#4*__SIZEOF_POINTER__]

	ldp	x4,x5,[c2]
	ldp	x6,x7,[c2,#16]
	ldp	x8,x9,[c2,#32]
	add	c2,c1,#48

	bl	__sub_mod_384			// a->re - a->im

	ldp	x16,x17,[c1]
	ldp	x19,x20,[c1,#16]
	ldp	x21,x22,[c1,#32]
	stp	x10,x11,[c0]
	ldp	x10,x11,[c1,#48]
	stp	x12,x13,[c0,#16]
	ldp	x12,x13,[c1,#64]
	stp	x14,x15,[c0,#32]
	ldp	x14,x15,[c1,#80]

	bl	__add_mod_384_ab_are_loaded	// a->re + a->im
	ldr	c30,[csp,#__SIZEOF_POINTER__]

	stp	x10,x11,[c0,#48]
	stp	x12,x13,[c0,#64]
	stp	x14,x15,[c0,#80]

	ldp	c19,c20,[c29,#2*__SIZEOF_POINTER__]
	ldp	c21,c22,[c29,#4*__SIZEOF_POINTER__]
	ldr	c29,[csp],#6*__SIZEOF_POINTER__
	.inst	0xd50323bf
	ret
.size	mul_by_1_plus_i_mod_384x,.-mul_by_1_plus_i_mod_384x

.globl	sgn0_pty_mod_384
.hidden	sgn0_pty_mod_384
.type	sgn0_pty_mod_384,%function
.align	5
sgn0_pty_mod_384:
	ldp	x10,x11,[c0]
	ldp	x12,x13,[c0,#16]
	ldp	x14,x15,[c0,#32]

	ldp	x4,x5,[c1]
	ldp	x6,x7,[c1,#16]
	ldp	x8,x9,[c1,#32]

	and	x0,x10,#1
	adds	x10,x10,x10
	adcs	x11,x11,x11
	adcs	x12,x12,x12
	adcs	x13,x13,x13
	adcs	x14,x14,x14
	adcs	x15,x15,x15
	adc	x3,xzr,xzr

	subs	x10,x10,x4
	sbcs	x11,x11,x5
	sbcs	x12,x12,x6
	sbcs	x13,x13,x7
	sbcs	x14,x14,x8
	sbcs	x15,x15,x9
	sbc	x3,x3,xzr

	mvn	x3,x3
	and	x3,x3,#2
	orr	x0,x0,x3

	ret
.size	sgn0_pty_mod_384,.-sgn0_pty_mod_384

.globl	sgn0_pty_mod_384x
.hidden	sgn0_pty_mod_384x
.type	sgn0_pty_mod_384x,%function
.align	5
sgn0_pty_mod_384x:
	ldp	x10,x11,[c0]
	ldp	x12,x13,[c0,#16]
	ldp	x14,x15,[c0,#32]

	ldp	x4,x5,[c1]
	ldp	x6,x7,[c1,#16]
	ldp	x8,x9,[c1,#32]

	and	x2,x10,#1
	orr	x3,x10,x11
	adds	x10,x10,x10
	orr	x3,x3,x12
	adcs	x11,x11,x11
	orr	x3,x3,x13
	adcs	x12,x12,x12
	orr	x3,x3,x14
	adcs	x13,x13,x13
	orr	x3,x3,x15
	adcs	x14,x14,x14
	adcs	x15,x15,x15
	adc	x16,xzr,xzr

	subs	x10,x10,x4
	sbcs	x11,x11,x5
	sbcs	x12,x12,x6
	sbcs	x13,x13,x7
	sbcs	x14,x14,x8
	sbcs	x15,x15,x9
	sbc	x16,x16,xzr

	ldp	x10,x11,[c0,#48]
	ldp	x12,x13,[c0,#64]
	ldp	x14,x15,[c0,#80]

	mvn	x16,x16
	and	x16,x16,#2
	orr	x2,x2,x16

	and	x0,x10,#1
	orr	x1,x10,x11
	adds	x10,x10,x10
	orr	x1,x1,x12
	adcs	x11,x11,x11
	orr	x1,x1,x13
	adcs	x12,x12,x12
	orr	x1,x1,x14
	adcs	x13,x13,x13
	orr	x1,x1,x15
	adcs	x14,x14,x14
	adcs	x15,x15,x15
	adc	x16,xzr,xzr

	subs	x10,x10,x4
	sbcs	x11,x11,x5
	sbcs	x12,x12,x6
	sbcs	x13,x13,x7
	sbcs	x14,x14,x8
	sbcs	x15,x15,x9
	sbc	x16,x16,xzr

	mvn	x16,x16
	and	x16,x16,#2
	orr	x0,x0,x16

	cmp	x3,#0
	csel	x3,x0,x2,eq	// a->re==0? prty(a->im) : prty(a->re)

	cmp	x1,#0
	csel	x1,x0,x2,ne	// a->im!=0? sgn0(a->im) : sgn0(a->re)

	and	x3,x3,#1
	and	x1,x1,#2
	orr	x0,x1,x3	// pack sign and parity

	ret
.size	sgn0_pty_mod_384x,.-sgn0_pty_mod_384x
.globl	vec_select_32
.hidden	vec_select_32
.type	vec_select_32,%function
.align	5
vec_select_32:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	bit	v1.16b, v4.16b, v6.16b
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0]
	ret
.size	vec_select_32,.-vec_select_32
.globl	vec_select_48
.hidden	vec_select_48
.type	vec_select_48,%function
.align	5
vec_select_48:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	bit	v1.16b, v4.16b, v6.16b
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0]
	ret
.size	vec_select_48,.-vec_select_48
.globl	vec_select_96
.hidden	vec_select_96
.type	vec_select_96,%function
.align	5
vec_select_96:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	bit	v17.16b, v20.16b, v6.16b
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0]
	ret
.size	vec_select_96,.-vec_select_96
.globl	vec_select_192
.hidden	vec_select_192
.type	vec_select_192,%function
.align	5
vec_select_192:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	bit	v17.16b, v20.16b, v6.16b
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	bit	v17.16b, v20.16b, v6.16b
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0]
	ret
.size	vec_select_192,.-vec_select_192
.globl	vec_select_144
.hidden	vec_select_144
.type	vec_select_144,%function
.align	5
vec_select_144:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	bit	v17.16b, v20.16b, v6.16b
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0],#48
	bit	v0.16b, v3.16b, v6.16b
	bit	v1.16b, v4.16b, v6.16b
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0]
	ret
.size	vec_select_144,.-vec_select_144
.globl	vec_select_288
.hidden	vec_select_288
.type	vec_select_288,%function
.align	5
vec_select_288:
	dup	v6.2d, x3
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	cmeq	v6.2d, v6.2d, #0
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	bit	v17.16b, v20.16b, v6.16b
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	ld1	{v0.2d, v1.2d, v2.2d}, [c1],#48
	bit	v17.16b, v20.16b, v6.16b
	ld1	{v3.2d, v4.2d, v5.2d}, [c2],#48
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0],#48
	bit	v0.16b, v3.16b, v6.16b
	ld1	{v16.2d, v17.2d, v18.2d}, [c1],#48
	bit	v1.16b, v4.16b, v6.16b
	ld1	{v19.2d, v20.2d, v21.2d}, [c2],#48
	bit	v2.16b, v5.16b, v6.16b
	st1	{v0.2d, v1.2d, v2.2d}, [c0],#48
	bit	v16.16b, v19.16b, v6.16b
	bit	v17.16b, v20.16b, v6.16b
	bit	v18.16b, v21.16b, v6.16b
	st1	{v16.2d, v17.2d, v18.2d}, [c0]
	ret
.size	vec_select_288,.-vec_select_288
.globl	vec_prefetch
.hidden	vec_prefetch
.type	vec_prefetch,%function
.align	5
vec_prefetch:
	add	x1, x1, x0
	sub	x1, x1, #1
	mov	x2, #64
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	csel	x2, xzr, x2, hi
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	csel	x2, xzr, x2, hi
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	csel	x2, xzr, x2, hi
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	csel	x2, xzr, x2, hi
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	csel	x2, xzr, x2, hi
	prfm	pldl1keep, [c0]
	add	x0, x0, x2
	cmp	x0, x1
	csel	x0, x1, x0, hi
	prfm	pldl1keep, [c0]
	ret
.size	vec_prefetch,.-vec_prefetch
.globl	vec_is_zero_16x
.hidden	vec_is_zero_16x
.type	vec_is_zero_16x,%function
.align	5
vec_is_zero_16x:
	ld1	{v0.2d}, [c0], #16
	lsr	x1, x1, #4
	sub	x1, x1, #1
	cbz	x1, .Loop_is_zero_done

.Loop_is_zero:
	ld1	{v1.2d}, [c0], #16
	orr	v0.16b, v0.16b, v1.16b
	sub	x1, x1, #1
	cbnz	x1, .Loop_is_zero

.Loop_is_zero_done:
	dup	v1.2d, v0.d[1]
	orr	v0.16b, v0.16b, v1.16b
	umov	x1, v0.d[0]
	mov	x0, #1
	cmp	x1, #0
	csel	x0, x0, xzr, eq
	ret
.size	vec_is_zero_16x,.-vec_is_zero_16x
.globl	vec_is_equal_16x
.hidden	vec_is_equal_16x
.type	vec_is_equal_16x,%function
.align	5
vec_is_equal_16x:
	ld1	{v0.2d}, [c0], #16
	ld1	{v1.2d}, [c1], #16
	lsr	x2, x2, #4
	eor	v0.16b, v0.16b, v1.16b

.Loop_is_equal:
	sub	x2, x2, #1
	cbz	x2, .Loop_is_equal_done
	ld1	{v1.2d}, [c0], #16
	ld1	{v2.2d}, [c1], #16
	eor	v1.16b, v1.16b, v2.16b
	orr	v0.16b, v0.16b, v1.16b
	b	.Loop_is_equal
	nop

.Loop_is_equal_done:
	dup	v1.2d, v0.d[1]
	orr	v0.16b, v0.16b, v1.16b
	umov	x1, v0.d[0]
	mov	x0, #1
	cmp	x1, #0
	csel	x0, x0, xzr, eq
	ret
.size	vec_is_equal_16x,.-vec_is_equal_16x
