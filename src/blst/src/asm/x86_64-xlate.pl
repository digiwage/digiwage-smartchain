#!/usr/bin/env perl
#
# Copyright Supranational LLC
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Ascetic x86_64 AT&T to MASM/NASM assembler translator by @dot-asm.
#
# Why AT&T to MASM and not vice versa? Several reasons. Because AT&T
# format is way easier to parse. Because it's simpler to "gear" from
# Unix ABI to Windows one [see cross-reference "card" at the end of
# file]. Because Linux targets were available first...
#
# In addition the script also "distills" code suitable for GNU
# assembler, so that it can be compiled with more rigid assemblers,
# such as Solaris /usr/ccs/bin/as.
#
# This translator is not designed to convert *arbitrary* assembler
# code from AT&T format to MASM one. It's designed to convert just
# enough to provide for dual-ABI OpenSSL modules development...
# There *are* limitations and you might have to modify your assembler
# code or this script to achieve the desired result...
#
# Currently recognized limitations:
#
# - can't use multiple ops per line;
#
# Dual-ABI styling rules.
#
# 1. Adhere to Unix register and stack layout [see cross-reference
#    ABI "card" at the end for explanation].
# 2. Forget about "red zone," stick to more traditional blended
#    stack frame allocation. If volatile storage is actually required
#    that is. If not, just leave the stack as is.
# 3. Functions tagged with ".type name,@function" get crafted with
#    unified Win64 prologue and epilogue automatically. If you want
#    to take care of ABI differences yourself, tag functions as
#    ".type name,@abi-omnipotent" instead.
# 4. To optimize the Win64 prologue you can specify number of input
#    arguments as ".type name,@function,N." Keep in mind that if N is
#    larger than 6, then you *have to* write "abi-omnipotent" code,
#    because >6 cases can't be addressed with unified prologue.
# 5. Name local labels as .L*, do *not* use dynamic labels such as 1:
#    (sorry about latter).
# 6. Don't use [or hand-code with .byte] "rep ret." "ret" mnemonic is
#    required to identify the spots, where to inject Win64 epilogue!
#    But on the pros, it's then prefixed with rep automatically:-)
# 7. Stick to explicit ip-relative addressing. If you have to use
#    GOTPCREL addressing, stick to mov symbol@GOTPCREL(%rip),%r??.
#    Both are recognized and translated to proper Win64 addressing
#    modes.
#
# 8. In order to provide for structured exception handling unified
#    Win64 prologue copies %rsp value to %rax. [Unless function is
#    tagged with additional .type tag.] For further details see SEH
#    paragraph at the end.
# 9. .init segment is allowed to contain calls to functions only.
# a. If function accepts more than 4 arguments *and* >4th argument
#    is declared as non 64-bit value, do clear its upper part.


use strict;

my $flavour = shift;
my $output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

open STDOUT,">$output" || die "can't open $output: $!"
	if (defined($output));

my $gas=1;	$gas=0 if ($output =~ /\.asm$/);
my $elf=1;	$elf=0 if (!$gas);
my $dwarf=$elf;
my $win64=0;
my $prefix="";
my $decor=".L";

my $masmref=8 + 50727*2**-32;	# 8.00.50727 shipped with VS2005
my $masm=0;
my $PTR=" PTR";

my $nasmref=2.03;
my $nasm=0;

if    ($flavour eq "mingw64")	{ $gas=1; $elf=0; $win64=1;
				  $prefix=`echo __USER_LABEL_PREFIX__ | \${CC:-false} -E -P -`;
				  $prefix =~ s|\R$||; # Better chomp
				}
elsif ($flavour eq "macosx")	{ $gas=1; $elf=0; $prefix="_"; $decor="L\$"; }
elsif ($flavour eq "masm")	{ $gas=0; $elf=0; $masm=$masmref; $win64=1; $decor="\$L\$"; }
elsif ($flavour eq "nasm")	{ $gas=0; $elf=0; $nasm=$nasmref; $win64=1; $decor="\$L\$"; $PTR=""; }
elsif (!$gas)
{   if ($ENV{ASM} =~ m/nasm/ && `nasm -v` =~ m/version ([0-9]+)\.([0-9]+)/i)
    {	$nasm = $1 + $2*0.01; $PTR="";  }
    elsif (`ml64 2>&1` =~ m/Version ([0-9]+)\.([0-9]+)(\.([0-9]+))?/)
    {	$masm = $1 + $2*2**-16 + $4*2**-32;   }
    die "no assembler found on %PATH%" if (!($nasm || $masm));
    $win64=1;
    $elf=0;
    $decor="\$L\$";
}
my $colon= $masm ? "::" : ":";

$dwarf=0 if($win64);

my $current_segment;
my $current_function;
my %globals;
my $ret_clobber;

{ package opcode;	# pick up opcodes
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /^([a-z][a-z0-9]*)/i) {
	    bless $self,$class;
	    $self->{op} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    undef $self->{sz};
	    if ($self->{op} =~ /^(movz)x?([bw]).*/) {	# movz is pain...
		$self->{op} = $1;
		$self->{sz} = $2;
	    } elsif ($self->{op} =~ /cmov[n]?[lb]$/) {
		# pass through
	    } elsif ($self->{op} =~ /call|jmp/) {
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /^p/ && $' !~ /^(ush|op|insrw)/) { # SSEn
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /^[vk]/) { # VEX or k* such as kmov
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /mov[dq]/ && $$line =~ /%xmm/) {
		$self->{sz} = "";
	    } elsif ($self->{op} =~ /([a-z]{3,})([qlwb])$/) {
		$self->{op} = $1;
		$self->{sz} = $2;
	    }
	}
	$ret;
    }
    sub size {
	my ($self, $sz) = @_;
	$self->{sz} = $sz if (defined($sz) && !defined($self->{sz}));
	$self->{sz};
    }
    sub out {
	my $self = shift;
	if ($gas) {
	    if ($self->{op} eq "movz") {	# movz is pain...
		sprintf "%s%s%s",$self->{op},$self->{sz},shift;
	    } elsif ($self->{op} =~ /^set/) {
		"$self->{op}";
	    } elsif ($self->{op} eq "ret") {
		my $epilogue = "";
		my $reg = $ret_clobber || "rdx";
		$ret_clobber = undef;
		if ($win64 && $current_function->{abi} eq "svr4"
			   && !$current_function->{unwind}) {
		    $epilogue = "movq	8(%rsp),%rdi\n\t" .
				"movq	16(%rsp),%rsi\n\t";
		}
		$epilogue . "\n#ifdef	__SGX_LVI_HARDENING__\n".
				"	popq	%$reg\n"		.
				"	lfence\n"		.
				"	jmpq	*%$reg\n"	.
				"	ud2\n"			.
				"#else\n"			.
				"	.byte	0xf3,0xc3\n"	.
				"#endif";
	    } elsif ($self->{op} eq "call" && !$elf && $current_segment eq ".init") {
		".p2align\t3\n\t.quad";
	    } else {
		"$self->{op}$self->{sz}";
	    }
	} else {
	    $self->{op} =~ s/^movz/movzx/;
	    if ($self->{op} eq "ret") {
		$self->{op} = "";
		my $reg = $ret_clobber || "rdx";
		$ret_clobber = undef;
		if ($win64 && $current_function->{abi} eq "svr4"
			   && !$current_function->{unwind}) {
		    $self->{op} = "mov	rdi,QWORD$PTR\[8+rsp\]\t;WIN64 epilogue\n\t".
				  "mov	rsi,QWORD$PTR\[16+rsp\]\n\t";
		}
		$self->{op} .= "\nifdef	__SGX_LVI_HARDENING__\n".
				"	pop	$reg\n"		.
				"	lfence\n"		.
				"	jmp	$reg\n"		.
				"	ud2\n"			.
				"else\n"			.
				"	DB\t0F3h,0C3h\n"	.
				"endif";
	    } elsif ($self->{op} =~ /^(pop|push)f/) {
		$self->{op} .= $self->{sz};
	    } elsif ($self->{op} eq "call" && $current_segment eq ".CRT\$XCU") {
		$self->{op} = "\tDQ";
	    }
	    $self->{op};
	}
    }
    sub mnemonic {
	my ($self, $op) = @_;
	$self->{op}=$op if (defined($op));
	$self->{op};
    }
}
{ package const;	# pick up constants, which start with $
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /^\$([^,]+)/) {
	    bless $self, $class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;
	}
	$ret;
    }
    sub out {
	my $self = shift;

	$self->{value} =~ s/\b(0b[0-1]+)/oct($1)/eig;
	if ($gas) {
	    # Solaris /usr/ccs/bin/as can't handle multiplications
	    # in $self->{value}
	    my $value = $self->{value};
	    no warnings;    # oct might complain about overflow, ignore here...
	    $value =~ s/(?<![\w\$\.])(0x?[0-9a-f]+)/oct($1)/egi;
	    if ($value =~ s/([0-9]+\s*[\*\/\%]\s*[0-9]+)/eval($1)/eg) {
		$self->{value} = $value;
	    }
	    sprintf "\$%s",$self->{value};
	} else {
	    my $value = $self->{value};
	    $value =~ s/0x([0-9a-f]+)/0$1h/ig if ($masm);
	    sprintf "%s",$value;
	}
    }
}
{ package ea;		# pick up effective addresses: expr(%reg,%reg,scale)

    my %szmap = (	b=>"BYTE$PTR",    w=>"WORD$PTR",
			l=>"DWORD$PTR",   d=>"DWORD$PTR",
			q=>"QWORD$PTR",   o=>"OWORD$PTR",
			x=>"XMMWORD$PTR", y=>"YMMWORD$PTR",
			z=>"ZMMWORD$PTR" ) if (!$gas);

    my %sifmap = (	ss=>"d",	sd=>"q",	# broadcast only
			i32x2=>"q",	f32x2=>"q",
			i32x4=>"x",	i64x2=>"x",	i128=>"x",
			f32x4=>"x",	f64x2=>"x",	f128=>"x",
			i32x8=>"y",	i64x4=>"y",
			f32x8=>"y",	f64x4=>"y" ) if (!$gas);

    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	# optional * ----vvv--- appears in indirect jmp/call
	if ($$line =~ /^(\*?)([^\(,]*)\(([%\w,\s]+)\)((?:{[^}]+})*)/) {
	    bless $self, $class;
	    $self->{asterisk} = $1;
	    $self->{label} = $2;
	    ($self->{base},$self->{index},$self->{scale})=split(/(?:,\s*)/,$3);
	    $self->{scale} = 1 if (!defined($self->{scale}));
	    $self->{opmask} = $4;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    if ($win64 && $self->{label} =~ s/\@GOTPCREL//) {
		die if ($opcode->mnemonic() ne "mov");
		$opcode->mnemonic("lea");
	    }
	    $self->{base}  =~ s/^%//;
	    $self->{index} =~ s/^%// if (defined($self->{index}));
	    $self->{opcode} = $opcode;
	}
	$ret;
    }
    sub size {}
    sub out {
	my ($self, $sz) = @_;

	$self->{label} =~ s/([_a-z][_a-z0-9\$]*)/$globals{$1} or $1/gei;
	$self->{label} =~ s/\.L/$decor/g;

	# Silently convert all EAs to 64-bit. This is required for
	# elder GNU assembler and results in more compact code,
	# *but* most importantly AES module depends on this feature!
	$self->{index} =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;
	$self->{base}  =~ s/^[er](.?[0-9xpi])[d]?$/r\1/;

	# Solaris /usr/ccs/bin/as can't handle multiplications
	# in $self->{label}...
	use integer;
	$self->{label} =~ s/(?<![\w\$\.])(0x?[0-9a-f]+)/oct($1)/egi;
	$self->{label} =~ s/\b([0-9]+\s*[\*\/\%]\s*[0-9]+)\b/eval($1)/eg;

	# Some assemblers insist on signed presentation of 32-bit
	# offsets, but sign extension is a tricky business in perl...
	$self->{label} =~ s/\b([0-9]+)\b/unpack("l",pack("L",$1))/eg;

	# if base register is %rbp or %r13, see if it's possible to
	# flip base and index registers [for better performance]
	if (!$self->{label} && $self->{index} && $self->{scale}==1 &&
	    $self->{base} =~ /(rbp|r13)/) {
		$self->{base} = $self->{index}; $self->{index} = $1;
	}

	if ($gas) {
	    $self->{label} =~ s/^___imp_/__imp__/   if ($flavour eq "mingw64");

	    if (defined($self->{index})) {
		sprintf "%s%s(%s,%%%s,%d)%s",
					$self->{asterisk},$self->{label},
					$self->{base}?"%$self->{base}":"",
					$self->{index},$self->{scale},
					$self->{opmask};
	    } else {
		sprintf "%s%s(%%%s)%s",	$self->{asterisk},$self->{label},
					$self->{base},$self->{opmask};
	    }
	} else {
	    $self->{label} =~ s/\./\$/g;
	    $self->{label} =~ s/(?<![\w\$\.])0x([0-9a-f]+)/0$1h/ig;
	    $self->{label} = "($self->{label})" if ($self->{label} =~ /[\*\+\-\/]/);

	    my $mnemonic = $self->{opcode}->mnemonic();
	    ($self->{asterisk})				&& ($sz="q") ||
	    ($mnemonic =~ /^v?mov([qd])$/)		&& ($sz=$1)  ||
	    ($mnemonic =~ /^v?pinsr([qdwb])$/)		&& ($sz=$1)  ||
	    ($mnemonic =~ /^vpbroadcast([qdwb])$/)	&& ($sz=$1)  ||
	    ($mnemonic =~ /^v(?:broadcast|extract|insert)([sif]\w+)$/)
							&& ($sz=$sifmap{$1});

	    $self->{opmask}  =~ s/%(k[0-7])/$1/;

	    if (defined($self->{index})) {
		sprintf "%s[%s%s*%d%s]%s",$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{index},$self->{scale},
					$self->{base}?"+$self->{base}":"",
					$self->{opmask};
	    } elsif ($self->{base} eq "rip") {
		sprintf "%s[%s]",$szmap{$sz},$self->{label};
	    } else {
		sprintf "%s[%s%s]%s",	$szmap{$sz},
					$self->{label}?"$self->{label}+":"",
					$self->{base},$self->{opmask};
	    }
	}
    }
}
{ package register;	# pick up registers, which start with %.
    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	# optional * ----vvv--- appears in indirect jmp/call
	if ($$line =~ /^(\*?)%(\w+)((?:{[^}]+})*)/) {
	    bless $self,$class;
	    $self->{asterisk} = $1;
	    $self->{value} = $2;
	    $self->{opmask} = $3;
	    $opcode->size($self->size());
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;
	}
	$ret;
    }
    sub size {
	my	$self = shift;
	my	$ret;

	if    ($self->{value} =~ /^r[\d]+b$/i)	{ $ret="b"; }
	elsif ($self->{value} =~ /^r[\d]+w$/i)	{ $ret="w"; }
	elsif ($self->{value} =~ /^r[\d]+d$/i)	{ $ret="l"; }
	elsif ($self->{value} =~ /^r[\w]+$/i)	{ $ret="q"; }
	elsif ($self->{value} =~ /^[a-d][hl]$/i){ $ret="b"; }
	elsif ($self->{value} =~ /^[\w]{2}l$/i)	{ $ret="b"; }
	elsif ($self->{value} =~ /^[\w]{2}$/i)	{ $ret="w"; }
	elsif ($self->{value} =~ /^e[a-z]{2}$/i){ $ret="l"; }

	$ret;
    }
    sub out {
	my $self = shift;
	if ($gas)	{ sprintf "%s%%%s%s",	$self->{asterisk},
						$self->{value},
						$self->{opmask}; }
	else		{ $self->{opmask} =~ s/%(k[0-7])/$1/;
			  $self->{value}.$self->{opmask}; }
    }
}
{ package label;	# pick up labels, which end with :
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /(^[\.\w\$]+)\:/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    $self->{value} =~ s/^(\w+\$\w*)/$decor\1/ if ($flavour eq "macosx");
	    $self->{value} =~ s/^\.L/$decor/;
	}
	$ret;
    }
    sub win64_args {
	my $narg = $current_function->{narg} // 6;
	return undef if ($narg < 0);
	my $arg5 = 4*8 - cfi_directive::cfa_rsp();
	my $arg6 = $arg5 + 8;
	my $args;
	if ($gas) {
	    $args .= "	movq	%rcx,%rdi\n" if ($narg>0);
	    $args .= "	movq	%rdx,%rsi\n" if ($narg>1);
	    $args .= "	movq	%r8,%rdx\n"  if ($narg>2);
	    $args .= "	movq	%r9,%rcx\n"  if ($narg>3);
	    $args .= "	movq	$arg5(%rsp),%r8\n" if ($narg>4);
	    $args .= "	movq	$arg6(%rsp),%r9\n" if ($narg>5);
	} else {
	    $args .= "	mov	rdi,rcx\n" if ($narg>0);
	    $args .= "	mov	rsi,rdx\n" if ($narg>1);
	    $args .= "	mov	rdx,r8\n"  if ($narg>2);
	    $args .= "	mov	rcx,r9\n"  if ($narg>3);
	    $args .= "	mov	r8,QWORD$PTR\[$arg5+rsp\]\n" if ($narg>4);
	    $args .= "	mov	r9,QWORD$PTR\[$arg6+rsp\]\n" if ($narg>5);
	}
	$current_function->{narg} = -1;
	$args;
    }
    sub out {
	my $self = shift;

	if ($gas) {
	    my $func = ($globals{$self->{value}} or $self->{value}) . ":";
	    if ($current_function->{name} eq $self->{value}) {
		$current_function->{pc} = 0;
		$func .= "\n.cfi_".cfi_directive::startproc()   if ($dwarf);
		$func .= "\n	.byte	0xf3,0x0f,0x1e,0xfa\n";	# endbranch
		if ($win64) {
		    if ($current_function->{abi} eq "svr4") {
			my $fp = $current_function->{unwind} ? "%r11" : "%rax";
			$func .= "	movq	%rdi,8(%rsp)\n";
			$func .= "	movq	%rsi,16(%rsp)\n";
			$func .= "	movq	%rsp,$fp\n";
			$func .= "${decor}SEH_begin_$current_function->{name}:\n";
		    } elsif ($current_function->{unwind}) {
			$func .= "	movq	%rsp,%r11\n";
			$func .= "${decor}SEH_begin_$current_function->{name}:\n";
		    }
		}
	    } elsif ($win64 && $current_function->{abi} eq "svr4"
			    && $current_function->{pc} >= 0) {
		$func = win64_args().$func;
	    }
	    $func;
	} elsif ($self->{value} ne "$current_function->{name}") {
	    my $func;
	    if ($win64 && $current_function->{abi} eq "svr4"
		       && $current_function->{pc} >= 0) {
		$func = win64_args();
	    }
	    $func .= $self->{value} . $colon;
	    $func;
	} else {
	    $current_function->{pc} = 0;
	    my $func =	"$current_function->{name}" .
			($nasm ? ":" : "\tPROC $current_function->{scope}") .
			"\n";
	    $func .= "	DB	243,15,30,250\n";	# endbranch
	    if ($current_function->{abi} eq "svr4") {
		my $fp = $current_function->{unwind} ? "r11" : "rax";
		$func .= "	mov	QWORD$PTR\[8+rsp\],rdi\t;WIN64 prologue\n";
		$func .= "	mov	QWORD$PTR\[16+rsp\],rsi\n";
		$func .= "	mov	$fp,rsp\n";
		$func .= "${decor}SEH_begin_$current_function->{name}${colon}\n";
	    } elsif ($current_function->{unwind}) {
		$func .= "	mov	r11,rsp\n";
		$func .= "${decor}SEH_begin_$current_function->{name}${colon}\n";
	    }
	    $func;
	}
    }
}
{ package expr;		# pick up expressions
    sub re {
	my	($class, $line, $opcode) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ /(^[^,]+)/) {
	    bless $self,$class;
	    $self->{value} = $1;
	    $ret = $self;
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    $self->{value} =~ s/\@PLT// if (!$elf);
	    $self->{value} =~ s/([_a-z][_a-z0-9\$]*)/$globals{$1} or $1/gei;
	    if ($flavour eq "macosx" and $self->{value} !~ /\.L/) {
		$self->{value} =~ s/(\w+\$\w*)/$decor\1/g;
	    }
	    $self->{value} =~ s/\.L/$decor/g;
	    $self->{opcode} = $opcode;
	}
	$ret;
    }
    sub out {
	my $self = shift;
	$self->{value};
    }
}

my @xdata_seg = (".section	.xdata", ".align	8");
my @pdata_seg = (".section	.pdata", ".align	4");

{ package cfi_directive;
    # CFI directives annotate instructions that are significant for
    # stack unwinding procedure compliant with DWARF specification,
    # see http://dwarfstd.org/. Besides naturally expected for this
    # script platform-specific filtering function, this module adds
    # four auxiliary synthetic directives not recognized by [GNU]
    # assembler:
    #
    # - .cfi_push to annotate push instructions in prologue, which
    #   translates to .cfi_adjust_cfa_offset (if needed) and
    #   .cfi_offset;
    # - .cfi_pop to annotate pop instructions in epilogue, which
    #   translates to .cfi_adjust_cfa_offset (if needed) and
    #   .cfi_restore;
    # - .cfi_alloca to annotate stack pointer adjustments, which
    #   translates to .cfi_adjust_cfa_offset as needed;
    # - [and most notably] .cfi_cfa_expression which encodes
    #   DW_CFA_def_cfa_expression and passes it to .cfi_escape as
    #   byte vector;
    #
    # CFA expressions were introduced in DWARF specification version
    # 3 and describe how to deduce CFA, Canonical Frame Address. This
    # becomes handy if your stack frame is variable and you can't
    # spare register for [previous] frame pointer. Suggested directive
    # syntax is made-up mix of DWARF operator suffixes [subset of]
    # and references to registers with optional bias. Following example
    # describes offloaded *original* stack pointer at specific offset
    # from *current* stack pointer:
    #
    #   .cfi_cfa_expression     %rsp+40,deref,+8
    #
    # Final +8 has everything to do with the fact that CFA is defined
    # as reference to top of caller's stack, and on x86_64 call to
    # subroutine pushes 8-byte return address. In other words original
    # stack pointer upon entry to a subroutine is 8 bytes off from CFA.
    #
    # In addition the .cfi directives are re-purposed even for Win64
    # stack unwinding. Two more synthetic directives were added:
    #
    # - .cfi_end_prologue to denote point when all non-volatile
    #   registers are saved and stack or [chosen] frame pointer is
    #   stable;
    # - .cfi_epilogue to denote point when all non-volatile registers
    #   are restored [and it even adds missing .cfi_restore-s];
    #
    # Though it's not universal "miracle cure," it has its limitations.
    # Most notably .cfi_cfa_expression won't start working... For more
    # information see the end of this file.

    # Below constants are taken from "DWARF Expressions" section of the
    # DWARF specification, section is numbered 7.7 in versions 3 and 4.
    my %DW_OP_simple = (	# no-arg operators, mapped directly
	deref	=> 0x06,	dup	=> 0x12,
	drop	=> 0x13,	over	=> 0x14,
	pick	=> 0x15,	swap	=> 0x16,
	rot	=> 0x17,	xderef	=> 0x18,

	abs	=> 0x19,	and	=> 0x1a,
	div	=> 0x1b,	minus	=> 0x1c,
	mod	=> 0x1d,	mul	=> 0x1e,
	neg	=> 0x1f,	not	=> 0x20,
	or	=> 0x21,	plus	=> 0x22,
	shl	=> 0x24,	shr	=> 0x25,
	shra	=> 0x26,	xor	=> 0x27,
	);

    my %DW_OP_complex = (	# used in specific subroutines
	constu		=> 0x10,	# uleb128
	consts		=> 0x11,	# sleb128
	plus_uconst	=> 0x23,	# uleb128
	lit0 		=> 0x30,	# add 0-31 to opcode
	reg0		=> 0x50,	# add 0-31 to opcode
	breg0		=> 0x70,	# add 0-31 to opcole, sleb128
	regx		=> 0x90,	# uleb28
	fbreg		=> 0x91,	# sleb128
	bregx		=> 0x92,	# uleb128, sleb128
	piece		=> 0x93,	# uleb128
	);

    # Following constants are defined in x86_64 ABI supplement, for
    # example available at https://www.uclibc.org/docs/psABI-x86_64.pdf,
    # see section 3.7 "Stack Unwind Algorithm".
    my %DW_reg_idx = (
	"%rax"=>0,  "%rdx"=>1,  "%rcx"=>2,  "%rbx"=>3,
	"%rsi"=>4,  "%rdi"=>5,  "%rbp"=>6,  "%rsp"=>7,
	"%r8" =>8,  "%r9" =>9,  "%r10"=>10, "%r11"=>11,
	"%r12"=>12, "%r13"=>13, "%r14"=>14, "%r15"=>15
	);

    my ($cfa_reg, $cfa_off, $cfa_rsp, %saved_regs);
    my @cfa_stack;

    sub cfa_rsp { return $cfa_rsp // -8;  }

    # [us]leb128 format is variable-length integer representation base
    # 2^128, with most significant bit of each byte being 0 denoting
    # *last* most significant digit. See "Variable Length Data" in the
    # DWARF specification, numbered 7.6 at least in versions 3 and 4.
    sub sleb128 {
	use integer;	# get right shift extend sign

	my $val = shift;
	my $sign = ($val < 0) ? -1 : 0;
	my @ret = ();

	while(1) {
	    push @ret, $val&0x7f;

	    # see if remaining bits are same and equal to most
	    # significant bit of the current digit, if so, it's
	    # last digit...
	    last if (($val>>6) == $sign);

	    @ret[-1] |= 0x80;
	    $val >>= 7;
	}

	return @ret;
    }
    sub uleb128 {
	my $val = shift;
	my @ret = ();

	while(1) {
	    push @ret, $val&0x7f;

	    # see if it's last significant digit...
	    last if (($val >>= 7) == 0);

	    @ret[-1] |= 0x80;
	}

	return @ret;
    }
    sub const {
	my $val = shift;

	if ($val >= 0 && $val < 32) {
	    return ($DW_OP_complex{lit0}+$val);
	}
	return ($DW_OP_complex{consts}, sleb128($val));
    }
    sub reg {
	my $val = shift;

	return if ($val !~ m/^(%r\w+)(?:([\+\-])((?:0x)?[0-9a-f]+))?/);

	my $reg = $DW_reg_idx{$1};
	my $off = eval ("0 $2 $3");

	return (($DW_OP_complex{breg0} + $reg), sleb128($off));
	# Yes, we use DW_OP_bregX+0 to push register value and not
	# DW_OP_regX, because latter would require even DW_OP_piece,
	# which would be a waste under the circumstances. If you have
	# to use DWP_OP_reg, use "regx:N"...
    }
    sub cfa_expression {
	my $line = shift;
	my @ret;

	foreach my $token (split(/,\s*/,$line)) {
	    if ($token =~ /^%r/) {
		push @ret,reg($token);
	    } elsif ($token =~ /((?:0x)?[0-9a-f]+)\((%r\w+)\)/) {
		push @ret,reg("$2+$1");
	    } elsif ($token =~ /(\w+):(\-?(?:0x)?[0-9a-f]+)(U?)/i) {
		my $i = 1*eval($2);
		push @ret,$DW_OP_complex{$1}, ($3 ? uleb128($i) : sleb128($i));
	    } elsif (my $i = 1*eval($token) or $token eq "0") {
		if ($token =~ /^\+/) {
		    push @ret,$DW_OP_complex{plus_uconst},uleb128($i);
		} else {
		    push @ret,const($i);
		}
	    } else {
		push @ret,$DW_OP_simple{$token};
	    }
	}

	# Finally we return DW_CFA_def_cfa_expression, 15, followed by
	# length of the expression and of course the expression itself.
	return (15,scalar(@ret),@ret);
    }

    # Following constants are defined in "x64 exception handling" at
    # https://docs.microsoft.com/ and match the register sequence in
    # CONTEXT structure defined in winnt.h.
    my %WIN64_reg_idx = (
	"%rax"=>0,  "%rcx"=>1,  "%rdx"=>2,  "%rbx"=>3,
	"%rsp"=>4,  "%rbp"=>5,  "%rsi"=>6,  "%rdi"=>7,
	"%r8" =>8,  "%r9" =>9,  "%r10"=>10, "%r11"=>11,
	"%r12"=>12, "%r13"=>13, "%r14"=>14, "%r15"=>15
	);
    sub xdata {
	our @dat = ();
	our $len = 0;

	sub savereg {
	    my ($key, $offset) = @_;

	    if ($key =~ /%xmm([0-9]+)/) {
		if ($offset < 0x100000) {
		    push @dat, [0,($1<<4)|8,unpack("C2",pack("v",$offset>>4))];
		} else {
		    push @dat, [0,($1<<4)|9,unpack("C4",pack("V",$offset))];
		}
	    } else {
		if ($offset < 0x80000) {
		    push @dat, [0,(($WIN64_reg_idx{$key})<<4)|4,
				unpack("C2",pack("v",$offset>>3))];
		} else {
		    push @dat, [0,(($WIN64_reg_idx{$key})<<4)|5,
				unpack("C4",pack("V",$offset))];
		}
	    }
	    $len += $#{@dat[-1]}+1;
	}

	my $fp_info = 0;

	# allocate stack frame
	if ($cfa_rsp < -8) {
	    my $offset = -8 - $cfa_rsp;
	    if ($cfa_reg ne "%rsp" && $saved_regs{$cfa_reg} == -16) {
		$fp_info = $WIN64_reg_idx{$cfa_reg};
		push @dat, [0,$fp_info<<4];		# UWOP_PUSH_NONVOL
		$len += $#{@dat[-1]}+1;
		$offset -= 8;
	    }
	    if ($offset <= 128) {
		my $alloc = ($offset - 8) >> 3;
		push @dat, [0,$alloc<<4|2];		# UWOP_ALLOC_SMALL
	    } elsif ($offset < 0x80000) {
		push @dat, [0,0x01,unpack("C2",pack("v",$offset>>3))];
	    } else {
		push @dat, [0,0x11,unpack("C4",pack("V",$offset))];
	    }
	    $len += $#{@dat[-1]}+1;
	}

	# save frame pointer [if not pushed already]
	if ($cfa_reg ne "%rsp" && $fp_info == 0) {
	    $fp_info = $WIN64_reg_idx{$cfa_reg};
	    if (defined(my $offset = $saved_regs{$cfa_reg})) {
		$offset -= $cfa_rsp;
		savereg($cfa_reg, $offset);
	    }
	}

	# set up frame pointer
	if ($fp_info) {
	    push @dat, [0,($fp_info<<4)|3];		# UWOP_SET_FPREG
	    $len += $#{@dat[-1]}+1;
	    my $fp_off = $cfa_off - $cfa_rsp;
	    ($fp_off > 240 or $fp_off&0xf) and die "invalid FP offset $fp_off";
	    $fp_info |= $fp_off&-16;
	}

	# save registers
	foreach my $key (sort { $saved_regs{$b} <=> $saved_regs{$a} }
			      keys(%saved_regs)) {
	    next if ($cfa_reg ne "%rsp" && $cfa_reg eq $key);
	    my $offset = $saved_regs{$key} - $cfa_rsp;
	    savereg($key, $offset);
	}

	my @ret;
	# generate 4-byte descriptor
	push @ret, ".byte	1,0,".($len/2).",$fp_info";
	$len += 4;
	# keep objdump happy, pad to 4*n and add a 32-bit zero
	unshift @dat, [(0)x(((-$len)&3)+4)];
	$len += $#{@dat[0]}+1;
	# pad to 8*n
	unshift @dat, [(0)x((-$len)&7)] if ($len&7);
	# emit data
	while(defined(my $row = pop @dat)) {
	    push @ret, ".byte	". join(",",
					map { sprintf "0x%02x",$_ } @{$row});
	}

	return @ret;
    }
    sub startproc {
	return if ($cfa_rsp == -8);
	($cfa_reg, $cfa_off, $cfa_rsp) = ("%rsp", -8, -8);
	%saved_regs = ();
	return "startproc";
    }
    sub endproc {
	return if ($cfa_rsp == 0);
	($cfa_reg, $cfa_off, $cfa_rsp) = ("%rsp", 0, 0);
	%saved_regs = ();
	return "endproc";
    }
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;

	if ($$line =~ s/^\s*\.cfi_(\w+)\s*//) {
	    bless $self,$class;
	    $ret = $self;
	    undef $self->{value};
	    my $dir = $1;

	    SWITCH: for ($dir) {
	    # What is $cfa_rsp? Effectively it's difference between %rsp
	    # value and current CFA, Canonical Frame Address, which is
	    # why it starts with -8. Recall that CFA is top of caller's
	    # stack...
	    /startproc/	&& do {	$dir = startproc(); last; };
	    /endproc/	&& do {	$dir = endproc();
				# .cfi_remember_state directives that are not
				# matched with .cfi_restore_state are
				# unnecessary.
				die "unpaired .cfi_remember_state" if (@cfa_stack);
				last;
			      };
	    /def_cfa_register/
			&& do {	$cfa_off = $cfa_rsp if ($cfa_reg eq "%rsp");
				$cfa_reg = $$line;
				$cfa_rsp = $cfa_off if ($cfa_reg eq "%rsp");
				last;
			      };
	    /def_cfa_offset/
			&& do {	$cfa_off = -1*eval($$line);
				$cfa_rsp = $cfa_off if ($cfa_reg eq "%rsp");
				last;
			      };
	    /adjust_cfa_offset/
			&& do { my $val = 1*eval($$line);
				$cfa_off -= $val;
				if ($cfa_reg eq "%rsp") {
				    $cfa_rsp -= $val;
				}
				last;
			      };
	    /alloca/	&& do { $dir = undef;
				my $val = 1*eval($$line);
				$cfa_rsp -= $val;
				if ($cfa_reg eq "%rsp") {
				    $cfa_off -= $val;
				    $dir = "adjust_cfa_offset";
				}
				last;
			      };
	    /def_cfa/	&& do {	if ($$line =~ /(%r\w+)\s*(?:,\s*(.+))?/) {
				    $cfa_reg = $1;
				    if ($cfa_reg eq "%rsp" && !defined($2)) {
					$cfa_off = $cfa_rsp;
					$$line .= ",".(-$cfa_rsp);
				    } else {
					$cfa_off = -1*eval($2);
					$cfa_rsp = $cfa_off if ($cfa_reg eq "%rsp");
				    }
				}
				last;
			      };
	    /push/	&& do {	$dir = undef;
				$cfa_rsp -= 8;
				if ($cfa_reg eq "%rsp") {
				    $cfa_off = $cfa_rsp;
				    $self->{value} = ".cfi_adjust_cfa_offset\t8\n";
				}
				$saved_regs{$$line} = $cfa_rsp;
				$self->{value} .= ".cfi_offset\t$$line,$cfa_rsp";
				last;
			      };
	    /pop/	&& do {	$dir = undef;
				$cfa_rsp += 8;
				if ($cfa_reg eq "%rsp") {
				    $cfa_off = $cfa_rsp;
				    $self->{value} = ".cfi_adjust_cfa_offset\t-8\n";
				}
				$self->{value} .= ".cfi_restore\t$$line";
				delete $saved_regs{$$line};
				last;
			      };
	    /cfa_expression/
			&& do {	$dir = undef;
				$self->{value} = ".cfi_escape\t" .
					join(",", map(sprintf("0x%02x", $_),
						      cfa_expression($$line)));
				last;
			      };
	    /remember_state/
			&& do {	push @cfa_stack,
				     [$cfa_reg,$cfa_off,$cfa_rsp,%saved_regs];
				last;
			      };
	    /restore_state/
			&& do {	     ($cfa_reg,$cfa_off,$cfa_rsp,%saved_regs)
				= @{pop @cfa_stack};
				last;
			      };
	    /offset/	&& do { if ($$line =~ /(%\w+)(?:-%xmm(\d+))?\s*,\s*(.+)/) {
				    my ($reg, $off, $xmmlast) = ($1, 1*eval($3), $2);
				    if ($reg !~ /%xmm(\d+)/) {
					$saved_regs{$reg} = $off;
				    } else {
					$dir = undef;
					$xmmlast //= $1;
					for (my $i=$1; $i<=$xmmlast; $i++) {
					    $saved_regs{"%xmm$i"} = $off;
					    $off += 16;
					}
				    }
				}
				last;
			      };
	    /restore/	&& do {	delete $saved_regs{$$line}; last; };
	    /end_prologue/
			&& do {	$dir = undef;
				$self->{win64} = ".endprolog";
				last;
			      };
	    /epilogue/	&& do {	$dir = undef;
				$self->{win64} = ".epilogue";
				$self->{value} = join("\n",
						      map { ".cfi_restore\t$_" }
						      sort keys(%saved_regs));
				%saved_regs = ();
				last;
			      };
	    }

	    $self->{value} = ".cfi_$dir\t$$line" if ($dir);

	    $$line = "";
	}

	return $ret;
    }
    sub out {
	my $self = shift;
	return $self->{value} if ($dwarf);

	if ($win64 and $current_function->{unwind}
		   and my $ret = $self->{win64}) {
	    my ($reg, $off) = ($cfa_reg =~ /%(?!rsp)/)  ? ($',    $cfa_off)
							: ("rsp", $cfa_rsp);
	    my $fname = $current_function->{name};

	    if ($ret eq ".endprolog") {
		$ret = "";
		if ($current_function->{abi} eq "svr4") {
		    $ret .= label::win64_args();
		    $saved_regs{"%rdi"} = 0;	# relative to CFA, remember?
		    $saved_regs{"%rsi"} = 8;
		}

		push @pdata_seg,
		    ".rva	.LSEH_begin_${fname}",
		    ".rva	.LSEH_body_${fname}",
		    ".rva	.LSEH_info_${fname}_prologue","";
		push @xdata_seg,
		    ".LSEH_info_${fname}_prologue:";
		if ($current_function->{unwind} eq "%rbp") {
		    if ($current_function->{abi} eq "svr4") {
			push @xdata_seg,
			".byte	1,4,6,0x05",	# 6 unwind codes, %rbp is FP
			".byte	4,0x74,2,0",	# %rdi at 16(%rsp)
			".byte	4,0x64,3,0",	# %rsi at 24(%rsp)
			".byte	4,0x53",	# mov	%rsp, %rbp
			".byte	1,0x50",	# push	%rbp
			".long	0,0"		# pad to keep objdump happy
			;
		    } else {
			push @xdata_seg,
			".byte	1,4,2,0x05",	# 2 unwind codes, %rbp is FP
			".byte	4,0x53",	# mov	%rsp, %rbp
			".byte	1,0x50",	# push	%rbp
			".long	0,0"		# pad to keep objdump happy
			;
		    }
		} else {
		    if ($current_function->{abi} eq "svr4") {
			push @xdata_seg,
			".byte	1,0,5,0x0b",	# 5 unwind codes, %r11 is FP
			".byte	0,0x74,1,0",	# %rdi at 8(%rsp)
			".byte	0,0x64,2,0",	# %rsi at 16(%rsp)
			".byte	0,0xb3",	# set frame pointer
			".byte	0,0",		# padding
			".long	0,0"		# pad to keep objdump happy
			;
		    } else {
			push @xdata_seg,
			".byte	1,0,1,0x0b",	# 1 unwind code, %r11 is FP
			".byte	0,0xb3",	# set frame pointer
			".byte	0,0",		# padding
			".long	0,0"		# pad to keep objdump happy
			;
		    }
		}
		push @pdata_seg,
		    ".rva	.LSEH_body_${fname}",
		    ".rva	.LSEH_epilogue_${fname}",
		    ".rva	.LSEH_info_${fname}_body","";
		push @xdata_seg,".LSEH_info_${fname}_body:", xdata();
		$ret .= "${decor}SEH_body_${fname}${colon}\n";
	    } elsif ($ret eq ".epilogue") {
		%saved_regs = ();
		$cfa_rsp = $cfa_off;
		$ret = "${decor}SEH_epilogue_${fname}${colon}\n";
		if ($current_function->{abi} eq "svr4") {
		    $saved_regs{"%rdi"} = 0;	# relative to CFA, remember?
		    $saved_regs{"%rsi"} = 8;

		    push @pdata_seg,
			".rva	.LSEH_epilogue_${fname}",
			".rva	.LSEH_end_${fname}",
			".rva	.LSEH_info_${fname}_epilogue","";
		    push @xdata_seg,".LSEH_info_${fname}_epilogue:", xdata(), "";
		    if ($gas) {
			$ret .= "	mov	".(0-$off)."(%$reg),%rdi\n";
			$ret .= "	mov	".(8-$off)."(%$reg),%rsi\n";
		    } else {
			$ret .= "	mov	rdi,QWORD$PTR\[".(0-$off)."+$reg\]";
			$ret .= "	;WIN64 epilogue\n";
			$ret .= "	mov	rsi,QWORD$PTR\[".(8-$off)."+$reg\]\n";
		    }
		}
	    }
	    return $ret;
	}
	return;
    }
}
{ package directive;	# pick up directives, which start with .
    sub re {
	my	($class, $line) = @_;
	my	$self = {};
	my	$ret;
	my	$dir;

	# chain-call to cfi_directive
	$ret = cfi_directive->re($line) and return $ret;

	if ($$line =~ /^\s*(\.\w+)/) {
	    bless $self,$class;
	    $dir = $1;
	    $ret = $self;
	    undef $self->{value};
	    $$line = substr($$line,@+[0]); $$line =~ s/^\s+//;

	    SWITCH: for ($dir) {
		/\.global|\.globl|\.extern|\.comm/
			    && do { $$line =~ s/([_a-z][_a-z0-9\$]*)/$prefix\1/gi;
				    $globals{$1} = $prefix.$1 if ($1);
				    last;
				  };
		/\.type/    && do { my ($sym,$type,$narg,$unwind) = split(',',$$line);
				    if ($type eq "\@function") {
					undef $current_function;
					$current_function->{name} = $sym;
					$current_function->{abi}  = "svr4";
					$current_function->{narg} = $narg;
					$current_function->{scope} = defined($globals{$sym})?"PUBLIC":"PRIVATE";
					$current_function->{unwind} = $unwind;
					$current_function->{pc} = -1;
				    } elsif ($type eq "\@abi-omnipotent") {
					undef $current_function;
					$current_function->{name} = $sym;
					$current_function->{scope} = defined($globals{$sym})?"PUBLIC":"PRIVATE";
					$current_function->{unwind} = $unwind;
					$current_function->{pc} = -1;
				    }
				    $$line =~ s/\@abi\-omnipotent/\@function/;
				    $$line =~ s/\@function.*/\@function/;
				    last;
				  };
		/\.asciz/   && do { if ($$line =~ /^"(.*)"$/) {
					$dir  = ".byte";
					$$line = join(",",unpack("C*",$1),0);
				    }
				    last;
				  };
		/\.rva|\.long|\.quad/
			    && do { $$line =~ s/([_a-z][_a-z0-9\$]*)/$globals{$1} or $1/gei;
				    $$line =~ s/\.L/$decor/g;
				    last;
				  };
	    }

	    if ($gas) {
		$self->{value} = $dir . "\t" . $$line;

		if ($dir =~ /\.extern/) {
		    $self->{value} = ""; # swallow extern
		} elsif (!$elf && $dir =~ /\.type/) {
		    $self->{value} = "";
		    $self->{value} = ".def\t" . ($globals{$1} or $1) . ";\t" .
				(defined($globals{$1})?".scl 2;":".scl 3;") .
				"\t.type 32;\t.endef"
				if ($win64 && $$line =~ /([^,]+),\@function/);
		} elsif ($dir =~ /\.size/) {
		    $self->{value} = "" if (!$elf);
		    if ($dwarf and my $endproc = cfi_directive::endproc()) {
			$self->{value} = ".cfi_$endproc\n$self->{value}";
		    } elsif (!$elf && defined($current_function)) {
			$self->{value} .= "${decor}SEH_end_$current_function->{name}:"
				if ($win64 && $current_function->{abi} eq "svr4");
			undef $current_function;
		    }
		} elsif (!$elf && $dir =~ /\.align/) {
		    $self->{value} = ".p2align\t" . (log($$line)/log(2));
		} elsif ($dir eq ".section") {
		    $current_segment=$$line;
		    if (!$elf && $current_segment eq ".init") {
			if	($flavour eq "macosx")	{ $self->{value} = ".mod_init_func"; }
			elsif	($flavour eq "mingw64")	{ $self->{value} = ".section\t.ctors"; }
		    }
		    if (!$elf && $current_segment eq ".rodata") {
			if	($flavour eq "macosx")	{ $self->{value} = ".section\t__TEXT,__const"; }
			elsif	($flavour eq "mingw64")	{ $self->{value} = ".section\t.rdata"; }
		    }
		} elsif ($dir =~ /\.(text|data)/) {
		    $current_segment=".$1";
		} elsif ($dir =~ /\.hidden/) {
		    if    ($flavour eq "macosx")  { $self->{value} = ".private_extern\t$prefix$$line"; }
		    elsif ($flavour eq "mingw64") { $self->{value} = ""; }
		} elsif ($dir =~ /\.comm/) {
		    $self->{value} = "$dir\t$$line";
		    $self->{value} =~ s|,([0-9]+),([0-9]+)$|",$1,".log($2)/log(2)|e if ($flavour eq "macosx");
		}
		$$line = "";
		return $self;
	    }

	    # non-gas case or nasm/masm
	    SWITCH: for ($dir) {
		/\.text/    && do { my $v=undef;
				    if ($nasm) {
					$v="section	.text code align=64\n";
				    } else {
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = ".text\$";
					$v.="$current_segment\tSEGMENT ";
					$v.=$masm>=$masmref ? "ALIGN(256)" : "PAGE";
					$v.=" 'CODE'";
				    }
				    $self->{value} = $v;
				    last;
				  };
		/\.data/    && do { my $v=undef;
				    if ($nasm) {
					$v="section	.data data align=8\n";
				    } else {
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = "_DATA";
					$v.="$current_segment\tSEGMENT";
				    }
				    $self->{value} = $v;
				    last;
				  };
		/\.section/ && do { my $v=undef;
				    $$line =~ s/([^,]*).*/$1/;
				    $$line = ".CRT\$XCU" if ($$line eq ".init");
				    $$line = ".rdata" if ($$line eq ".rodata");
				    my %align = ( p=>4, x=>8, r=>256);
				    if ($nasm) {
					$v="section	$$line";
					if ($$line=~/\.([pxr])data/) {
					    $v.=" rdata align=$align{$1}";
					} elsif ($$line=~/\.CRT\$/i) {
					    $v.=" rdata align=8";
					}
				    } else {
					$v="$current_segment\tENDS\n" if ($current_segment);
					$v.="$$line\tSEGMENT";
					if ($$line=~/\.([pxr])data/) {
					    $v.=" READONLY";
					    $v.=" ALIGN($align{$1})" if ($masm>=$masmref);
					} elsif ($$line=~/\.CRT\$/i) {
					    $v.=" READONLY ";
					    $v.=$masm>=$masmref ? "ALIGN(8)" : "DWORD";
					}
				    }
				    $current_segment = $$line;
				    $self->{value} = $v;
				    last;
				  };
		/\.extern/  && do { $self->{value}  = "EXTERN\t".$$line;
				    $self->{value} .= ":NEAR" if ($masm);
				    last;
				  };
		/\.globl|.global/
			    && do { $self->{value}  = $masm?"PUBLIC":"global";
				    $self->{value} .= "\t".$$line;
				    last;
				  };
		/\.size/    && do { if (defined($current_function)) {
					undef $self->{value};
					if ($current_function->{abi} eq "svr4") {
					    $self->{value}="${decor}SEH_end_$current_function->{name}${colon}\n";
					}
					$self->{value}.="$current_function->{name}\tENDP" if($masm && $current_function->{name});
					undef $current_function;
				    }
				    last;
				  };
		/\.align/   && do { my $max = ($masm && $masm>=$masmref) ? 256 : 4096;
				    $self->{value} = "ALIGN\t".($$line>$max?$max:$$line);
				    last;
				  };
		/\.(value|long|rva|quad)/
			    && do { my $sz  = substr($1,0,1);
				    my @arr = split(/,\s*/,$$line);
				    my $last = pop(@arr);
				    my $conv = sub  {	my $var=shift;
							$var=~s/^(0b[0-1]+)/oct($1)/eig;
							$var=~s/^0x([0-9a-f]+)/0$1h/ig if ($masm);
							if ($sz eq "D" && ($current_segment=~/.[px]data/ || $dir eq ".rva"))
							{ $var=~s/^([_a-z\$\@][_a-z0-9\$\@]*)/$nasm?"$1 wrt ..imagebase":"imagerel $1"/egi; }
							$var;
						    };

				    $sz =~ tr/bvlrq/BWDDQ/;
				    $self->{value} = "\tD$sz\t";
				    for (@arr) { $self->{value} .= &$conv($_).","; }
				    $self->{value} .= &$conv($last);
				    last;
				  };
		/\.byte/    && do { my @str=split(/,\s*/,$$line);
				    map(s/(0b[0-1]+)/oct($1)/eig,@str);
				    map(s/0x([0-9a-f]+)/0$1h/ig,@str) if ($masm);
				    while ($#str>15) {
					$self->{value}.="DB\t"
						.join(",",@str[0..15])."\n";
					foreach (0..15) { shift @str; }
				    }
				    $self->{value}.="DB\t"
						.join(",",@str) if (@str);
				    last;
				  };
		/\.comm/    && do { my @str=split(/,\s*/,$$line);
				    my $v=undef;
				    if ($nasm) {
					$v.="common	$prefix@str[0] @str[1]";
				    } else {
					$v="$current_segment\tENDS\n" if ($current_segment);
					$current_segment = "_DATA";
					$v.="$current_segment\tSEGMENT\n";
					$v.="COMM	@str[0]:DWORD:".@str[1]/4;
				    }
				    $self->{value} = $v;
				    last;
				  };
	    }
	    $$line = "";
	}

	$ret;
    }
    sub out {
	my $self = shift;
	$self->{value};
    }
}

# Upon initial x86_64 introduction SSE>2 extensions were not introduced
# yet. In order not to be bothered by tracing exact assembler versions,
# but at the same time to provide a bare security minimum of AES-NI, we
# hard-code some instructions. Extensions past AES-NI on the other hand
# are traced by examining assembler version in individual perlasm
# modules...

my %regrm = (	"%eax"=>0, "%ecx"=>1, "%edx"=>2, "%ebx"=>3,
		"%esp"=>4, "%ebp"=>5, "%esi"=>6, "%edi"=>7	);

sub rex {
 my $opcode=shift;
 my ($dst,$src,$rex)=@_;

   $rex|=0x04 if($dst>=8);
   $rex|=0x01 if($src>=8);
   push @$opcode,($rex|0x40) if ($rex);
}

my $movq = sub {	# elderly gas can't handle inter-register movq
  my $arg = shift;
  my @opcode=(0x66);
    if ($arg =~ /%xmm([0-9]+),\s*%r(\w+)/) {
	my ($src,$dst)=($1,$2);
	if ($dst !~ /[0-9]+/)	{ $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,$src,$dst,0x8);
	push @opcode,0x0f,0x7e;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	@opcode;
    } elsif ($arg =~ /%r(\w+),\s*%xmm([0-9]+)/) {
	my ($src,$dst)=($2,$1);
	if ($dst !~ /[0-9]+/)	{ $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,$src,$dst,0x8);
	push @opcode,0x0f,0x6e;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	@opcode;
    } else {
	();
    }
};

my $pextrd = sub {
    if (shift =~ /\$([0-9]+),\s*%xmm([0-9]+),\s*(%\w+)/) {
      my @opcode=(0x66);
	my $imm=$1;
	my $src=$2;
	my $dst=$3;
	if ($dst =~ /%r([0-9]+)d/)	{ $dst = $1; }
	elsif ($dst =~ /%e/)		{ $dst = $regrm{$dst}; }
	rex(\@opcode,$src,$dst);
	push @opcode,0x0f,0x3a,0x16;
	push @opcode,0xc0|(($src&7)<<3)|($dst&7);	# ModR/M
	push @opcode,$imm;
	@opcode;
    } else {
	();
    }
};

my $pinsrd = sub {
    if (shift =~ /\$([0-9]+),\s*(%\w+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	my $imm=$1;
	my $src=$2;
	my $dst=$3;
	if ($src =~ /%r([0-9]+)/)	{ $src = $1; }
	elsif ($src =~ /%e/)		{ $src = $regrm{$src}; }
	rex(\@opcode,$dst,$src);
	push @opcode,0x0f,0x3a,0x22;
	push @opcode,0xc0|(($dst&7)<<3)|($src&7);	# ModR/M
	push @opcode,$imm;
	@opcode;
    } else {
	();
    }
};

my $pshufb = sub {
    if (shift =~ /%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$2,$1);
	push @opcode,0x0f,0x38,0x00;
	push @opcode,0xc0|($1&7)|(($2&7)<<3);		# ModR/M
	@opcode;
    } else {
	();
    }
};

my $palignr = sub {
    if (shift =~ /\$([0-9]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x3a,0x0f;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	push @opcode,$1;
	@opcode;
    } else {
	();
    }
};

my $pclmulqdq = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x66);
	rex(\@opcode,$3,$2);
	push @opcode,0x0f,0x3a,0x44;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

my $rdrand = sub {
    if (shift =~ /%[er](\w+)/) {
      my @opcode=();
      my $dst=$1;
	if ($dst !~ /[0-9]+/) { $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,0,$dst,8);
	push @opcode,0x0f,0xc7,0xf0|($dst&7);
	@opcode;
    } else {
	();
    }
};

my $rdseed = sub {
    if (shift =~ /%[er](\w+)/) {
      my @opcode=();
      my $dst=$1;
	if ($dst !~ /[0-9]+/) { $dst = $regrm{"%e$dst"}; }
	rex(\@opcode,0,$dst,8);
	push @opcode,0x0f,0xc7,0xf8|($dst&7);
	@opcode;
    } else {
	();
    }
};

# Not all AVX-capable assemblers recognize AMD XOP extension. Since we
# are using only two instructions hand-code them in order to be excused
# from chasing assembler versions...

sub rxb {
 my $opcode=shift;
 my ($dst,$src1,$src2,$rxb)=@_;

   $rxb|=0x7<<5;
   $rxb&=~(0x04<<5) if($dst>=8);
   $rxb&=~(0x01<<5) if($src1>=8);
   $rxb&=~(0x02<<5) if($src2>=8);
   push @$opcode,$rxb;
}

my $vprotd = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x8f);
	rxb(\@opcode,$3,$2,-1,0x08);
	push @opcode,0x78,0xc2;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

my $vprotq = sub {
    if (shift =~ /\$([x0-9a-f]+),\s*%xmm([0-9]+),\s*%xmm([0-9]+)/) {
      my @opcode=(0x8f);
	rxb(\@opcode,$3,$2,-1,0x08);
	push @opcode,0x78,0xc3;
	push @opcode,0xc0|($2&7)|(($3&7)<<3);		# ModR/M
	my $c=$1;
	push @opcode,$c=~/^0/?oct($c):$c;
	@opcode;
    } else {
	();
    }
};

# Intel Control-flow Enforcement Technology extension. All functions and
# indirect branch targets will have to start with this instruction...
# However, it should not be used in functions' prologues explicitly, as
# it's added automatically [and in the right spot]. Which leaves only
# non-function indirect branch targets, such as in a case-like dispatch
# table, as application area.

my $endbr64 = sub {
    (0xf3,0x0f,0x1e,0xfa);
};

########################################################################

my $preproc_prefix = "#";

if ($nasm) {
    $preproc_prefix = "%";
    print <<___;
default	rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
___
} elsif ($masm) {
    $preproc_prefix = "";
    print <<___;
OPTION	DOTNAME
___
}

sub process {
    my $line = shift;

    $line =~ s|\R$||;		# Better chomp

    if ($line =~ m/^#\s*(if|elif|else|endif)(.*)/) {	# pass through preproc
	if ($win64 && $current_function->{abi} eq "svr4"
		   && $current_function->{narg} >= 0) {
	    print label::win64_args();
	}
	print $preproc_prefix,$1,$2,"\n";
	next;
    }

    if ($line =~ m|#\s*__SGX_LVI_HARDENING_CLOBBER__=(?:%?(r\w+))|) {
	$ret_clobber = $1;
    }

    $line =~ s|[#!].*$||;	# get rid of asm-style comments...
    $line =~ s|/\*.*\*/||;	# ... and C-style comments...
    $line =~ s|^\s+||;		# ... and skip white spaces in beginning
    $line =~ s|\s+$||;		# ... and at the end

    if (my $label=label->re(\$line))	{ print $label->out(); }

    if (my $directive=directive->re(\$line)) {
	printf "%s",$directive->out();
    } elsif (my $opcode=opcode->re(\$line)) {
	my $asm = eval("\$".$opcode->mnemonic());

	if ((ref($asm) eq 'CODE') && scalar(my @bytes=&$asm($line))) {
	    print $gas?".byte\t":"DB\t",join(',',@bytes),"\n";
	    next;
	}

	my @args;
	ARGUMENT: while (1) {
	    my $arg;

	    ($arg=register->re(\$line, $opcode))||
	    ($arg=const->re(\$line))		||
	    ($arg=ea->re(\$line, $opcode))	||
	    ($arg=expr->re(\$line, $opcode))	||
	    last ARGUMENT;

	    push @args,$arg;

	    last ARGUMENT if ($line !~ /^,/);

	    $line =~ s/^,\s*//;
	} # ARGUMENT:

	if ($win64 && $current_function->{abi} eq "svr4"
		   && $current_function->{narg} >= 0) {
	    my $pc = $current_function->{pc};
	    my $op = $opcode->{op};
	    my $a0 = @args[0]->{value} if ($#args>=0);
	    if (!$current_function->{unwind}
		|| $pc == 0 && !($op eq "push" && $a0 eq "rbp")
		|| $pc == 1 && !($op eq "mov" && $a0 eq "rsp"
					      && @args[1]->{value} eq "rbp"
					      && ($current_function->{unwind} = "%rbp"))
		|| $pc > 1) {
		print label::win64_args();
	    }
	}

	if ($#args>=0) {
	    my $insn;
	    my $sz=$opcode->size();

	    if ($gas) {
		$insn = $opcode->out($#args>=1?$args[$#args]->size():$sz);
		@args = map($_->out($sz),@args);
		printf "\t%s\t%s",$insn,join(",",@args);
	    } else {
		$insn = $opcode->out();
		foreach (@args) {
		    my $arg = $_->out();
		    # $insn.=$sz compensates for movq, pinsrw, ...
		    if ($arg =~ /^xmm[0-9]+$/) { $insn.=$sz; $sz="x" if(!$sz); last; }
		    if ($arg =~ /^ymm[0-9]+$/) { $insn.=$sz; $sz="y" if(!$sz); last; }
		    if ($arg =~ /^zmm[0-9]+$/) { $insn.=$sz; $sz="z" if(!$sz); last; }
		    if ($arg =~ /^mm[0-9]+$/)  { $insn.=$sz; $sz="q" if(!$sz); last; }
		}
		@args = reverse(@args);
		undef $sz if ($nasm && $opcode->mnemonic() eq "lea");
		printf "\t%s\t%s",$insn,join(",",map($_->out($sz),@args));
	    }
	} else {
	    printf "\t%s",$opcode->out();
	}

	++$current_function->{pc} if (defined($current_function));
    }

    print $line,"\n";
}

while(<>) { process($_); }

map { process($_) } @pdata_seg if ($win64 && $#pdata_seg>1);
map { process($_) } @xdata_seg if ($win64 && $#xdata_seg>1);

# platform-specific epilogue
if ($masm) {
    print "\n$current_segment\tENDS\n"	if ($current_segment);
    print "END\n";
} elsif ($elf) {
    # -fcf-protection segment, snatched from compiler -S output
    my $align = ($flavour =~ /elf32/) ? 4 : 8;
    print <<___;

.section	.note.GNU-stack,"",\@progbits
#ifndef	__SGX_LVI_HARDENING__
.section	.note.gnu.property,"a",\@note
	.long	4,2f-1f,5
	.byte	0x47,0x4E,0x55,0
1:	.long	0xc0000002,4,3
.align	$align
2:
#endif
___
}

close STDOUT;

#################################################
# Cross-reference x86_64 ABI "card"
#
# 		Unix		Win64
# %rax		*		*
# %rbx		-		-
# %rcx		#4		#1
# %rdx		#3		#2
# %rsi		#2		-
# %rdi		#1		-
# %rbp		-		-
# %rsp		-		-
# %r8		#5		#3
# %r9		#6		#4
# %r10		*		*
# %r11		*		*
# %r12		-		-
# %r13		-		-
# %r14		-		-
# %r15		-		-
#
# (*)	volatile register
# (-)	preserved by callee
# (#)	Nth argument, volatile
#
# In Unix terms top of stack is argument transfer area for arguments
# which could not be accommodated in registers. Or in other words 7th
# [integer] argument resides at 8(%rsp) upon function entry point.
# 128 bytes above %rsp constitute a "red zone" which is not touched
# by signal handlers and can be used as temporal storage without
# allocating a frame.
#
# In Win64 terms N*8 bytes on top of stack is argument transfer area,
# which belongs to/can be overwritten by callee. N is the number of
# arguments passed to callee, *but* not less than 4! This means that
# upon function entry point 5th argument resides at 40(%rsp), as well
# as that 32 bytes from 8(%rsp) can always be used as temporal
# storage [without allocating a frame]. One can actually argue that
# one can assume a "red zone" above stack pointer under Win64 as well.
# Point is that at apparently no occasion Windows kernel would alter
# the area above user stack pointer in true asynchronous manner...
#
# All the above means that if assembler programmer adheres to Unix
# register and stack layout, but disregards the "red zone" existence,
# it's possible to use following prologue and epilogue to "gear" from
# Unix to Win64 ABI in leaf functions with not more than 6 arguments.
#
# omnipotent_function:
# ifdef WIN64
#	movq	%rdi,8(%rsp)
#	movq	%rsi,16(%rsp)
#	movq	%rcx,%rdi	; if 1st argument is actually present
#	movq	%rdx,%rsi	; if 2nd argument is actually ...
#	movq	%r8,%rdx	; if 3rd argument is ...
#	movq	%r9,%rcx	; if 4th argument ...
#	movq	40(%rsp),%r8	; if 5th ...
#	movq	48(%rsp),%r9	; if 6th ...
# endif
#	...
# ifdef WIN64
#	movq	8(%rsp),%rdi
#	movq	16(%rsp),%rsi
# endif
#	ret
#
#################################################
# Win64 SEH, Structured Exception Handling.
#
# Unlike on Unix systems(*) lack of Win64 stack unwinding information
# has undesired side-effect at run-time: if an exception is raised in
# assembler subroutine such as those in question (basically we're
# referring to segmentation violations caused by malformed input
# parameters), the application is briskly terminated without invoking
# any exception handlers, most notably without generating memory dump
# or any user notification whatsoever. This poses a problem. It's
# possible to address it by registering custom language-specific
# handler that would restore processor context to the state at
# subroutine entry point and return "exception is not handled, keep
# unwinding" code. Writing such handler can be a challenge... But it's
# doable, though requires certain coding convention. Consider following
# snippet:
#
# .type	function,@function
# function:
#	movq	%rsp,%rax	# copy rsp to volatile register
#	pushq	%r15		# save non-volatile registers
#	pushq	%rbx
#	pushq	%rbp
#	movq	%rsp,%r11
#	subq	%rdi,%r11	# prepare [variable] stack frame
#	andq	$-64,%r11
#	movq	%rax,0(%r11)	# check for exceptions
#	movq	%r11,%rsp	# allocate [variable] stack frame
#	movq	%rax,0(%rsp)	# save original rsp value
# magic_point:
#	...
#	movq	0(%rsp),%rcx	# pull original rsp value
#	movq	-24(%rcx),%rbp	# restore non-volatile registers
#	movq	-16(%rcx),%rbx
#	movq	-8(%rcx),%r15
#	movq	%rcx,%rsp	# restore original rsp
# magic_epilogue:
#	ret
# .size function,.-function
#
# The key is that up to magic_point copy of original rsp value remains
# in chosen volatile register and no non-volatile register, except for
# rsp, is modified. While past magic_point rsp remains constant till
# the very end of the function. In this case custom language-specific
# exception handler would look like this:
#
# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
# {	ULONG64 *rsp = (ULONG64 *)context->Rax;
#	ULONG64  rip = context->Rip;
#
#	if (rip >= magic_point)
#	{   rsp = (ULONG64 *)context->Rsp;
#	    if (rip < magic_epilogue)
#	    {	rsp = (ULONG64 *)rsp[0];
#		context->Rbp = rsp[-3];
#		context->Rbx = rsp[-2];
#		context->R15 = rsp[-1];
#	    }
#	}
#	context->Rsp = (ULONG64)rsp;
#	context->Rdi = rsp[1];
#	context->Rsi = rsp[2];
#
#	memcpy (disp->ContextRecord,context,sizeof(CONTEXT));
#	RtlVirtualUnwind(UNW_FLAG_NHANDLER,disp->ImageBase,
#		dips->ControlPc,disp->FunctionEntry,disp->ContextRecord,
#		&disp->HandlerData,&disp->EstablisherFrame,NULL);
#	return ExceptionContinueSearch;
# }
#
# It's appropriate to implement this handler in assembler, directly in
# function's module. In order to do that one has to know members'
# offsets in CONTEXT and DISPATCHER_CONTEXT structures and some constant
# values. Here they are:
#
#	CONTEXT.Rax				120
#	CONTEXT.Rcx				128
#	CONTEXT.Rdx				136
#	CONTEXT.Rbx				144
#	CONTEXT.Rsp				152
#	CONTEXT.Rbp				160
#	CONTEXT.Rsi				168
#	CONTEXT.Rdi				176
#	CONTEXT.R8				184
#	CONTEXT.R9				192
#	CONTEXT.R10				200
#	CONTEXT.R11				208
#	CONTEXT.R12				216
#	CONTEXT.R13				224
#	CONTEXT.R14				232
#	CONTEXT.R15				240
#	CONTEXT.Rip				248
#	CONTEXT.Xmm6				512
#	sizeof(CONTEXT)				1232
#	DISPATCHER_CONTEXT.ControlPc		0
#	DISPATCHER_CONTEXT.ImageBase		8
#	DISPATCHER_CONTEXT.FunctionEntry	16
#	DISPATCHER_CONTEXT.EstablisherFrame	24
#	DISPATCHER_CONTEXT.TargetIp		32
#	DISPATCHER_CONTEXT.ContextRecord	40
#	DISPATCHER_CONTEXT.LanguageHandler	48
#	DISPATCHER_CONTEXT.HandlerData		56
#	UNW_FLAG_NHANDLER			0
#	ExceptionContinueSearch			1
#
# In order to tie the handler to the function one has to compose
# couple of structures: one for .xdata segment and one for .pdata.
#
# UNWIND_INFO structure for .xdata segment would be
#
# function_unwind_info:
#	.byte	9,0,0,0
#	.rva	handler
#
# This structure designates exception handler for a function with
# zero-length prologue, no stack frame or frame register.
#
# To facilitate composing of .pdata structures, auto-generated "gear"
# prologue copies rsp value to rax and denotes next instruction with
# .LSEH_begin_{function_name} label. This essentially defines the SEH
# styling rule mentioned in the beginning. Position of this label is
# chosen in such manner that possible exceptions raised in the "gear"
# prologue would be accounted to caller and unwound from latter's frame.
# End of function is marked with respective .LSEH_end_{function_name}
# label. To summarize, .pdata segment would contain
#
#	.rva	.LSEH_begin_function
#	.rva	.LSEH_end_function
#	.rva	function_unwind_info
#
# Reference to function_unwind_info from .xdata segment is the anchor.
# In case you wonder why references are 32-bit .rvas and not 64-bit
# .quads. References put into these two segments are required to be
# *relative* to the base address of the current binary module, a.k.a.
# image base. No Win64 module, be it .exe or .dll, can be larger than
# 2GB and thus such relative references can be and are accommodated in
# 32 bits.
#
# Having reviewed the example function code, one can argue that "movq
# %rsp,%rax" above is redundant. It is not! Keep in mind that on Unix
# rax would contain an undefined value. If this "offends" you, use
# another register and refrain from modifying rax till magic_point is
# reached, i.e. as if it was a non-volatile register. If more registers
# are required prior [variable] frame setup is completed, note that
# nobody says that you can have only one "magic point." You can
# "liberate" non-volatile registers by denoting last stack off-load
# instruction and reflecting it in finer grade unwind logic in handler.
# After all, isn't it why it's called *language-specific* handler...
#
# SE handlers are also involved in unwinding stack when executable is
# profiled or debugged. Profiling implies additional limitations that
# are too subtle to discuss here. For now it's sufficient to say that
# in order to simplify handlers one should either a) offload original
# %rsp to stack (like discussed above); or b) if you have a register to
# spare for frame pointer, choose volatile one.
#
# (*)	Note that we're talking about run-time, not debug-time. Lack of
#	unwind information makes debugging hard on both Windows and
#	Unix. "Unlike" refers to the fact that on Unix signal handler
#	will always be invoked, core dumped and appropriate exit code
#	returned to parent (for user notification).
#
########################################################################
# As of May 2020 an alternative approach that works with both exceptions
# and debugging/profiling was implemented by re-purposing DWARF .cfi
# annotations even for Win64 unwind tables' generation. Unfortunately,
# but not really unexpectedly, it imposes additional limitations on
# coding style. Probably the most significant limitation is that the
# frame pointer has to be at 16*n distance from the stack pointer at the
# exit from prologue. But first things first. There are two additional
# synthetic .cfi directives, .cfi_end_prologue and .cfi_epilogue,
# that need to be added to all functions marked with additional .type
# tag (see example below). There are "do's and don'ts" for prologue
# and epilogue. It shouldn't come as a surprise that in prologue one may
# not modify non-volatile registers, but one may not modify %r11 either.
# This is because it's used as a temporary frame pointer(*). There are
# two exceptions to this rule. 1) One can set up a non-volatile register
# or %r11 as a frame pointer, but it must be last instruction in the
# prologue. 2) One can use 'push %rbp' as first instruction immediately
# followed by 'mov %rsp,%rbp' to use %rbp as "legacy" frame pointer.
# Constraints for epilogue, or rather on its boundary, depend on whether
# the frame is fixed- or variable-length. In fixed-frame subroutine
# stack pointer has to be restored in the last instruction prior to the
# .cfi_epilogue directive. If it's a variable-frame subroutine, and a
# non-volatile register was used as a frame pointer, then the last
# instruction prior to the directive has to restore its original value.
# This means that final stack pointer adjustment would have to be
# pushed past the directive. Normally this would render the epilogue
# non-unwindable, so special care has to be taken. To resolve the
# dilemma, copy the frame pointer to a volatile register in advance.
# To give an example:
#
# .type	rbp_as_frame_pointer,\@function,3,"unwind"  # mind extra tag!
# rbp_as_frame_pointer:
# .cfi_startproc
#	push	%rbp
# .cfi_push	%rbp
#	push	%rbx
# .cfi_push	%rbx
# 	mov	%rsp,%rbp	# last instruction in prologue
# .cfi_def_cfa_register	%rbp	# %rsp-%rbp has to be 16*n, e.g. 16*0
# .cfi_end_prologue
#	sub	\$40,%rsp
#	and	\$-64,%rsp
#	...
#	mov	%rbp,%r11
# .cfi_def_cfa_register	%r11	# copy frame pointer to volatile %r11
#	mov	0(%rbp),%rbx
#	mov	8(%rbp),%rbp	# last instruction prior epilogue
# .cfi_epilogue			# may not change %r11 in epilogue
#	lea	16(%r11),%rsp
#	ret
# .cfi_endproc
# .size	rbp_as_frame_pointer,.-rbp_as_frame_pointer
#
# An example of "legacy" frame pointer:
#
# .type	legacy_frame_pointer,\@function,3,"unwind"  # mind extra tag!
# legacy_frame_pointer:
# .cfi_startproc
#	push	%rbp
# .cfi_push	%rbp
# 	mov	%rsp,%rbp
# .cfi_def_cfa_register	%rbp
#	push	%rbx
# .cfi_push	%rbx
#	sub	\$40,%rsp
# .cfi_alloca	40
# .cfi_end_prologue		# %rsp-%rbp has to be 16*n
#	and	\$-64,%rsp
#	...
#	mov	-8(%rbp),%rbx
#	mov	%rbp,%rsp
# .cfi_def_cfa_regiser	%rsp
#	pop	%rbp		# recognized by Windows
# .cfi_pop	%rbp
# .cfi_epilogue
#	ret
# .cfi_endproc
# .size	legacy_frame_pointer,.-legacy_frame_pointer
#
# To give an example of fixed-frame subroutine for reference:
#
# .type	fixed_frame,\@function,3,"unwind"           # mind extra tag!
# fixed_frame:
# .cfi_startproc
#	push	%rbp
# .cfi_push	%rbp
#	push	%rbx
# .cfi_push	%rbx
#	sub	\$40,%rsp
# .cfi_adjust_cfa_offset 40
# .cfi_end_prologue
#	...
#	mov	40(%rsp),%rbx
#	mov	48(%rsp),%rbp
#	lea	56(%rsp),%rsp
# .cfi_adjust_cfa_offset -56
# .cfi_epilogue
#	ret
# .cfi_endproc
# .size	fixed_frame,.-fixed_frame
#
# As for epilogue itself, one can only work on non-volatile registers.
# "Non-volatile" in "Windows" sense, i.e. minus %rdi and %rsi.
#
# On a final note, mixing old-style and modernized subroutines in the
# same file takes some trickery. Ones of the new kind have to appear
# after old-style ones. This has everything to do with the fact that
# entries in the .pdata segment have to appear in strictly same order
# as corresponding subroutines, and auto-generated RUNTIME_FUNCTION
# structures get mechanically appended to whatever existing .pdata.
#
# (*)	Just in case, why %r11 and not %rax. This has everything to do
#	with the way UNWIND_INFO is, one just can't designate %rax as
#	frame pointer.
