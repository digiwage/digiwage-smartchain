// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// DO NOT MODIFY THIS FILE!!
// The file is generated from *.tgo by generate.py
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/*
 * Copyright Supranational LLC
 * Licensed under the Apache License, Version 2.0, see LICENSE for details.
 * SPDX-License-Identifier: Apache-2.0
 */

package blst

// #cgo CFLAGS: -I${SRCDIR}/.. -I${SRCDIR}/../../build -I${SRCDIR}/../../src -D__BLST_CGO__ -fno-builtin-memcpy -fno-builtin-memset
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// // no-asm 64-bit platforms from https://go.dev/doc/install/source
// #cgo loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__
//
// #include "blst.h"
//
// #if defined(__x86_64__) && (defined(__unix__) || defined(__APPLE__))
// # include <signal.h>
// # include <unistd.h>
// static void handler(int signum)
// {   ssize_t n = write(2, "Caught SIGILL in blst_cgo_init, "
//                          "consult <blst>/bindings/go/README.md.\n", 70);
//     _exit(128+SIGILL);
//     (void)n;
// }
// __attribute__((constructor)) static void blst_cgo_init()
// {   blst_fp temp = { 0 };
//     struct sigaction act = { handler }, oact;
//     sigaction(SIGILL, &act, &oact);
//     blst_fp_sqr(&temp, &temp);
//     sigaction(SIGILL, &oact, NULL);
// }
// #endif
//
// static void go_pairing_init(blst_pairing *new_ctx, bool hash_or_encode,
//                             const byte *DST, size_t DST_len)
// {   if (DST != NULL) {
//         byte *dst = (byte*)new_ctx + blst_pairing_sizeof();
//         for(size_t i = 0; i < DST_len; i++) dst[i] = DST[i];
//         DST = dst;
//     }
//     blst_pairing_init(new_ctx, hash_or_encode, DST, DST_len);
// }
// static void go_pairing_as_fp12(blst_fp12 *pt, blst_pairing *ctx)
// {   *pt = *blst_pairing_as_fp12(ctx);   }
//
// static void go_p1slice_to_affine(blst_p1_affine dst[],
//                                  const blst_p1 points[], size_t npoints)
// {   const blst_p1 *ppoints[2] = { points, NULL };
//     blst_p1s_to_affine(dst, ppoints, npoints);
// }
// static void go_p1slice_add(blst_p1 *dst, const blst_p1_affine points[],
//                                          size_t npoints)
// {   const blst_p1_affine *ppoints[2] = { points, NULL };
//     blst_p1s_add(dst, ppoints, npoints);
// }
// static void go_p2slice_to_affine(blst_p2_affine dst[],
//                                  const blst_p2 points[], size_t npoints)
// {   const blst_p2 *ppoints[2] = { points, NULL };
//     blst_p2s_to_affine(dst, ppoints, npoints);
// }
// static void go_p2slice_add(blst_p2 *dst, const blst_p2_affine points[],
//                                          size_t npoints)
// {   const blst_p2_affine *ppoints[2] = { points, NULL };
//     blst_p2s_add(dst, ppoints, npoints);
// }
//
// static void go_p1_mult_n_acc(blst_p1 *acc, const blst_fp *x, bool affine,
//                                            const byte *scalar, size_t nbits)
// {   blst_p1 m[1];
//     const void *p = x;
//     if (p == NULL)
//         p = blst_p1_generator();
//     else if (affine)
//         blst_p1_from_affine(m, p), p = m;
//     blst_p1_mult(m, p, scalar, nbits);
//     blst_p1_add_or_double(acc, acc, m);
// }
// static void go_p2_mult_n_acc(blst_p2 *acc, const blst_fp2 *x, bool affine,
//                                            const byte *scalar, size_t nbits)
// {   blst_p2 m[1];
//     const void *p = x;
//     if (p == NULL)
//         p = blst_p2_generator();
//     else if (affine)
//         blst_p2_from_affine(m, p), p = m;
//     blst_p2_mult(m, p, scalar, nbits);
//     blst_p2_add_or_double(acc, acc, m);
// }
//
// static void go_p1_sub_assign(blst_p1 *a, const blst_fp *x, bool affine)
// {   blst_p1 minus_b;
//     if (affine)
//         blst_p1_from_affine(&minus_b, (const blst_p1_affine*)x);
//     else
//         minus_b = *(const blst_p1*)x;
//     blst_p1_cneg(&minus_b, 1);
//     blst_p1_add_or_double(a, a, &minus_b);
// }
//
// static void go_p2_sub_assign(blst_p2 *a, const blst_fp2 *x, bool affine)
// {   blst_p2 minus_b;
//     if (affine)
//         blst_p2_from_affine(&minus_b, (const blst_p2_affine*)x);
//     else
//         minus_b = *(const blst_p2*)x;
//     blst_p2_cneg(&minus_b, 1);
//     blst_p2_add_or_double(a, a, &minus_b);
// }
//
// static bool go_scalar_from_bendian(blst_scalar *ret, const byte *in)
// {   blst_scalar_from_bendian(ret, in);
//     return blst_sk_check(ret);
// }
// static bool go_hash_to_scalar(blst_scalar *ret,
//                               const byte *msg, size_t msg_len,
//                               const byte *DST, size_t DST_len)
// {   byte elem[48];
//     blst_expand_message_xmd(elem, sizeof(elem), msg, msg_len, DST, DST_len);
//     return blst_scalar_from_be_bytes(ret, elem, sizeof(elem));
// }
// static void go_miller_loop_n(blst_fp12 *dst, const blst_p2_affine Q[],
//                                              const blst_p1_affine P[],
//                                              size_t npoints, bool acc)
// {   const blst_p2_affine *Qs[2] = { Q, NULL };
//     const blst_p1_affine *Ps[2] = { P, NULL };
//     if (acc) {
//         blst_fp12 tmp;
//         blst_miller_loop_n(&tmp, Qs, Ps, npoints);
//         blst_fp12_mul(dst, dst, &tmp);
//     } else {
//         blst_miller_loop_n(dst, Qs, Ps, npoints);
//     }
// }
// static void go_fp12slice_mul(blst_fp12 *dst, const blst_fp12 in[], size_t n)
// {   size_t i;
//     blst_fp12_mul(dst, &in[0], &in[1]);
//     for (i = 2; i < n; i++)
//         blst_fp12_mul(dst, dst, &in[i]);
// }
// static bool go_p1_affine_validate(const blst_p1_affine *p, bool infcheck)
// {   if (infcheck && blst_p1_affine_is_inf(p))
//         return 0;
//     return blst_p1_affine_in_g1(p);
// }
// static bool go_p2_affine_validate(const blst_p2_affine *p, bool infcheck)
// {   if (infcheck && blst_p2_affine_is_inf(p))
//         return 0;
//     return blst_p2_affine_in_g2(p);
// }
import "C"

import (
	"fmt"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
)

const BLST_SCALAR_BYTES = 256 / 8
const BLST_FP_BYTES = 384 / 8
const BLST_P1_COMPRESS_BYTES = BLST_FP_BYTES
const BLST_P1_SERIALIZE_BYTES = BLST_FP_BYTES * 2
const BLST_P2_COMPRESS_BYTES = BLST_FP_BYTES * 2
const BLST_P2_SERIALIZE_BYTES = BLST_FP_BYTES * 4

type Scalar = C.blst_scalar
type Fp = C.blst_fp
type Fp2 = C.blst_fp2
type Fp6 = C.blst_fp6
type Fp12 = C.blst_fp12
type P1 = C.blst_p1
type P2 = C.blst_p2
type P1Affine = C.blst_p1_affine
type P2Affine = C.blst_p2_affine
type Message = []byte
type Pairing = []C.blst_pairing
type SecretKey = Scalar
type P1s []P1
type P2s []P2
type P1Affines []P1Affine
type P2Affines []P2Affine

//
// Configuration
//

var maxProcs = initMaxProcs()

func initMaxProcs() int {
	maxProcs := runtime.GOMAXPROCS(0)
	var version float32
	_, err := fmt.Sscanf(runtime.Version(), "go%f", &version)
	if err != nil || version < 1.14 {
		// be cooperative and leave one processor for the application
		maxProcs -= 1
	}
	if maxProcs <= 0 {
		maxProcs = 1
	}
	return maxProcs
}

func SetMaxProcs(max int) {
	if max <= 0 {
		max = 1
	}
	maxProcs = max
}

func numThreads(maxThreads int) int {
	numThreads := maxProcs

	// take into consideration the possility that application reduced
	// GOMAXPROCS after |maxProcs| was initialized
	numProcs := runtime.GOMAXPROCS(0)
	if maxProcs > numProcs {
		numThreads = numProcs
	}

	if maxThreads > 0 && numThreads > maxThreads {
		return maxThreads
	}
	return numThreads
}

var cgo_pairingSizeOf = C.blst_pairing_sizeof()
var cgo_p1Generator = *C.blst_p1_generator()
var cgo_p2Generator = *C.blst_p2_generator()
var cgo_fp12One = *C.blst_fp12_one()

// Secret key
func (sk *SecretKey) Zeroize() {
	var zero SecretKey
	*sk = zero
}

func KeyGen(ikm []byte, optional ...[]byte) *SecretKey {
	var sk SecretKey
	var info []byte
	if len(optional) > 0 {
		info = optional[0]
	}
	if len(ikm) < 32 {
		return nil
	}
	C.blst_keygen(&sk, (*C.byte)(&ikm[0]), C.size_t(len(ikm)),
		ptrOrNil(info), C.size_t(len(info)))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

func KeyGenV3(ikm []byte, optional ...[]byte) *SecretKey {
	if len(ikm) < 32 {
		return nil
	}
	var sk SecretKey
	var info []byte
	if len(optional) > 0 {
		info = optional[0]
	}
	C.blst_keygen_v3(&sk, (*C.byte)(&ikm[0]), C.size_t(len(ikm)),
		ptrOrNil(info), C.size_t(len(info)))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

func KeyGenV45(ikm []byte, salt []byte, optional ...[]byte) *SecretKey {
	if len(ikm) < 32 {
		return nil
	}
	var sk SecretKey
	var info []byte
	if len(optional) > 0 {
		info = optional[0]
	}
	C.blst_keygen_v4_5(&sk, (*C.byte)(&ikm[0]), C.size_t(len(ikm)),
		(*C.byte)(&salt[0]), C.size_t(len(salt)),
		ptrOrNil(info), C.size_t(len(info)))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

func KeyGenV5(ikm []byte, salt []byte, optional ...[]byte) *SecretKey {
	if len(ikm) < 32 {
		return nil
	}
	var sk SecretKey
	var info []byte
	if len(optional) > 0 {
		info = optional[0]
	}
	C.blst_keygen_v5(&sk, (*C.byte)(&ikm[0]), C.size_t(len(ikm)),
		(*C.byte)(&salt[0]), C.size_t(len(salt)),
		ptrOrNil(info), C.size_t(len(info)))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

func DeriveMasterEip2333(ikm []byte) *SecretKey {
	if len(ikm) < 32 {
		return nil
	}
	var sk SecretKey
	C.blst_derive_master_eip2333(&sk, (*C.byte)(&ikm[0]), C.size_t(len(ikm)))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

func (master *SecretKey) DeriveChildEip2333(child_index uint32) *SecretKey {
	var sk SecretKey
	C.blst_derive_child_eip2333(&sk, master, C.uint(child_index))
	// Postponing secret key zeroing till garbage collection can be too
	// late to be effective, but every little bit helps...
	runtime.SetFinalizer(&sk, func(sk *SecretKey) { sk.Zeroize() })
	return &sk
}

// Pairing
func pairingSizeOf(DST_len C.size_t) int {
	return int((cgo_pairingSizeOf + DST_len + 7) / 8)
}

func PairingCtx(hash_or_encode bool, DST []byte) Pairing {
	DST_len := C.size_t(len(DST))
	ctx := make([]C.blst_pairing, pairingSizeOf(DST_len))
	C.go_pairing_init(&ctx[0], C.bool(hash_or_encode), ptrOrNil(DST), DST_len)
	return ctx
}

func PairingCommit(ctx Pairing) {
	C.blst_pairing_commit(&ctx[0])
}

func PairingMerge(ctx Pairing, ctx1 Pairing) int {
	r := C.blst_pairing_merge(&ctx[0], &ctx1[0])
	return int(r)
}

func PairingFinalVerify(ctx Pairing, optional ...*Fp12) bool {
	var gtsig *Fp12
	if len(optional) > 0 {
		gtsig = optional[0]
	}
	return bool(C.blst_pairing_finalverify(&ctx[0], gtsig))
}

func PairingRawAggregate(ctx Pairing, q *P2Affine, p *P1Affine) {
	C.blst_pairing_raw_aggregate(&ctx[0], q, p)
}

func PairingAsFp12(ctx Pairing) *Fp12 {
	var pt Fp12
	C.go_pairing_as_fp12(&pt, &ctx[0])
	return &pt
}

func Fp12One() Fp12 {
	return cgo_fp12One
}

func Fp12FinalVerify(pt1 *Fp12, pt2 *Fp12) bool {
	return bool(C.blst_fp12_finalverify(pt1, pt2))
}

func Fp12MillerLoop(q *P2Affine, p *P1Affine) *Fp12 {
	var pt Fp12
	C.blst_miller_loop(&pt, q, p)
	return &pt
}

func Fp12MillerLoopN(qs []P2Affine, ps []P1Affine) *Fp12 {
	if len(qs) != len(ps) || len(qs) == 0 {
		panic("inputs' lengths mismatch")
	}

	nElems := uint32(len(qs))
	nThreads := uint32(maxProcs)

	if nThreads == 1 || nElems == 1 {
		var pt Fp12
		C.go_miller_loop_n(&pt, &qs[0], &ps[0], C.size_t(nElems), false)
		return &pt
	}

	stride := (nElems + nThreads - 1) / nThreads
	if stride > 16 {
		stride = 16
	}

	strides := (nElems + stride - 1) / stride
	if nThreads > strides {
		nThreads = strides
	}

	msgsCh := make(chan Fp12, nThreads)
	curElem := uint32(0)

	for tid := uint32(0); tid < nThreads; tid++ {
		go func() {
			acc := Fp12One()
			first := true
			for {
				work := atomic.AddUint32(&curElem, stride) - stride
				if work >= nElems {
					break
				}
				n := nElems - work
				if n > stride {
					n = stride
				}
				C.go_miller_loop_n(&acc, &qs[work], &ps[work], C.size_t(n),
					C.bool(!first))
				first = false
			}
			msgsCh <- acc
		}()
	}

	var ret = make([]Fp12, nThreads)
	for i := range ret {
		ret[i] = <-msgsCh
	}

	var pt Fp12
	C.go_fp12slice_mul(&pt, &ret[0], C.size_t(nThreads))
	return &pt
}

func (pt *Fp12) MulAssign(p *Fp12) {
	C.blst_fp12_mul(pt, pt, p)
}

func (pt *Fp12) FinalExp() {
	C.blst_final_exp(pt, pt)
}

func (pt *Fp12) InGroup() bool {
	return bool(C.blst_fp12_in_group(pt))
}

func (pt *Fp12) ToBendian() []byte {
	var out [BLST_FP_BYTES * 12]byte
	C.blst_bendian_from_fp12((*C.byte)(&out[0]), pt)
	return out[:]
}

func (pt1 *Fp12) Equals(pt2 *Fp12) bool {
	return *pt1 == *pt2
}

func ptrOrNil(bytes []byte) *C.byte {
	var ptr *C.byte
	if len(bytes) > 0 {
		ptr = (*C.byte)(&bytes[0])
	}
	return ptr
}

//
// MIN-PK
//

//
// PublicKey
//

func (pk *P1Affine) From(s *Scalar) *P1Affine {
	C.blst_sk_to_pk2_in_g1(nil, pk, s)
	return pk
}

func (pk *P1Affine) KeyValidate() bool {
	return bool(C.go_p1_affine_validate(pk, true))
}

// sigInfcheck, check for infinity, is a way to avoid going
// into resource-consuming verification. Passing 'false' is
// always cryptographically safe, but application might want
// to guard against obviously bogus individual[!] signatures.
func (sig *P2Affine) SigValidate(sigInfcheck bool) bool {
	return bool(C.go_p2_affine_validate(sig, C.bool(sigInfcheck)))
}

//
// Sign
//

func (sig *P2Affine) Sign(sk *SecretKey, msg []byte, dst []byte,
	optional ...interface{}) *P2Affine {
	augSingle, aug, useHash, ok := parseOpts(optional...)
	if !ok || len(aug) != 0 {
		return nil
	}

	var q *P2
	if useHash {
		q = HashToG2(msg, dst, augSingle)
	} else {
		q = EncodeToG2(msg, dst, augSingle)
	}
	C.blst_sign_pk2_in_g1(nil, sig, q, sk)
	return sig
}

//
// Signature
//

// Functions to return a signature and public key+augmentation tuple.
// This enables point decompression (if needed) to happen in parallel.
type sigGetterP2 func() *P2Affine
type pkGetterP1 func(i uint32, temp *P1Affine) (*P1Affine, []byte)

// Single verify with decompressed pk
func (sig *P2Affine) Verify(sigGroupcheck bool, pk *P1Affine, pkValidate bool,
	msg Message, dst []byte,
	optional ...interface{}) bool { // useHash bool, aug []byte

	aug, _, useHash, ok := parseOpts(optional...)
	if !ok {
		return false
	}
	return sig.AggregateVerify(sigGroupcheck, []*P1Affine{pk}, pkValidate,
		[]Message{msg}, dst, useHash, [][]byte{aug})
}

// Single verify with compressed pk
// Uses a dummy signature to get the correct type
func (dummy *P2Affine) VerifyCompressed(sig []byte, sigGroupcheck bool,
	pk []byte, pkValidate bool, msg Message, dst []byte,
	optional ...bool) bool { // useHash bool, usePksAsAugs bool

	return dummy.AggregateVerifyCompressed(sig, sigGroupcheck,
		[][]byte{pk}, pkValidate,
		[]Message{msg}, dst, optional...)
}

// Aggregate verify with uncompressed signature and public keys
// Note that checking message uniqueness, if required, is left to the user.
// Not all signature schemes require it and this keeps the binding minimal
// and fast. Refer to the Uniq function for one method method of performing
// this check.
func (sig *P2Affine) AggregateVerify(sigGroupcheck bool,
	pks []*P1Affine, pksVerify bool, msgs []Message, dst []byte,
	optional ...interface{}) bool { // useHash bool, augs [][]byte

	// sanity checks and argument parsing
	n := len(pks)
	if n == 0 || len(msgs) != n {
		return false
	}
	_, augs, useHash, ok := parseOpts(optional...)
	useAugs := len(augs) != 0
	if !ok || (useAugs && len(augs) != n) {
		return false
	}

	sigFn := func() *P2Affine {
		return sig
	}

	pkFn := func(i uint32, _ *P1Affine) (*P1Affine, []byte) {
		if useAugs {
			return pks[i], augs[i]
		}
		return pks[i], nil
	}

	return coreAggregateVerifyPkInG1(sigFn, sigGroupcheck, pkFn, pksVerify,
		msgs, dst, useHash)
}

// Aggregate verify with compressed signature and public keys
// Uses a dummy signature to get the correct type
func (_ *P2Affine) AggregateVerifyCompressed(sig []byte, sigGroupcheck bool,
	pks [][]byte, pksVerify bool, msgs []Message, dst []byte,
	optional ...bool) bool { // useHash bool, usePksAsAugs bool

	// sanity checks and argument parsing
	if len(pks) != len(msgs) {
		return false
	}
	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}
	usePksAsAugs := false
	if len(optional) > 1 {
		usePksAsAugs = optional[1]
	}

	sigFn := func() *P2Affine {
		sigP := new(P2Affine)
		if sigP.Uncompress(sig) == nil {
			return nil
		}
		return sigP
	}
	pkFn := func(i uint32, pk *P1Affine) (*P1Affine, []byte) {
		bytes := pks[i]
		if len(bytes) == BLST_P1_SERIALIZE_BYTES && (bytes[0]&0x80) == 0 {
			// Not compressed
			if pk.Deserialize(bytes) == nil {
				return nil, nil
			}
		} else if len(bytes) == BLST_P1_COMPRESS_BYTES && (bytes[0]&0x80) != 0 {
			if pk.Uncompress(bytes) == nil {
				return nil, nil
			}
		} else {
			return nil, nil
		}
		if usePksAsAugs {
			return pk, bytes
		}
		return pk, nil
	}
	return coreAggregateVerifyPkInG1(sigFn, sigGroupcheck, pkFn, pksVerify,
		msgs, dst, useHash)
}

func coreAggregateVerifyPkInG1(sigFn sigGetterP2, sigGroupcheck bool,
	pkFn pkGetterP1, pkValidate bool, msgs []Message, dst []byte,
	optional ...bool) bool { // useHash

	n := len(msgs)
	if n == 0 {
		return false
	}

	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}

	numCores := runtime.GOMAXPROCS(0)
	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding pk,msg[,aug] tuple and
	// repeat until n is exceeded.  The resulting accumulations will be
	// fed into the msgsCh channel.
	msgsCh := make(chan Pairing, numThreads)
	valid := int32(1)
	curItem := uint32(0)
	mutex := sync.Mutex{}

	mutex.Lock()
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			pairing := PairingCtx(useHash, dst)
			var temp P1Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				} else if work == 0 && maxProcs == numCores-1 &&
					numThreads == maxProcs {
					// Avoid consuming all cores by waiting until the
					// main thread has completed its miller loop before
					// proceeding.
					mutex.Lock()
					mutex.Unlock() //nolint:staticcheck
				}

				// Pull Public Key and augmentation blob
				curPk, aug := pkFn(work, &temp)
				if curPk == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// Pairing and accumulate
				ret := PairingAggregatePkInG1(pairing, curPk, pkValidate,
					nil, false, msgs[work], aug)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// application might have some async work to do
				runtime.Gosched()
			}
			if atomic.LoadInt32(&valid) > 0 {
				PairingCommit(pairing)
				msgsCh <- pairing
			} else {
				msgsCh <- nil
			}
		}()
	}

	// Uncompress and check signature
	var gtsig Fp12
	sig := sigFn()
	if sig == nil {
		atomic.StoreInt32(&valid, 0)
	}
	if atomic.LoadInt32(&valid) > 0 && sigGroupcheck &&
		!sig.SigValidate(false) {
		atomic.StoreInt32(&valid, 0)
	}
	if atomic.LoadInt32(&valid) > 0 {
		C.blst_aggregated_in_g2(&gtsig, sig)
	}
	mutex.Unlock()

	// Accumulate the thread results
	var pairings Pairing
	for i := 0; i < numThreads; i++ {
		msg := <-msgsCh
		if msg != nil {
			if pairings == nil {
				pairings = msg
			} else {
				ret := PairingMerge(pairings, msg)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
				}
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 || pairings == nil {
		return false
	}

	return PairingFinalVerify(pairings, &gtsig)
}

func CoreVerifyPkInG1(pk *P1Affine, sig *P2Affine, hash_or_encode bool,
	msg Message, dst []byte, optional ...[]byte) int {

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	if runtime.NumGoroutine() < maxProcs {
		sigFn := func() *P2Affine {
			return sig
		}
		pkFn := func(_ uint32, _ *P1Affine) (*P1Affine, []byte) {
			return pk, aug
		}
		if !coreAggregateVerifyPkInG1(sigFn, true, pkFn, true, []Message{msg},
			dst, hash_or_encode) {
			return C.BLST_VERIFY_FAIL
		}
		return C.BLST_SUCCESS
	}

	return int(C.blst_core_verify_pk_in_g1(pk, sig, C.bool(hash_or_encode),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug))))
}

// pks are assumed to be verified for proof of possession,
// which implies that they are already group-checked
func (sig *P2Affine) FastAggregateVerify(sigGroupcheck bool,
	pks []*P1Affine, msg Message, dst []byte,
	optional ...interface{}) bool { // pass-through to Verify
	n := len(pks)

	// TODO: return value for length zero?
	if n == 0 {
		return false
	}

	aggregator := new(P1Aggregate)
	if !aggregator.Aggregate(pks, false) {
		return false
	}
	pkAff := aggregator.ToAffine()

	// Verify
	return sig.Verify(sigGroupcheck, pkAff, false, msg, dst, optional...)
}

func (_ *P2Affine) MultipleAggregateVerify(sigs []*P2Affine,
	sigsGroupcheck bool, pks []*P1Affine, pksVerify bool,
	msgs []Message, dst []byte, randFn func(*Scalar), randBits int,
	optional ...interface{}) bool { // useHash

	// Sanity checks and argument parsing
	n := len(pks)
	if n == 0 || len(msgs) != n || len(sigs) != n {
		return false
	}
	_, augs, useHash, ok := parseOpts(optional...)
	useAugs := len(augs) != 0
	if !ok || (useAugs && len(augs) != n) {
		return false
	}

	paramsFn :=
		func(work uint32, _ *P2Affine, _ *P1Affine, rand *Scalar) (
			*P2Affine, *P1Affine, *Scalar, []byte) {
			randFn(rand)
			var aug []byte
			if useAugs {
				aug = augs[work]
			}
			return sigs[work], pks[work], rand, aug
		}

	return multipleAggregateVerifyPkInG1(paramsFn, sigsGroupcheck, pksVerify,
		msgs, dst, randBits, useHash)
}

type mulAggGetterPkInG1 func(work uint32, sig *P2Affine, pk *P1Affine,
	rand *Scalar) (*P2Affine, *P1Affine, *Scalar, []byte)

func multipleAggregateVerifyPkInG1(paramsFn mulAggGetterPkInG1,
	sigsGroupcheck bool, pksVerify bool, msgs []Message,
	dst []byte, randBits int,
	optional ...bool) bool { // useHash
	n := len(msgs)
	if n == 0 {
		return false
	}

	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}

	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding pk,msg[,aug] tuple and
	// repeat until n is exceeded.  The resulting accumulations will be
	// fed into the msgsCh channel.
	msgsCh := make(chan Pairing, numThreads)
	valid := int32(1)
	curItem := uint32(0)

	for tid := 0; tid < numThreads; tid++ {
		go func() {
			pairing := PairingCtx(useHash, dst)
			var tempRand Scalar
			var tempPk P1Affine
			var tempSig P2Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}

				curSig, curPk, curRand, aug := paramsFn(work, &tempSig,
					&tempPk, &tempRand)

				if PairingMulNAggregatePkInG1(pairing, curPk, pksVerify,
					curSig, sigsGroupcheck, curRand,
					randBits, msgs[work], aug) !=
					C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// application might have some async work to do
				runtime.Gosched()
			}
			if atomic.LoadInt32(&valid) > 0 {
				PairingCommit(pairing)
				msgsCh <- pairing
			} else {
				msgsCh <- nil
			}
		}()
	}

	// Accumulate the thread results
	var pairings Pairing
	for i := 0; i < numThreads; i++ {
		msg := <-msgsCh
		if msg != nil {
			if pairings == nil {
				pairings = msg
			} else {
				ret := PairingMerge(pairings, msg)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
				}
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 || pairings == nil {
		return false
	}

	return PairingFinalVerify(pairings, nil)
}

//
// Aggregate P2
//

type aggGetterP2 func(i uint32, temp *P2Affine) *P2Affine
type P2Aggregate struct {
	v *P2
}

// Aggregate uncompressed elements
func (agg *P2Aggregate) Aggregate(elmts []*P2Affine,
	groupcheck bool) bool {
	if len(elmts) == 0 {
		return true
	}
	getter := func(i uint32, _ *P2Affine) *P2Affine { return elmts[i] }
	return agg.coreAggregate(getter, groupcheck, len(elmts))
}

func (agg *P2Aggregate) AggregateWithRandomness(pointsIf interface{},
	scalarsIf interface{}, nbits int, groupcheck bool) bool {
	if groupcheck && !P2AffinesValidate(pointsIf) {
		return false
	}
	agg.v = P2AffinesMult(pointsIf, scalarsIf, nbits)
	return true
}

// Aggregate compressed elements
func (agg *P2Aggregate) AggregateCompressed(elmts [][]byte,
	groupcheck bool) bool {
	if len(elmts) == 0 {
		return true
	}
	getter := func(i uint32, p *P2Affine) *P2Affine {
		bytes := elmts[i]
		if p.Uncompress(bytes) == nil {
			return nil
		}
		return p
	}
	return agg.coreAggregate(getter, groupcheck, len(elmts))
}

func (agg *P2Aggregate) AddAggregate(other *P2Aggregate) {
	if other.v == nil {
		// do nothing
	} else if agg.v == nil {
		agg.v = other.v
	} else {
		C.blst_p2_add_or_double(agg.v, agg.v, other.v)
	}
}

func (agg *P2Aggregate) Add(elmt *P2Affine, groupcheck bool) bool {
	if groupcheck && !bool(C.blst_p2_affine_in_g2(elmt)) {
		return false
	}
	if agg.v == nil {
		agg.v = new(P2)
		C.blst_p2_from_affine(agg.v, elmt)
	} else {
		C.blst_p2_add_or_double_affine(agg.v, agg.v, elmt)
	}
	return true
}

func (agg *P2Aggregate) ToAffine() *P2Affine {
	if agg.v == nil {
		return new(P2Affine)
	}
	return agg.v.ToAffine()
}

func (agg *P2Aggregate) coreAggregate(getter aggGetterP2, groupcheck bool,
	n int) bool {

	if n == 0 {
		return true
	}
	// operations are considered short enough for not to care about
	// keeping one core free...
	numThreads := runtime.GOMAXPROCS(0)
	if numThreads > n {
		numThreads = n
	}

	valid := int32(1)
	type result struct {
		agg   *P2
		empty bool
	}
	msgs := make(chan result, numThreads)
	curItem := uint32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			first := true
			var agg P2
			var temp P2Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}

				// Signature validate
				curElmt := getter(work, &temp)
				if curElmt == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}
				if groupcheck && !bool(C.blst_p2_affine_in_g2(curElmt)) {
					atomic.StoreInt32(&valid, 0)
					break
				}
				if first {
					C.blst_p2_from_affine(&agg, curElmt)
					first = false
				} else {
					C.blst_p2_add_or_double_affine(&agg, &agg, curElmt)
				}
				// application might have some async work to do
				runtime.Gosched()
			}
			if first {
				msgs <- result{nil, true}
			} else if atomic.LoadInt32(&valid) > 0 {
				msgs <- result{&agg, false}
			} else {
				msgs <- result{nil, false}
			}
		}()
	}

	// Accumulate the thread results
	first := agg.v == nil
	validLocal := true
	for i := 0; i < numThreads; i++ {
		msg := <-msgs
		if !validLocal || msg.empty {
			// do nothing
		} else if msg.agg == nil {
			validLocal = false
			// This should be unnecessary but seems safer
			atomic.StoreInt32(&valid, 0)
		} else {
			if first {
				agg.v = msg.agg
				first = false
			} else {
				C.blst_p2_add_or_double(agg.v, agg.v, msg.agg)
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 {
		agg.v = nil
		return false
	}
	return true
}

//
// MIN-SIG
//

//
// PublicKey
//

func (pk *P2Affine) From(s *Scalar) *P2Affine {
	C.blst_sk_to_pk2_in_g2(nil, pk, s)
	return pk
}

func (pk *P2Affine) KeyValidate() bool {
	return bool(C.go_p2_affine_validate(pk, true))
}

// sigInfcheck, check for infinity, is a way to avoid going
// into resource-consuming verification. Passing 'false' is
// always cryptographically safe, but application might want
// to guard against obviously bogus individual[!] signatures.
func (sig *P1Affine) SigValidate(sigInfcheck bool) bool {
	return bool(C.go_p1_affine_validate(sig, C.bool(sigInfcheck)))
}

//
// Sign
//

func (sig *P1Affine) Sign(sk *SecretKey, msg []byte, dst []byte,
	optional ...interface{}) *P1Affine {
	augSingle, aug, useHash, ok := parseOpts(optional...)
	if !ok || len(aug) != 0 {
		return nil
	}

	var q *P1
	if useHash {
		q = HashToG1(msg, dst, augSingle)
	} else {
		q = EncodeToG1(msg, dst, augSingle)
	}
	C.blst_sign_pk2_in_g2(nil, sig, q, sk)
	return sig
}

//
// Signature
//

// Functions to return a signature and public key+augmentation tuple.
// This enables point decompression (if needed) to happen in parallel.
type sigGetterP1 func() *P1Affine
type pkGetterP2 func(i uint32, temp *P2Affine) (*P2Affine, []byte)

// Single verify with decompressed pk
func (sig *P1Affine) Verify(sigGroupcheck bool, pk *P2Affine, pkValidate bool,
	msg Message, dst []byte,
	optional ...interface{}) bool { // useHash bool, aug []byte

	aug, _, useHash, ok := parseOpts(optional...)
	if !ok {
		return false
	}
	return sig.AggregateVerify(sigGroupcheck, []*P2Affine{pk}, pkValidate,
		[]Message{msg}, dst, useHash, [][]byte{aug})
}

// Single verify with compressed pk
// Uses a dummy signature to get the correct type
func (dummy *P1Affine) VerifyCompressed(sig []byte, sigGroupcheck bool,
	pk []byte, pkValidate bool, msg Message, dst []byte,
	optional ...bool) bool { // useHash bool, usePksAsAugs bool

	return dummy.AggregateVerifyCompressed(sig, sigGroupcheck,
		[][]byte{pk}, pkValidate,
		[]Message{msg}, dst, optional...)
}

// Aggregate verify with uncompressed signature and public keys
// Note that checking message uniqueness, if required, is left to the user.
// Not all signature schemes require it and this keeps the binding minimal
// and fast. Refer to the Uniq function for one method method of performing
// this check.
func (sig *P1Affine) AggregateVerify(sigGroupcheck bool,
	pks []*P2Affine, pksVerify bool, msgs []Message, dst []byte,
	optional ...interface{}) bool { // useHash bool, augs [][]byte

	// sanity checks and argument parsing
	n := len(pks)
	if n == 0 || len(msgs) != n {
		return false
	}
	_, augs, useHash, ok := parseOpts(optional...)
	useAugs := len(augs) != 0
	if !ok || (useAugs && len(augs) != n) {
		return false
	}

	sigFn := func() *P1Affine {
		return sig
	}

	pkFn := func(i uint32, _ *P2Affine) (*P2Affine, []byte) {
		if useAugs {
			return pks[i], augs[i]
		}
		return pks[i], nil
	}

	return coreAggregateVerifyPkInG2(sigFn, sigGroupcheck, pkFn, pksVerify,
		msgs, dst, useHash)
}

// Aggregate verify with compressed signature and public keys
// Uses a dummy signature to get the correct type
func (_ *P1Affine) AggregateVerifyCompressed(sig []byte, sigGroupcheck bool,
	pks [][]byte, pksVerify bool, msgs []Message, dst []byte,
	optional ...bool) bool { // useHash bool, usePksAsAugs bool

	// sanity checks and argument parsing
	if len(pks) != len(msgs) {
		return false
	}
	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}
	usePksAsAugs := false
	if len(optional) > 1 {
		usePksAsAugs = optional[1]
	}

	sigFn := func() *P1Affine {
		sigP := new(P1Affine)
		if sigP.Uncompress(sig) == nil {
			return nil
		}
		return sigP
	}
	pkFn := func(i uint32, pk *P2Affine) (*P2Affine, []byte) {
		bytes := pks[i]
		if len(bytes) == BLST_P2_SERIALIZE_BYTES && (bytes[0]&0x80) == 0 {
			// Not compressed
			if pk.Deserialize(bytes) == nil {
				return nil, nil
			}
		} else if len(bytes) == BLST_P2_COMPRESS_BYTES && (bytes[0]&0x80) != 0 {
			if pk.Uncompress(bytes) == nil {
				return nil, nil
			}
		} else {
			return nil, nil
		}
		if usePksAsAugs {
			return pk, bytes
		}
		return pk, nil
	}
	return coreAggregateVerifyPkInG2(sigFn, sigGroupcheck, pkFn, pksVerify,
		msgs, dst, useHash)
}

func coreAggregateVerifyPkInG2(sigFn sigGetterP1, sigGroupcheck bool,
	pkFn pkGetterP2, pkValidate bool, msgs []Message, dst []byte,
	optional ...bool) bool { // useHash

	n := len(msgs)
	if n == 0 {
		return false
	}

	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}

	numCores := runtime.GOMAXPROCS(0)
	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding pk,msg[,aug] tuple and
	// repeat until n is exceeded.  The resulting accumulations will be
	// fed into the msgsCh channel.
	msgsCh := make(chan Pairing, numThreads)
	valid := int32(1)
	curItem := uint32(0)
	mutex := sync.Mutex{}

	mutex.Lock()
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			pairing := PairingCtx(useHash, dst)
			var temp P2Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				} else if work == 0 && maxProcs == numCores-1 &&
					numThreads == maxProcs {
					// Avoid consuming all cores by waiting until the
					// main thread has completed its miller loop before
					// proceeding.
					mutex.Lock()
					mutex.Unlock() //nolint:staticcheck
				}

				// Pull Public Key and augmentation blob
				curPk, aug := pkFn(work, &temp)
				if curPk == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// Pairing and accumulate
				ret := PairingAggregatePkInG2(pairing, curPk, pkValidate,
					nil, false, msgs[work], aug)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// application might have some async work to do
				runtime.Gosched()
			}
			if atomic.LoadInt32(&valid) > 0 {
				PairingCommit(pairing)
				msgsCh <- pairing
			} else {
				msgsCh <- nil
			}
		}()
	}

	// Uncompress and check signature
	var gtsig Fp12
	sig := sigFn()
	if sig == nil {
		atomic.StoreInt32(&valid, 0)
	}
	if atomic.LoadInt32(&valid) > 0 && sigGroupcheck &&
		!sig.SigValidate(false) {
		atomic.StoreInt32(&valid, 0)
	}
	if atomic.LoadInt32(&valid) > 0 {
		C.blst_aggregated_in_g1(&gtsig, sig)
	}
	mutex.Unlock()

	// Accumulate the thread results
	var pairings Pairing
	for i := 0; i < numThreads; i++ {
		msg := <-msgsCh
		if msg != nil {
			if pairings == nil {
				pairings = msg
			} else {
				ret := PairingMerge(pairings, msg)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
				}
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 || pairings == nil {
		return false
	}

	return PairingFinalVerify(pairings, &gtsig)
}

func CoreVerifyPkInG2(pk *P2Affine, sig *P1Affine, hash_or_encode bool,
	msg Message, dst []byte, optional ...[]byte) int {

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	if runtime.NumGoroutine() < maxProcs {
		sigFn := func() *P1Affine {
			return sig
		}
		pkFn := func(_ uint32, _ *P2Affine) (*P2Affine, []byte) {
			return pk, aug
		}
		if !coreAggregateVerifyPkInG2(sigFn, true, pkFn, true, []Message{msg},
			dst, hash_or_encode) {
			return C.BLST_VERIFY_FAIL
		}
		return C.BLST_SUCCESS
	}

	return int(C.blst_core_verify_pk_in_g2(pk, sig, C.bool(hash_or_encode),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug))))
}

// pks are assumed to be verified for proof of possession,
// which implies that they are already group-checked
func (sig *P1Affine) FastAggregateVerify(sigGroupcheck bool,
	pks []*P2Affine, msg Message, dst []byte,
	optional ...interface{}) bool { // pass-through to Verify
	n := len(pks)

	// TODO: return value for length zero?
	if n == 0 {
		return false
	}

	aggregator := new(P2Aggregate)
	if !aggregator.Aggregate(pks, false) {
		return false
	}
	pkAff := aggregator.ToAffine()

	// Verify
	return sig.Verify(sigGroupcheck, pkAff, false, msg, dst, optional...)
}

func (_ *P1Affine) MultipleAggregateVerify(sigs []*P1Affine,
	sigsGroupcheck bool, pks []*P2Affine, pksVerify bool,
	msgs []Message, dst []byte, randFn func(*Scalar), randBits int,
	optional ...interface{}) bool { // useHash

	// Sanity checks and argument parsing
	n := len(pks)
	if n == 0 || len(msgs) != n || len(sigs) != n {
		return false
	}
	_, augs, useHash, ok := parseOpts(optional...)
	useAugs := len(augs) != 0
	if !ok || (useAugs && len(augs) != n) {
		return false
	}

	paramsFn :=
		func(work uint32, _ *P1Affine, _ *P2Affine, rand *Scalar) (
			*P1Affine, *P2Affine, *Scalar, []byte) {
			randFn(rand)
			var aug []byte
			if useAugs {
				aug = augs[work]
			}
			return sigs[work], pks[work], rand, aug
		}

	return multipleAggregateVerifyPkInG2(paramsFn, sigsGroupcheck, pksVerify,
		msgs, dst, randBits, useHash)
}

type mulAggGetterPkInG2 func(work uint32, sig *P1Affine, pk *P2Affine,
	rand *Scalar) (*P1Affine, *P2Affine, *Scalar, []byte)

func multipleAggregateVerifyPkInG2(paramsFn mulAggGetterPkInG2,
	sigsGroupcheck bool, pksVerify bool, msgs []Message,
	dst []byte, randBits int,
	optional ...bool) bool { // useHash
	n := len(msgs)
	if n == 0 {
		return false
	}

	useHash := true
	if len(optional) > 0 {
		useHash = optional[0]
	}

	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding pk,msg[,aug] tuple and
	// repeat until n is exceeded.  The resulting accumulations will be
	// fed into the msgsCh channel.
	msgsCh := make(chan Pairing, numThreads)
	valid := int32(1)
	curItem := uint32(0)

	for tid := 0; tid < numThreads; tid++ {
		go func() {
			pairing := PairingCtx(useHash, dst)
			var tempRand Scalar
			var tempPk P2Affine
			var tempSig P1Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}

				curSig, curPk, curRand, aug := paramsFn(work, &tempSig,
					&tempPk, &tempRand)

				if PairingMulNAggregatePkInG2(pairing, curPk, pksVerify,
					curSig, sigsGroupcheck, curRand,
					randBits, msgs[work], aug) !=
					C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
					break
				}

				// application might have some async work to do
				runtime.Gosched()
			}
			if atomic.LoadInt32(&valid) > 0 {
				PairingCommit(pairing)
				msgsCh <- pairing
			} else {
				msgsCh <- nil
			}
		}()
	}

	// Accumulate the thread results
	var pairings Pairing
	for i := 0; i < numThreads; i++ {
		msg := <-msgsCh
		if msg != nil {
			if pairings == nil {
				pairings = msg
			} else {
				ret := PairingMerge(pairings, msg)
				if ret != C.BLST_SUCCESS {
					atomic.StoreInt32(&valid, 0)
				}
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 || pairings == nil {
		return false
	}

	return PairingFinalVerify(pairings, nil)
}

//
// Aggregate P1
//

type aggGetterP1 func(i uint32, temp *P1Affine) *P1Affine
type P1Aggregate struct {
	v *P1
}

// Aggregate uncompressed elements
func (agg *P1Aggregate) Aggregate(elmts []*P1Affine,
	groupcheck bool) bool {
	if len(elmts) == 0 {
		return true
	}
	getter := func(i uint32, _ *P1Affine) *P1Affine { return elmts[i] }
	return agg.coreAggregate(getter, groupcheck, len(elmts))
}

func (agg *P1Aggregate) AggregateWithRandomness(pointsIf interface{},
	scalarsIf interface{}, nbits int, groupcheck bool) bool {
	if groupcheck && !P1AffinesValidate(pointsIf) {
		return false
	}
	agg.v = P1AffinesMult(pointsIf, scalarsIf, nbits)
	return true
}

// Aggregate compressed elements
func (agg *P1Aggregate) AggregateCompressed(elmts [][]byte,
	groupcheck bool) bool {
	if len(elmts) == 0 {
		return true
	}
	getter := func(i uint32, p *P1Affine) *P1Affine {
		bytes := elmts[i]
		if p.Uncompress(bytes) == nil {
			return nil
		}
		return p
	}
	return agg.coreAggregate(getter, groupcheck, len(elmts))
}

func (agg *P1Aggregate) AddAggregate(other *P1Aggregate) {
	if other.v == nil {
		// do nothing
	} else if agg.v == nil {
		agg.v = other.v
	} else {
		C.blst_p1_add_or_double(agg.v, agg.v, other.v)
	}
}

func (agg *P1Aggregate) Add(elmt *P1Affine, groupcheck bool) bool {
	if groupcheck && !bool(C.blst_p1_affine_in_g1(elmt)) {
		return false
	}
	if agg.v == nil {
		agg.v = new(P1)
		C.blst_p1_from_affine(agg.v, elmt)
	} else {
		C.blst_p1_add_or_double_affine(agg.v, agg.v, elmt)
	}
	return true
}

func (agg *P1Aggregate) ToAffine() *P1Affine {
	if agg.v == nil {
		return new(P1Affine)
	}
	return agg.v.ToAffine()
}

func (agg *P1Aggregate) coreAggregate(getter aggGetterP1, groupcheck bool,
	n int) bool {

	if n == 0 {
		return true
	}
	// operations are considered short enough for not to care about
	// keeping one core free...
	numThreads := runtime.GOMAXPROCS(0)
	if numThreads > n {
		numThreads = n
	}

	valid := int32(1)
	type result struct {
		agg   *P1
		empty bool
	}
	msgs := make(chan result, numThreads)
	curItem := uint32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			first := true
			var agg P1
			var temp P1Affine
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}

				// Signature validate
				curElmt := getter(work, &temp)
				if curElmt == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}
				if groupcheck && !bool(C.blst_p1_affine_in_g1(curElmt)) {
					atomic.StoreInt32(&valid, 0)
					break
				}
				if first {
					C.blst_p1_from_affine(&agg, curElmt)
					first = false
				} else {
					C.blst_p1_add_or_double_affine(&agg, &agg, curElmt)
				}
				// application might have some async work to do
				runtime.Gosched()
			}
			if first {
				msgs <- result{nil, true}
			} else if atomic.LoadInt32(&valid) > 0 {
				msgs <- result{&agg, false}
			} else {
				msgs <- result{nil, false}
			}
		}()
	}

	// Accumulate the thread results
	first := agg.v == nil
	validLocal := true
	for i := 0; i < numThreads; i++ {
		msg := <-msgs
		if !validLocal || msg.empty {
			// do nothing
		} else if msg.agg == nil {
			validLocal = false
			// This should be unnecessary but seems safer
			atomic.StoreInt32(&valid, 0)
		} else {
			if first {
				agg.v = msg.agg
				first = false
			} else {
				C.blst_p1_add_or_double(agg.v, agg.v, msg.agg)
			}
		}
	}
	if atomic.LoadInt32(&valid) == 0 {
		agg.v = nil
		return false
	}
	return true
}
func PairingAggregatePkInG1(ctx Pairing, PK *P1Affine, pkValidate bool,
	sig *P2Affine, sigGroupcheck bool, msg []byte,
	optional ...[]byte) int { // aug
	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	r := C.blst_pairing_chk_n_aggr_pk_in_g1(&ctx[0],
		PK, C.bool(pkValidate),
		sig, C.bool(sigGroupcheck),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(aug), C.size_t(len(aug)))

	return int(r)
}

func PairingMulNAggregatePkInG1(ctx Pairing, PK *P1Affine, pkValidate bool,
	sig *P2Affine, sigGroupcheck bool,
	rand *Scalar, randBits int, msg []byte,
	optional ...[]byte) int { // aug
	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	r := C.blst_pairing_chk_n_mul_n_aggr_pk_in_g1(&ctx[0],
		PK, C.bool(pkValidate),
		sig, C.bool(sigGroupcheck),
		&rand.b[0], C.size_t(randBits),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(aug), C.size_t(len(aug)))

	return int(r)
}

//
// Serialization/Deserialization.
//

// P1 Serdes
func (p1 *P1Affine) Serialize() []byte {
	var out [BLST_P1_SERIALIZE_BYTES]byte
	C.blst_p1_affine_serialize((*C.byte)(&out[0]), p1)
	return out[:]
}

func (p1 *P1Affine) Deserialize(in []byte) *P1Affine {
	if len(in) != BLST_P1_SERIALIZE_BYTES {
		return nil
	}
	if C.blst_p1_deserialize(p1, (*C.byte)(&in[0])) != C.BLST_SUCCESS {
		return nil
	}
	return p1
}
func (p1 *P1Affine) Compress() []byte {
	var out [BLST_P1_COMPRESS_BYTES]byte
	C.blst_p1_affine_compress((*C.byte)(&out[0]), p1)
	return out[:]
}

func (p1 *P1Affine) Uncompress(in []byte) *P1Affine {
	if len(in) != BLST_P1_COMPRESS_BYTES {
		return nil
	}
	if C.blst_p1_uncompress(p1, (*C.byte)(&in[0])) != C.BLST_SUCCESS {
		return nil
	}
	return p1
}

func (p1 *P1Affine) InG1() bool {
	return bool(C.blst_p1_affine_in_g1(p1))
}

func (_ *P1Affine) BatchUncompress(in [][]byte) []*P1Affine {
	// Allocate space for all of the resulting points. Later we'll save pointers
	// and return those so that the result could be used in other functions,
	// such as MultipleAggregateVerify.
	n := len(in)
	points := make([]P1Affine, n)
	pointsPtrs := make([]*P1Affine, n)

	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding point, and
	// repeat until n is exceeded. Each thread will send a result (true for
	// success, false for failure) into the channel when complete.
	resCh := make(chan bool, numThreads)
	valid := int32(1)
	curItem := uint32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}
				if points[work].Uncompress(in[work]) == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}
				pointsPtrs[work] = &points[work]
			}
			if atomic.LoadInt32(&valid) > 0 {
				resCh <- true
			} else {
				resCh <- false
			}
		}()
	}

	// Collect the threads
	result := true
	for i := 0; i < numThreads; i++ {
		if !<-resCh {
			result = false
		}
	}
	if atomic.LoadInt32(&valid) == 0 || !result {
		return nil
	}
	return pointsPtrs
}

func (p1 *P1) Serialize() []byte {
	var out [BLST_P1_SERIALIZE_BYTES]byte
	C.blst_p1_serialize((*C.byte)(&out[0]), p1)
	return out[:]
}
func (p1 *P1) Compress() []byte {
	var out [BLST_P1_COMPRESS_BYTES]byte
	C.blst_p1_compress((*C.byte)(&out[0]), p1)
	return out[:]
}

func (p1 *P1) MultAssign(scalarIf interface{}, optional ...int) *P1 {
	var nbits int
	var scalar *C.byte
	switch val := scalarIf.(type) {
	case []byte:
		scalar = (*C.byte)(&val[0])
		nbits = len(val) * 8
	case *Scalar:
		scalar = &val.b[0]
		nbits = 255
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	if len(optional) > 0 {
		nbits = optional[0]
	}
	C.blst_p1_mult(p1, p1, scalar, C.size_t(nbits))
	return p1
}

func (p1 *P1) Mult(scalarIf interface{}, optional ...int) *P1 {
	ret := *p1
	return ret.MultAssign(scalarIf, optional...)
}

func (p1 *P1) AddAssign(pointIf interface{}) *P1 {
	switch val := pointIf.(type) {
	case *P1:
		C.blst_p1_add_or_double(p1, p1, val)
	case *P1Affine:
		C.blst_p1_add_or_double_affine(p1, p1, val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	return p1
}

func (p1 *P1) Add(pointIf interface{}) *P1 {
	ret := *p1
	return ret.AddAssign(pointIf)
}

func (p1 *P1) SubAssign(pointIf interface{}) *P1 {
	var x *Fp
	var affine C.bool
	switch val := pointIf.(type) {
	case *P1:
		x = &val.x
		affine = false
	case *P1Affine:
		x = &val.x
		affine = true
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	C.go_p1_sub_assign(p1, x, affine)
	return p1
}

func (p1 *P1) Sub(pointIf interface{}) *P1 {
	ret := *p1
	return ret.SubAssign(pointIf)
}

func P1Generator() *P1 {
	return &cgo_p1Generator
}

// 'acc += point * scalar', passing 'nil' for 'point' means "use the
//
//	group generator point"
func (acc *P1) MultNAccumulate(pointIf interface{}, scalarIf interface{},
	optional ...int) *P1 {
	var x *Fp
	var affine C.bool
	if pointIf != nil {
		switch val := pointIf.(type) {
		case *P1:
			x = &val.x
			affine = false
		case *P1Affine:
			x = &val.x
			affine = true
		default:
			panic(fmt.Sprintf("unsupported type %T", val))
		}
	}
	var nbits int
	var scalar *C.byte
	switch val := scalarIf.(type) {
	case []byte:
		scalar = (*C.byte)(&val[0])
		nbits = len(val) * 8
	case *Scalar:
		scalar = &val.b[0]
		nbits = 255
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	if len(optional) > 0 {
		nbits = optional[0]
	}
	C.go_p1_mult_n_acc(acc, x, affine, scalar, C.size_t(nbits))
	return acc
}

//
// Affine
//

func (p *P1) ToAffine() *P1Affine {
	var pa P1Affine
	C.blst_p1_to_affine(&pa, p)
	return &pa
}

func (p *P1) FromAffine(pa *P1Affine) {
	C.blst_p1_from_affine(p, pa)
}

// Hash
func HashToG1(msg []byte, dst []byte,
	optional ...[]byte) *P1 { // aug
	var q P1

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	C.blst_hash_to_g1(&q, ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug)))
	return &q
}

func EncodeToG1(msg []byte, dst []byte,
	optional ...[]byte) *P1 { // aug
	var q P1

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	C.blst_encode_to_g1(&q, ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug)))
	return &q
}

//
// Multi-point/scalar operations
//

func P1sToAffine(points []*P1, optional ...int) P1Affines {
	var npoints int
	if len(optional) > 0 {
		npoints = optional[0]
	} else {
		npoints = len(points)
	}
	ret := make([]P1Affine, npoints)
	_cgoCheckPointer := func(...interface{}) {}
	C.blst_p1s_to_affine(&ret[0], &points[0], C.size_t(npoints))
	return ret
}

func (points P1s) ToAffine(optional ...P1Affines) P1Affines {
	npoints := len(points)
	var ret P1Affines

	if len(optional) > 0 { // used in benchmark
		ret = optional[0]
		if len(ret) < npoints {
			panic("npoints mismatch")
		}
	} else {
		ret = make([]P1Affine, npoints)
	}

	if maxProcs < 2 || npoints < 768 {
		C.go_p1slice_to_affine(&ret[0], &points[0], C.size_t(npoints))
		return ret
	}

	nslices := (npoints + 511) / 512
	if nslices > maxProcs {
		nslices = maxProcs
	}
	delta, rem := npoints/nslices+1, npoints%nslices

	var wg sync.WaitGroup
	wg.Add(nslices)
	for x := 0; x < npoints; x += delta {
		if rem == 0 {
			delta -= 1
		}
		rem -= 1
		go func(out *P1Affine, inp *P1, delta int) {
			C.go_p1slice_to_affine(out, inp, C.size_t(delta))
			wg.Done()
		}(&ret[x], &points[x], delta)
	}
	wg.Wait()

	return ret
}

//
// Batch addition
//

func P1AffinesAdd(points []*P1Affine, optional ...int) *P1 {
	var npoints int
	if len(optional) > 0 {
		npoints = optional[0]
	} else {
		npoints = len(points)
	}
	var ret P1
	_cgoCheckPointer := func(...interface{}) {}
	C.blst_p1s_add(&ret, &points[0], C.size_t(npoints))
	return &ret
}

func (points P1Affines) Add() *P1 {
	npoints := len(points)
	if maxProcs < 2 || npoints < 768 {
		var ret P1
		C.go_p1slice_add(&ret, &points[0], C.size_t(npoints))
		return &ret
	}

	nslices := (npoints + 511) / 512
	if nslices > maxProcs {
		nslices = maxProcs
	}
	delta, rem := npoints/nslices+1, npoints%nslices

	msgs := make(chan P1, nslices)
	for x := 0; x < npoints; x += delta {
		if rem == 0 {
			delta -= 1
		}
		rem -= 1
		go func(points *P1Affine, delta int) {
			var ret P1
			C.go_p1slice_add(&ret, points, C.size_t(delta))
			msgs <- ret
		}(&points[x], delta)
	}

	ret := <-msgs
	for i := 1; i < nslices; i++ {
		msg := <-msgs
		C.blst_p1_add_or_double(&ret, &ret, &msg)
	}
	return &ret
}

func (points P1s) Add() *P1 {
	return points.ToAffine().Add()
}

//
// Multi-scalar multiplication
//

func P1AffinesMult(pointsIf interface{}, scalarsIf interface{}, nbits int) *P1 {
	var npoints int
	switch val := pointsIf.(type) {
	case []*P1Affine:
		npoints = len(val)
	case []P1Affine:
		npoints = len(val)
	case P1Affines:
		npoints = len(val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	nbytes := (nbits + 7) / 8
	var scalars []*C.byte
	switch val := scalarsIf.(type) {
	case []byte:
		if len(val) < npoints*nbytes {
			return nil
		}
	case [][]byte:
		if len(val) < npoints {
			return nil
		}
		scalars = make([]*C.byte, npoints)
		for i := range scalars {
			scalars[i] = (*C.byte)(&val[i][0])
		}
	case []Scalar:
		if len(val) < npoints {
			return nil
		}
		if nbits <= 248 {
			scalars = make([]*C.byte, npoints)
			for i := range scalars {
				scalars[i] = &val[i].b[0]
			}
		}
	case []*Scalar:
		if len(val) < npoints {
			return nil
		}
		scalars = make([]*C.byte, npoints)
		for i := range scalars {
			scalars[i] = &val[i].b[0]
		}
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	numThreads := numThreads(0)

	if numThreads < 2 {
		sz := int(C.blst_p1s_mult_pippenger_scratch_sizeof(C.size_t(npoints))) / 8
		scratch := make([]uint64, sz)

		pointsBySlice := [2]*P1Affine{nil, nil}
		var p_points **P1Affine
		switch val := pointsIf.(type) {
		case []*P1Affine:
			p_points = &val[0]
		case []P1Affine:
			pointsBySlice[0] = &val[0]
			p_points = &pointsBySlice[0]
		case P1Affines:
			pointsBySlice[0] = &val[0]
			p_points = &pointsBySlice[0]
		}

		scalarsBySlice := [2]*C.byte{nil, nil}
		var p_scalars **C.byte
		switch val := scalarsIf.(type) {
		case []byte:
			scalarsBySlice[0] = (*C.byte)(&val[0])
			p_scalars = &scalarsBySlice[0]
		case [][]byte:
			p_scalars = &scalars[0]
		case []Scalar:
			if nbits > 248 {
				scalarsBySlice[0] = &val[0].b[0]
				p_scalars = &scalarsBySlice[0]
			} else {
				p_scalars = &scalars[0]
			}
		case []*Scalar:
			p_scalars = &scalars[0]
		}

		var ret P1
		_cgoCheckPointer := func(...interface{}) {}
		C.blst_p1s_mult_pippenger(&ret, p_points, C.size_t(npoints),
			p_scalars, C.size_t(nbits),
			(*C.limb_t)(&scratch[0]))

		for i := range scalars {
			scalars[i] = nil
		}

		return &ret
	}

	if npoints < 32 {
		if numThreads > npoints {
			numThreads = npoints
		}

		curItem := uint32(0)
		msgs := make(chan P1, numThreads)

		for tid := 0; tid < numThreads; tid++ {
			go func() {
				var acc P1

				for {
					workItem := int(atomic.AddUint32(&curItem, 1) - 1)
					if workItem >= npoints {
						break
					}

					var point *P1Affine
					switch val := pointsIf.(type) {
					case []*P1Affine:
						point = val[workItem]
					case []P1Affine:
						point = &val[workItem]
					case P1Affines:
						point = &val[workItem]
					}

					var scalar *C.byte
					switch val := scalarsIf.(type) {
					case []byte:
						scalar = (*C.byte)(&val[workItem*nbytes])
					case [][]byte:
						scalar = scalars[workItem]
					case []Scalar:
						if nbits > 248 {
							scalar = &val[workItem].b[0]
						} else {
							scalar = scalars[workItem]
						}
					case []*Scalar:
						scalar = scalars[workItem]
					}

					C.go_p1_mult_n_acc(&acc, &point.x, true,
						scalar, C.size_t(nbits))
				}

				msgs <- acc
			}()
		}

		ret := <-msgs
		for tid := 1; tid < numThreads; tid++ {
			point := <-msgs
			C.blst_p1_add_or_double(&ret, &ret, &point)
		}

		for i := range scalars {
			scalars[i] = nil
		}

		return &ret
	}

	// this is sizeof(scratch[0])
	sz := int(C.blst_p1s_mult_pippenger_scratch_sizeof(0)) / 8

	nx, ny, window := breakdown(nbits, pippenger_window_size(npoints),
		numThreads)

	// |grid[]| holds "coordinates" and place for result
	grid := make([]struct {
		x, dx, y, dy int
		point        P1
	}, nx*ny)

	dx := npoints / nx
	y := window * (ny - 1)
	total := 0
	for ; total < nx; total++ {
		grid[total].x = total * dx
		grid[total].dx = dx
		grid[total].y = y
		grid[total].dy = nbits - y
	}
	grid[total-1].dx = npoints - grid[total-1].x

	for y > 0 {
		y -= window
		for i := 0; i < nx; i++ {
			grid[total].x = grid[i].x
			grid[total].dx = grid[i].dx
			grid[total].y = y
			grid[total].dy = window
			total++
		}
	}

	if numThreads > total {
		numThreads = total
	}

	msgsCh := make(chan int, ny)
	rowSync := make([]int32, ny) // count up to |nx|
	curItem := int32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			scratch := make([]uint64, sz<<uint(window-1))
			pointsBySlice := [2]*P1Affine{nil, nil}
			scalarsBySlice := [2]*C.byte{nil, nil}
			_cgoCheckPointer := func(...interface{}) {}

			for {
				workItem := atomic.AddInt32(&curItem, 1) - 1
				if int(workItem) >= total {
					break
				}

				x := grid[workItem].x
				y := grid[workItem].y

				var p_points **P1Affine
				switch val := pointsIf.(type) {
				case []*P1Affine:
					p_points = &val[x]
				case []P1Affine:
					pointsBySlice[0] = &val[x]
					p_points = &pointsBySlice[0]
				case P1Affines:
					pointsBySlice[0] = &val[x]
					p_points = &pointsBySlice[0]
				}

				var p_scalars **C.byte
				switch val := scalarsIf.(type) {
				case []byte:
					scalarsBySlice[0] = (*C.byte)(&val[x*nbytes])
					p_scalars = &scalarsBySlice[0]
				case [][]byte:
					p_scalars = &scalars[x]
				case []Scalar:
					if nbits > 248 {
						scalarsBySlice[0] = &val[x].b[0]
						p_scalars = &scalarsBySlice[0]
					} else {
						p_scalars = &scalars[x]
					}
				case []*Scalar:
					p_scalars = &scalars[x]
				}

				C.blst_p1s_tile_pippenger(&grid[workItem].point,
					p_points, C.size_t(grid[workItem].dx),
					p_scalars, C.size_t(nbits),
					(*C.limb_t)(&scratch[0]),
					C.size_t(y), C.size_t(window))

				if atomic.AddInt32(&rowSync[y/window], 1) == int32(nx) {
					msgsCh <- y // "row" is done
				} else {
					runtime.Gosched() // be nice to the application
				}
			}

			pointsBySlice[0] = nil
			scalarsBySlice[0] = nil
		}()
	}

	var ret P1
	rows := make([]bool, ny)
	row := 0                  // actually index in |grid[]|
	for i := 0; i < ny; i++ { // we expect |ny| messages, one per "row"
		y := <-msgsCh
		rows[y/window] = true  // mark the "row"
		for grid[row].y == y { // if it's current "row", process it
			for row < total && grid[row].y == y {
				C.blst_p1_add_or_double(&ret, &ret, &grid[row].point)
				row++
			}
			if y == 0 {
				break // one can as well 'return &ret' here
			}
			for j := 0; j < window; j++ {
				C.blst_p1_double(&ret, &ret)
			}
			y -= window
			if !rows[y/window] { // see if next "row" was marked already
				break
			}
		}
	}

	for i := range scalars {
		scalars[i] = nil
	}

	return &ret
}

func (points P1Affines) Mult(scalarsIf interface{}, nbits int) *P1 {
	return P1AffinesMult(points, scalarsIf, nbits)
}

func (points P1s) Mult(scalarsIf interface{}, nbits int) *P1 {
	return points.ToAffine().Mult(scalarsIf, nbits)
}

//
// Group-check
//

func P1AffinesValidate(pointsIf interface{}) bool {
	var npoints int
	switch val := pointsIf.(type) {
	case []*P1Affine:
		npoints = len(val)
	case []P1Affine:
		npoints = len(val)
	case P1Affines:
		npoints = len(val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	numThreads := numThreads(npoints)

	if numThreads < 2 {
		for i := 0; i < npoints; i++ {
			var point *P1Affine

			switch val := pointsIf.(type) {
			case []*P1Affine:
				point = val[i]
			case []P1Affine:
				point = &val[i]
			case P1Affines:
				point = &val[i]
			default:
				panic(fmt.Sprintf("unsupported type %T", val))
			}

			if !C.go_p1_affine_validate(point, true) {
				return false
			}
		}

		return true
	}

	valid := int32(1)
	curItem := uint32(0)

	var wg sync.WaitGroup
	wg.Add(numThreads)

	for tid := 0; tid < numThreads; tid++ {
		go func() {
			for atomic.LoadInt32(&valid) != 0 {
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(npoints) {
					break
				}

				var point *P1Affine

				switch val := pointsIf.(type) {
				case []*P1Affine:
					point = val[work]
				case []P1Affine:
					point = &val[work]
				case P1Affines:
					point = &val[work]
				default:
					panic(fmt.Sprintf("unsupported type %T", val))
				}

				if !C.go_p1_affine_validate(point, true) {
					atomic.StoreInt32(&valid, 0)
					break
				}
			}

			wg.Done()
		}()
	}

	wg.Wait()

	return atomic.LoadInt32(&valid) != 0
}

func (points P1Affines) Validate() bool {
	return P1AffinesValidate(points)
}
func PairingAggregatePkInG2(ctx Pairing, PK *P2Affine, pkValidate bool,
	sig *P1Affine, sigGroupcheck bool, msg []byte,
	optional ...[]byte) int { // aug
	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	r := C.blst_pairing_chk_n_aggr_pk_in_g2(&ctx[0],
		PK, C.bool(pkValidate),
		sig, C.bool(sigGroupcheck),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(aug), C.size_t(len(aug)))

	return int(r)
}

func PairingMulNAggregatePkInG2(ctx Pairing, PK *P2Affine, pkValidate bool,
	sig *P1Affine, sigGroupcheck bool,
	rand *Scalar, randBits int, msg []byte,
	optional ...[]byte) int { // aug
	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	r := C.blst_pairing_chk_n_mul_n_aggr_pk_in_g2(&ctx[0],
		PK, C.bool(pkValidate),
		sig, C.bool(sigGroupcheck),
		&rand.b[0], C.size_t(randBits),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(aug), C.size_t(len(aug)))

	return int(r)
}

//
// Serialization/Deserialization.
//

// P2 Serdes
func (p2 *P2Affine) Serialize() []byte {
	var out [BLST_P2_SERIALIZE_BYTES]byte
	C.blst_p2_affine_serialize((*C.byte)(&out[0]), p2)
	return out[:]
}

func (p2 *P2Affine) Deserialize(in []byte) *P2Affine {
	if len(in) != BLST_P2_SERIALIZE_BYTES {
		return nil
	}
	if C.blst_p2_deserialize(p2, (*C.byte)(&in[0])) != C.BLST_SUCCESS {
		return nil
	}
	return p2
}
func (p2 *P2Affine) Compress() []byte {
	var out [BLST_P2_COMPRESS_BYTES]byte
	C.blst_p2_affine_compress((*C.byte)(&out[0]), p2)
	return out[:]
}

func (p2 *P2Affine) Uncompress(in []byte) *P2Affine {
	if len(in) != BLST_P2_COMPRESS_BYTES {
		return nil
	}
	if C.blst_p2_uncompress(p2, (*C.byte)(&in[0])) != C.BLST_SUCCESS {
		return nil
	}
	return p2
}

func (p2 *P2Affine) InG2() bool {
	return bool(C.blst_p2_affine_in_g2(p2))
}

func (_ *P2Affine) BatchUncompress(in [][]byte) []*P2Affine {
	// Allocate space for all of the resulting points. Later we'll save pointers
	// and return those so that the result could be used in other functions,
	// such as MultipleAggregateVerify.
	n := len(in)
	points := make([]P2Affine, n)
	pointsPtrs := make([]*P2Affine, n)

	numThreads := numThreads(n)

	// Each thread will determine next message to process by atomically
	// incrementing curItem, process corresponding point, and
	// repeat until n is exceeded. Each thread will send a result (true for
	// success, false for failure) into the channel when complete.
	resCh := make(chan bool, numThreads)
	valid := int32(1)
	curItem := uint32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			for atomic.LoadInt32(&valid) > 0 {
				// Get a work item
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(n) {
					break
				}
				if points[work].Uncompress(in[work]) == nil {
					atomic.StoreInt32(&valid, 0)
					break
				}
				pointsPtrs[work] = &points[work]
			}
			if atomic.LoadInt32(&valid) > 0 {
				resCh <- true
			} else {
				resCh <- false
			}
		}()
	}

	// Collect the threads
	result := true
	for i := 0; i < numThreads; i++ {
		if !<-resCh {
			result = false
		}
	}
	if atomic.LoadInt32(&valid) == 0 || !result {
		return nil
	}
	return pointsPtrs
}

func (p2 *P2) Serialize() []byte {
	var out [BLST_P2_SERIALIZE_BYTES]byte
	C.blst_p2_serialize((*C.byte)(&out[0]), p2)
	return out[:]
}
func (p2 *P2) Compress() []byte {
	var out [BLST_P2_COMPRESS_BYTES]byte
	C.blst_p2_compress((*C.byte)(&out[0]), p2)
	return out[:]
}

func (p2 *P2) MultAssign(scalarIf interface{}, optional ...int) *P2 {
	var nbits int
	var scalar *C.byte
	switch val := scalarIf.(type) {
	case []byte:
		scalar = (*C.byte)(&val[0])
		nbits = len(val) * 8
	case *Scalar:
		scalar = &val.b[0]
		nbits = 255
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	if len(optional) > 0 {
		nbits = optional[0]
	}
	C.blst_p2_mult(p2, p2, scalar, C.size_t(nbits))
	return p2
}

func (p2 *P2) Mult(scalarIf interface{}, optional ...int) *P2 {
	ret := *p2
	return ret.MultAssign(scalarIf, optional...)
}

func (p2 *P2) AddAssign(pointIf interface{}) *P2 {
	switch val := pointIf.(type) {
	case *P2:
		C.blst_p2_add_or_double(p2, p2, val)
	case *P2Affine:
		C.blst_p2_add_or_double_affine(p2, p2, val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	return p2
}

func (p2 *P2) Add(pointIf interface{}) *P2 {
	ret := *p2
	return ret.AddAssign(pointIf)
}

func (p2 *P2) SubAssign(pointIf interface{}) *P2 {
	var x *Fp2
	var affine C.bool
	switch val := pointIf.(type) {
	case *P2:
		x = &val.x
		affine = false
	case *P2Affine:
		x = &val.x
		affine = true
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	C.go_p2_sub_assign(p2, x, affine)
	return p2
}

func (p2 *P2) Sub(pointIf interface{}) *P2 {
	ret := *p2
	return ret.SubAssign(pointIf)
}

func P2Generator() *P2 {
	return &cgo_p2Generator
}

// 'acc += point * scalar', passing 'nil' for 'point' means "use the
//
//	group generator point"
func (acc *P2) MultNAccumulate(pointIf interface{}, scalarIf interface{},
	optional ...int) *P2 {
	var x *Fp2
	var affine C.bool
	if pointIf != nil {
		switch val := pointIf.(type) {
		case *P2:
			x = &val.x
			affine = false
		case *P2Affine:
			x = &val.x
			affine = true
		default:
			panic(fmt.Sprintf("unsupported type %T", val))
		}
	}
	var nbits int
	var scalar *C.byte
	switch val := scalarIf.(type) {
	case []byte:
		scalar = (*C.byte)(&val[0])
		nbits = len(val) * 8
	case *Scalar:
		scalar = &val.b[0]
		nbits = 255
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}
	if len(optional) > 0 {
		nbits = optional[0]
	}
	C.go_p2_mult_n_acc(acc, x, affine, scalar, C.size_t(nbits))
	return acc
}

//
// Affine
//

func (p *P2) ToAffine() *P2Affine {
	var pa P2Affine
	C.blst_p2_to_affine(&pa, p)
	return &pa
}

func (p *P2) FromAffine(pa *P2Affine) {
	C.blst_p2_from_affine(p, pa)
}

// Hash
func HashToG2(msg []byte, dst []byte,
	optional ...[]byte) *P2 { // aug
	var q P2

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	C.blst_hash_to_g2(&q, ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug)))
	return &q
}

func EncodeToG2(msg []byte, dst []byte,
	optional ...[]byte) *P2 { // aug
	var q P2

	var aug []byte
	if len(optional) > 0 {
		aug = optional[0]
	}

	C.blst_encode_to_g2(&q, ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)),
		ptrOrNil(aug), C.size_t(len(aug)))
	return &q
}

//
// Multi-point/scalar operations
//

func P2sToAffine(points []*P2, optional ...int) P2Affines {
	var npoints int
	if len(optional) > 0 {
		npoints = optional[0]
	} else {
		npoints = len(points)
	}
	ret := make([]P2Affine, npoints)
	_cgoCheckPointer := func(...interface{}) {}
	C.blst_p2s_to_affine(&ret[0], &points[0], C.size_t(npoints))
	return ret
}

func (points P2s) ToAffine(optional ...P2Affines) P2Affines {
	npoints := len(points)
	var ret P2Affines

	if len(optional) > 0 { // used in benchmark
		ret = optional[0]
		if len(ret) < npoints {
			panic("npoints mismatch")
		}
	} else {
		ret = make([]P2Affine, npoints)
	}

	if maxProcs < 2 || npoints < 768 {
		C.go_p2slice_to_affine(&ret[0], &points[0], C.size_t(npoints))
		return ret
	}

	nslices := (npoints + 511) / 512
	if nslices > maxProcs {
		nslices = maxProcs
	}
	delta, rem := npoints/nslices+1, npoints%nslices

	var wg sync.WaitGroup
	wg.Add(nslices)
	for x := 0; x < npoints; x += delta {
		if rem == 0 {
			delta -= 1
		}
		rem -= 1
		go func(out *P2Affine, inp *P2, delta int) {
			C.go_p2slice_to_affine(out, inp, C.size_t(delta))
			wg.Done()
		}(&ret[x], &points[x], delta)
	}
	wg.Wait()

	return ret
}

//
// Batch addition
//

func P2AffinesAdd(points []*P2Affine, optional ...int) *P2 {
	var npoints int
	if len(optional) > 0 {
		npoints = optional[0]
	} else {
		npoints = len(points)
	}
	var ret P2
	_cgoCheckPointer := func(...interface{}) {}
	C.blst_p2s_add(&ret, &points[0], C.size_t(npoints))
	return &ret
}

func (points P2Affines) Add() *P2 {
	npoints := len(points)
	if maxProcs < 2 || npoints < 768 {
		var ret P2
		C.go_p2slice_add(&ret, &points[0], C.size_t(npoints))
		return &ret
	}

	nslices := (npoints + 511) / 512
	if nslices > maxProcs {
		nslices = maxProcs
	}
	delta, rem := npoints/nslices+1, npoints%nslices

	msgs := make(chan P2, nslices)
	for x := 0; x < npoints; x += delta {
		if rem == 0 {
			delta -= 1
		}
		rem -= 1
		go func(points *P2Affine, delta int) {
			var ret P2
			C.go_p2slice_add(&ret, points, C.size_t(delta))
			msgs <- ret
		}(&points[x], delta)
	}

	ret := <-msgs
	for i := 1; i < nslices; i++ {
		msg := <-msgs
		C.blst_p2_add_or_double(&ret, &ret, &msg)
	}
	return &ret
}

func (points P2s) Add() *P2 {
	return points.ToAffine().Add()
}

//
// Multi-scalar multiplication
//

func P2AffinesMult(pointsIf interface{}, scalarsIf interface{}, nbits int) *P2 {
	var npoints int
	switch val := pointsIf.(type) {
	case []*P2Affine:
		npoints = len(val)
	case []P2Affine:
		npoints = len(val)
	case P2Affines:
		npoints = len(val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	nbytes := (nbits + 7) / 8
	var scalars []*C.byte
	switch val := scalarsIf.(type) {
	case []byte:
		if len(val) < npoints*nbytes {
			return nil
		}
	case [][]byte:
		if len(val) < npoints {
			return nil
		}
		scalars = make([]*C.byte, npoints)
		for i := range scalars {
			scalars[i] = (*C.byte)(&val[i][0])
		}
	case []Scalar:
		if len(val) < npoints {
			return nil
		}
		if nbits <= 248 {
			scalars = make([]*C.byte, npoints)
			for i := range scalars {
				scalars[i] = &val[i].b[0]
			}
		}
	case []*Scalar:
		if len(val) < npoints {
			return nil
		}
		scalars = make([]*C.byte, npoints)
		for i := range scalars {
			scalars[i] = &val[i].b[0]
		}
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	numThreads := numThreads(0)

	if numThreads < 2 {
		sz := int(C.blst_p2s_mult_pippenger_scratch_sizeof(C.size_t(npoints))) / 8
		scratch := make([]uint64, sz)

		pointsBySlice := [2]*P2Affine{nil, nil}
		var p_points **P2Affine
		switch val := pointsIf.(type) {
		case []*P2Affine:
			p_points = &val[0]
		case []P2Affine:
			pointsBySlice[0] = &val[0]
			p_points = &pointsBySlice[0]
		case P2Affines:
			pointsBySlice[0] = &val[0]
			p_points = &pointsBySlice[0]
		}

		scalarsBySlice := [2]*C.byte{nil, nil}
		var p_scalars **C.byte
		switch val := scalarsIf.(type) {
		case []byte:
			scalarsBySlice[0] = (*C.byte)(&val[0])
			p_scalars = &scalarsBySlice[0]
		case [][]byte:
			p_scalars = &scalars[0]
		case []Scalar:
			if nbits > 248 {
				scalarsBySlice[0] = &val[0].b[0]
				p_scalars = &scalarsBySlice[0]
			} else {
				p_scalars = &scalars[0]
			}
		case []*Scalar:
			p_scalars = &scalars[0]
		}

		var ret P2
		_cgoCheckPointer := func(...interface{}) {}
		C.blst_p2s_mult_pippenger(&ret, p_points, C.size_t(npoints),
			p_scalars, C.size_t(nbits),
			(*C.limb_t)(&scratch[0]))

		for i := range scalars {
			scalars[i] = nil
		}

		return &ret
	}

	if npoints < 32 {
		if numThreads > npoints {
			numThreads = npoints
		}

		curItem := uint32(0)
		msgs := make(chan P2, numThreads)

		for tid := 0; tid < numThreads; tid++ {
			go func() {
				var acc P2

				for {
					workItem := int(atomic.AddUint32(&curItem, 1) - 1)
					if workItem >= npoints {
						break
					}

					var point *P2Affine
					switch val := pointsIf.(type) {
					case []*P2Affine:
						point = val[workItem]
					case []P2Affine:
						point = &val[workItem]
					case P2Affines:
						point = &val[workItem]
					}

					var scalar *C.byte
					switch val := scalarsIf.(type) {
					case []byte:
						scalar = (*C.byte)(&val[workItem*nbytes])
					case [][]byte:
						scalar = scalars[workItem]
					case []Scalar:
						if nbits > 248 {
							scalar = &val[workItem].b[0]
						} else {
							scalar = scalars[workItem]
						}
					case []*Scalar:
						scalar = scalars[workItem]
					}

					C.go_p2_mult_n_acc(&acc, &point.x, true,
						scalar, C.size_t(nbits))
				}

				msgs <- acc
			}()
		}

		ret := <-msgs
		for tid := 1; tid < numThreads; tid++ {
			point := <-msgs
			C.blst_p2_add_or_double(&ret, &ret, &point)
		}

		for i := range scalars {
			scalars[i] = nil
		}

		return &ret
	}

	// this is sizeof(scratch[0])
	sz := int(C.blst_p2s_mult_pippenger_scratch_sizeof(0)) / 8

	nx, ny, window := breakdown(nbits, pippenger_window_size(npoints),
		numThreads)

	// |grid[]| holds "coordinates" and place for result
	grid := make([]struct {
		x, dx, y, dy int
		point        P2
	}, nx*ny)

	dx := npoints / nx
	y := window * (ny - 1)
	total := 0
	for ; total < nx; total++ {
		grid[total].x = total * dx
		grid[total].dx = dx
		grid[total].y = y
		grid[total].dy = nbits - y
	}
	grid[total-1].dx = npoints - grid[total-1].x

	for y > 0 {
		y -= window
		for i := 0; i < nx; i++ {
			grid[total].x = grid[i].x
			grid[total].dx = grid[i].dx
			grid[total].y = y
			grid[total].dy = window
			total++
		}
	}

	if numThreads > total {
		numThreads = total
	}

	msgsCh := make(chan int, ny)
	rowSync := make([]int32, ny) // count up to |nx|
	curItem := int32(0)
	for tid := 0; tid < numThreads; tid++ {
		go func() {
			scratch := make([]uint64, sz<<uint(window-1))
			pointsBySlice := [2]*P2Affine{nil, nil}
			scalarsBySlice := [2]*C.byte{nil, nil}
			_cgoCheckPointer := func(...interface{}) {}

			for {
				workItem := atomic.AddInt32(&curItem, 1) - 1
				if int(workItem) >= total {
					break
				}

				x := grid[workItem].x
				y := grid[workItem].y

				var p_points **P2Affine
				switch val := pointsIf.(type) {
				case []*P2Affine:
					p_points = &val[x]
				case []P2Affine:
					pointsBySlice[0] = &val[x]
					p_points = &pointsBySlice[0]
				case P2Affines:
					pointsBySlice[0] = &val[x]
					p_points = &pointsBySlice[0]
				}

				var p_scalars **C.byte
				switch val := scalarsIf.(type) {
				case []byte:
					scalarsBySlice[0] = (*C.byte)(&val[x*nbytes])
					p_scalars = &scalarsBySlice[0]
				case [][]byte:
					p_scalars = &scalars[x]
				case []Scalar:
					if nbits > 248 {
						scalarsBySlice[0] = &val[x].b[0]
						p_scalars = &scalarsBySlice[0]
					} else {
						p_scalars = &scalars[x]
					}
				case []*Scalar:
					p_scalars = &scalars[x]
				}

				C.blst_p2s_tile_pippenger(&grid[workItem].point,
					p_points, C.size_t(grid[workItem].dx),
					p_scalars, C.size_t(nbits),
					(*C.limb_t)(&scratch[0]),
					C.size_t(y), C.size_t(window))

				if atomic.AddInt32(&rowSync[y/window], 1) == int32(nx) {
					msgsCh <- y // "row" is done
				} else {
					runtime.Gosched() // be nice to the application
				}
			}

			pointsBySlice[0] = nil
			scalarsBySlice[0] = nil
		}()
	}

	var ret P2
	rows := make([]bool, ny)
	row := 0                  // actually index in |grid[]|
	for i := 0; i < ny; i++ { // we expect |ny| messages, one per "row"
		y := <-msgsCh
		rows[y/window] = true  // mark the "row"
		for grid[row].y == y { // if it's current "row", process it
			for row < total && grid[row].y == y {
				C.blst_p2_add_or_double(&ret, &ret, &grid[row].point)
				row++
			}
			if y == 0 {
				break // one can as well 'return &ret' here
			}
			for j := 0; j < window; j++ {
				C.blst_p2_double(&ret, &ret)
			}
			y -= window
			if !rows[y/window] { // see if next "row" was marked already
				break
			}
		}
	}

	for i := range scalars {
		scalars[i] = nil
	}

	return &ret
}

func (points P2Affines) Mult(scalarsIf interface{}, nbits int) *P2 {
	return P2AffinesMult(points, scalarsIf, nbits)
}

func (points P2s) Mult(scalarsIf interface{}, nbits int) *P2 {
	return points.ToAffine().Mult(scalarsIf, nbits)
}

//
// Group-check
//

func P2AffinesValidate(pointsIf interface{}) bool {
	var npoints int
	switch val := pointsIf.(type) {
	case []*P2Affine:
		npoints = len(val)
	case []P2Affine:
		npoints = len(val)
	case P2Affines:
		npoints = len(val)
	default:
		panic(fmt.Sprintf("unsupported type %T", val))
	}

	numThreads := numThreads(npoints)

	if numThreads < 2 {
		for i := 0; i < npoints; i++ {
			var point *P2Affine

			switch val := pointsIf.(type) {
			case []*P2Affine:
				point = val[i]
			case []P2Affine:
				point = &val[i]
			case P2Affines:
				point = &val[i]
			default:
				panic(fmt.Sprintf("unsupported type %T", val))
			}

			if !C.go_p2_affine_validate(point, true) {
				return false
			}
		}

		return true
	}

	valid := int32(1)
	curItem := uint32(0)

	var wg sync.WaitGroup
	wg.Add(numThreads)

	for tid := 0; tid < numThreads; tid++ {
		go func() {
			for atomic.LoadInt32(&valid) != 0 {
				work := atomic.AddUint32(&curItem, 1) - 1
				if work >= uint32(npoints) {
					break
				}

				var point *P2Affine

				switch val := pointsIf.(type) {
				case []*P2Affine:
					point = val[work]
				case []P2Affine:
					point = &val[work]
				case P2Affines:
					point = &val[work]
				default:
					panic(fmt.Sprintf("unsupported type %T", val))
				}

				if !C.go_p2_affine_validate(point, true) {
					atomic.StoreInt32(&valid, 0)
					break
				}
			}

			wg.Done()
		}()
	}

	wg.Wait()

	return atomic.LoadInt32(&valid) != 0
}

func (points P2Affines) Validate() bool {
	return P2AffinesValidate(points)
}

func parseOpts(optional ...interface{}) ([]byte, [][]byte, bool, bool) {
	var aug [][]byte     // For aggregate verify
	var augSingle []byte // For signing
	useHash := true      // hash (true), encode (false)

	for _, arg := range optional {
		switch v := arg.(type) {
		case []byte:
			augSingle = v
		case [][]byte:
			aug = v
		case bool:
			useHash = v
		default:
			return nil, nil, useHash, false
		}
	}
	return augSingle, aug, useHash, true
}

// These methods are inefficient because of cgo call overhead. For this
// reason they should be used primarily for prototyping with a goal to
// formulate interfaces that would process multiple scalars per cgo call.
func (a *Scalar) MulAssign(b *Scalar) (*Scalar, bool) {
	return a, bool(C.blst_sk_mul_n_check(a, a, b))
}

func (a *Scalar) Mul(b *Scalar) (*Scalar, bool) {
	var ret Scalar
	return &ret, bool(C.blst_sk_mul_n_check(&ret, a, b))
}

func (a *Scalar) AddAssign(b *Scalar) (*Scalar, bool) {
	return a, bool(C.blst_sk_add_n_check(a, a, b))
}

func (a *Scalar) Add(b *Scalar) (*Scalar, bool) {
	var ret Scalar
	return &ret, bool(C.blst_sk_add_n_check(&ret, a, b))
}

func (a *Scalar) SubAssign(b *Scalar) (*Scalar, bool) {
	return a, bool(C.blst_sk_sub_n_check(a, a, b))
}

func (a *Scalar) Sub(b *Scalar) (*Scalar, bool) {
	var ret Scalar
	return &ret, bool(C.blst_sk_sub_n_check(&ret, a, b))
}

func (a *Scalar) Inverse() *Scalar {
	var ret Scalar
	C.blst_sk_inverse(&ret, a)
	return &ret
}

//
// Serialization/Deserialization.
//

// Scalar serdes
func (s *Scalar) Serialize() []byte {
	var out [BLST_SCALAR_BYTES]byte
	C.blst_bendian_from_scalar((*C.byte)(&out[0]), s)
	return out[:]
}

func (s *Scalar) Deserialize(in []byte) *Scalar {
	if len(in) != BLST_SCALAR_BYTES ||
		!C.go_scalar_from_bendian(s, (*C.byte)(&in[0])) {
		return nil
	}
	return s
}

func (s *Scalar) Valid() bool {
	return bool(C.blst_sk_check(s))
}

func (s *Scalar) HashTo(msg []byte, dst []byte) bool {
	ret := HashToScalar(msg, dst)
	if ret != nil {
		*s = *ret
		return true
	}
	return false
}

func HashToScalar(msg []byte, dst []byte) *Scalar {
	var ret Scalar

	if C.go_hash_to_scalar(&ret, ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst))) {
		return &ret
	}

	return nil
}

//
// LEndian
//

func (fr *Scalar) ToLEndian() []byte {
	var arr [BLST_SCALAR_BYTES]byte
	C.blst_lendian_from_scalar((*C.byte)(&arr[0]), fr)
	return arr[:]
}

func (fp *Fp) ToLEndian() []byte {
	var arr [BLST_FP_BYTES]byte
	C.blst_lendian_from_fp((*C.byte)(&arr[0]), fp)
	return arr[:]
}

func (fr *Scalar) FromLEndian(arr []byte) *Scalar {
	nbytes := len(arr)
	if nbytes < BLST_SCALAR_BYTES ||
		!C.blst_scalar_from_le_bytes(fr, (*C.byte)(&arr[0]), C.size_t(nbytes)) {
		return nil
	}
	return fr
}

func (fp *Fp) FromLEndian(arr []byte) *Fp {
	if len(arr) != BLST_FP_BYTES {
		return nil
	}
	C.blst_fp_from_lendian(fp, (*C.byte)(&arr[0]))
	return fp
}

//
// BEndian
//

func (fr *Scalar) ToBEndian() []byte {
	var arr [BLST_SCALAR_BYTES]byte
	C.blst_bendian_from_scalar((*C.byte)(&arr[0]), fr)
	return arr[:]
}

func (fp *Fp) ToBEndian() []byte {
	var arr [BLST_FP_BYTES]byte
	C.blst_bendian_from_fp((*C.byte)(&arr[0]), fp)
	return arr[:]
}

func (fr *Scalar) FromBEndian(arr []byte) *Scalar {
	nbytes := len(arr)
	if nbytes < BLST_SCALAR_BYTES ||
		!C.blst_scalar_from_be_bytes(fr, (*C.byte)(&arr[0]), C.size_t(nbytes)) {
		return nil
	}
	return fr
}

func (fp *Fp) FromBEndian(arr []byte) *Fp {
	if len(arr) != BLST_FP_BYTES {
		return nil
	}
	C.blst_fp_from_bendian(fp, (*C.byte)(&arr[0]))
	return fp
}

//
// Printing
//

func PrintBytes(val []byte, name string) {
	fmt.Printf("%s = %02x\n", name, val)
}

func (s *Scalar) Print(name string) {
	arr := s.ToBEndian()
	PrintBytes(arr, name)
}

func (p *P1Affine) Print(name string) {
	fmt.Printf("%s:\n", name)
	arr := p.x.ToBEndian()
	PrintBytes(arr, "  x")
	arr = p.y.ToBEndian()
	PrintBytes(arr, "  y")
}

func (p *P1) Print(name string) {
	fmt.Printf("%s:\n", name)
	aff := p.ToAffine()
	aff.Print(name)
}

func (f *Fp2) Print(name string) {
	fmt.Printf("%s:\n", name)
	arr := f.fp[0].ToBEndian()
	PrintBytes(arr, "    0")
	arr = f.fp[1].ToBEndian()
	PrintBytes(arr, "    1")
}

func (p *P2Affine) Print(name string) {
	fmt.Printf("%s:\n", name)
	p.x.Print("  x")
	p.y.Print("  y")
}

func (p *P2) Print(name string) {
	fmt.Printf("%s:\n", name)
	aff := p.ToAffine()
	aff.Print(name)
}

//
// Equality
//

func (s1 *Scalar) Equals(s2 *Scalar) bool {
	return *s1 == *s2
}

func (e1 *Fp) Equals(e2 *Fp) bool {
	return *e1 == *e2
}

func (e1 *Fp2) Equals(e2 *Fp2) bool {
	return *e1 == *e2
}

func (e1 *P1Affine) Equals(e2 *P1Affine) bool {
	return bool(C.blst_p1_affine_is_equal(e1, e2))
}

func (e1 *P1) Equals(e2 *P1) bool {
	return bool(C.blst_p1_is_equal(e1, e2))
}

func (e1 *P2Affine) Equals(e2 *P2Affine) bool {
	return bool(C.blst_p2_affine_is_equal(e1, e2))
}

func (e1 *P2) Equals(e2 *P2) bool {
	return bool(C.blst_p2_is_equal(e1, e2))
}

// private thunk for testing

func expandMessageXmd(msg []byte, dst []byte, len_in_bytes int) []byte {
	ret := make([]byte, len_in_bytes)

	C.blst_expand_message_xmd((*C.byte)(&ret[0]), C.size_t(len(ret)),
		ptrOrNil(msg), C.size_t(len(msg)),
		ptrOrNil(dst), C.size_t(len(dst)))
	return ret
}

func breakdown(nbits, window, ncpus int) (nx int, ny int, wnd int) {

	if nbits > window*ncpus { //nolint:nestif
		nx = 1
		wnd = bits.Len(uint(ncpus) / 4)
		if (window + wnd) > 18 {
			wnd = window - wnd
		} else {
			wnd = (nbits/window + ncpus - 1) / ncpus
			if (nbits/(window+1)+ncpus-1)/ncpus < wnd {
				wnd = window + 1
			} else {
				wnd = window
			}
		}
	} else {
		nx = 2
		wnd = window - 2
		for (nbits/wnd+1)*nx < ncpus {
			nx += 1
			wnd = window - bits.Len(3*uint(nx)/2)
		}
		nx -= 1
		wnd = window - bits.Len(3*uint(nx)/2)
	}
	ny = nbits/wnd + 1
	wnd = nbits/ny + 1

	return nx, ny, wnd
}

func pippenger_window_size(npoints int) int {
	wbits := bits.Len(uint(npoints))

	if wbits > 13 {
		return wbits - 4
	}
	if wbits > 5 {
		return wbits - 3
	}
	return 2
}
