package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	oss "os"
	"sync"
	"time"
)

func main() {
	var victimSleeps string
	switch {
	case len(oss.Args) == 2:
		victimSleeps = oss.Args[1]
	case len(oss.Args) == 3 && oss.Args[1] == "--debug":
		debug = true
		victimSleeps = oss.Args[2]
	default:
		fmt.Fprintf(oss.Stderr, "Usage: %v [--debug] <victim-sleeps-duration>\n", oss.Args[0])
		oss.Exit(1)
	}

	victimSleepsDur, err := time.ParseDuration(victimSleeps)
	if err != nil {
		fmt.Fprintf(oss.Stderr, "could not parse duration: %v\n", err)
		oss.Exit(1)
	}

	o := boot()

	publishPublicKey := make(chan rsaPublicKey)
	// Spawn the victim as a separate goroutine. If you're not familar with
	// goroutines, that's fine - the point is just that `main` will continue
	// executing while the victim runs in parallel.
	go runVictim(o, publishPublicKey, victimSleepsDur)

	const document = "I am a stinky buttface!!"

	// Your attack gets called here.
	forgedSignature := runAttacker(o, document, victimSleepsDur)

	// The verifier is used to verify that you successfully forged the victim's
	// signature.
	runVerifier(publishPublicKey, document, forgedSignature)
}

// *************** Verifier process ***************

// Run the verifier process.
//
// Given a document and a signature, the verifier will wait until the victim has
// published their public key, and will then verify the signature. It will print
// a message to stdout which describes whether or not the signature was valid.
func runVerifier(publish chan rsaPublicKey, document string, signature []byte) {
	pub := <-publish
	if pub.verify([]byte(document), signature) {
		fmt.Println("The victim has published the following document:", document)
	} else {
		fmt.Println("Somebody tried to forge the following document:", document)
	}
}

// *************** Victim process ***************

// Run the victim process.
//
// `runVictim` sleeps for `sleepBeforeGenerateKey`, and then draws a sample from
// the OS. It uses that sample to seed a new PRNG, and uses that PRNG to
// generate an RSA key pair. Finally, it publishes the public key to the
// `publish` channel.
func runVictim(o *os, publish chan rsaPublicKey, sleepBeforeGenerateKey time.Duration) {
	time.Sleep(sleepBeforeGenerateKey)

	draw := o.draw()
	debugPrintf("[victim] drew:                %x\n", draw)
	prng := newPrng(prngSeed(draw))
	debugPrintf("[victim] init prng state:     %x\n", prng.state)
	pub, _ := generateRsaKeyPair(&prng)

	publish <- pub
}

// *************** RSA ***************

// An RSA public key.
type rsaPublicKey struct {
	key *rsa.PublicKey
}

// An RSA private key.
type rsaPrivateKey struct {
	key *rsa.PrivateKey
}

// Generate an RSA key pair using `prng` as the source of randomness.
func generateRsaKeyPair(prng io.Reader) (rsaPublicKey, rsaPrivateKey) {
	priv, err := rsa.GenerateKey(prng, 2048)
	if err != nil {
		panic(err)
	}
	pub := priv.Public().(*rsa.PublicKey)

	return rsaPublicKey{key: pub}, rsaPrivateKey{key: priv}
}

// Sign a document with an RSA private key.
func (k *rsaPrivateKey) sign(document []byte) []byte {
	h := sha256.Sum256(document)
	sig, err := rsa.SignPSS(rand.Reader, k.key, crypto.SHA256, h[:], nil)
	if err != nil {
		panic(err)
	}

	return sig
}

// Verify a document's signature with an RSA public key.
func (k *rsaPublicKey) verify(document, signature []byte) bool {
	h := sha256.Sum256(document)
	err := rsa.VerifyPSS(k.key, crypto.SHA256, h[:], signature, nil)
	return err == nil
}

// *************** Operating system ***************

// The operating system!
//
// The only things you can do with this `os` are:
// - Boot it via `boot()`
// - Draw a PRNG sample from it via `draw()`
//
// As described in Homework 06, this will add a new sample to the entropy pool
// at `t` in `(1, ..., 16)`.
type os struct {
	poolState
	prng
	mtx sync.Mutex
}

// Boot the OS.
func boot() *os {
	o := &os{
		poolState: poolInitState,
		prng:      newPrng(prngSeed(poolInitState)),
	}

	debugPrintf("[os][ 0s] state (pool, prng): %x, %x\n", o.poolState, o.prng.state)

	go func() {
		var t time.Duration = 0
		for t < 16*time.Second {
			time.Sleep(time.Second)
			t += time.Second

			var sample poolSample
			rand.Read(sample[:])
			debugPrintf("[os][%3v] drew sample:        %x\n", t, sample)

			o.mtx.Lock()
			o.poolState = poolAdd(o.poolState, sample)
			o.prng = newPrng(prngSeed(o.poolState))
			debugPrintf("[os][%3v] state (pool, prng): %x, %x\n", t, o.poolState, o.prng.state)
			o.mtx.Unlock()
		}
	}()

	return o
}

// Draw a PRNG sample from the OS.
func (o *os) draw() prngSample {
	o.mtx.Lock()
	defer o.mtx.Unlock()
	return o.prng.draw()
}

// *************** Convenience PRNG wrapper ***************

// A convenience wrapper around `prngState` which will automatically update the
// state on every draw.
type prng struct {
	state prngState
}

func newPrng(seed prngSeed) prng {
	return prng{state: prngInit(seed)}
}

func (p *prng) draw() prngSample {
	var sample prngSample
	p.state, sample = prngDraw(p.state)
	return sample
}

// This implements the `io.Reader` interface, which lets us use `prng` as the
// `random` argument to `rsa.GenerateKey`.
func (p *prng) Read(buf []byte) (int, error) {
	if len(buf) == 1 {
		// This is a horrible, horrible hack that I (Josh) had to add purely to
		// get this code to work with Go's `rsa.GenerateKey` implementation, and
		// you shouldn't pay any attention to it. It has nothing to do with the
		// ideas in this assignment. If you pretend this `if` branch doesn't
		// exist, you will still be able to complete the assignment. If you want
		// to know why this exists, see the comment at the bottom of this file,
		// but again: this is just a hack to get the assignment to work, and has
		// nothing to do with the ideas we're trying to teach.
		return 1, nil
	}

	ret := len(buf)
	for len(buf) > 0 {
		sample := p.draw()
		n := copy(buf, sample[:])
		buf = buf[n:]
	}
	return ret, nil
}

// *************** Core PRNG implementation ***************

const (
	// 32 bytes = 256 bits
	prngStateSize = 32
	// 32 bytes = 256 bits
	prngSeedSize = 32
	// 32 bytes = 256 bits
	prngSampleSize = 32
)

type (
	prngState  [prngStateSize]byte
	prngSeed   [prngSeedSize]byte
	prngSample [prngSampleSize]byte
)

// This implements the PRNG `init` function we've seen in homework.
func prngInit(seed prngSeed) prngState {
	// NOTE: We do not promise that this is a secure implementation of a PRNG
	// init function! The point of this problem is not to bother with the
	// specifics of the function. You should be able to implement your attack
	// for *any* deterministic `prngInit` function.
	return sha256.Sum256(seed[:])
}

// This implements the PRNG `draw` function we've seen in homework.
func prngDraw(state prngState) (prngState, prngSample) {
	// NOTE: We do not promise that this is a secure implementation of a PRNG
	// draw function! The point of this problem is not to bother with the
	// specifics of the function. You should be able to implement your attack
	// for *any* deterministic `prngDraw` function.
	newState := sha256.Sum256(append([]byte("newState"), state[:]...))
	sample := sha256.Sum256(append([]byte("sample"), state[:]...))
	return newState, sample
}

// *************** Core entropy pool implementation ***************

const (
	// 32 bytes = 256 bits
	poolStateSize = 32
	// 2 bytes = 16 bits
	poolSampleSize = 2
)

// The initial entropy pool state (s0 from homework).
var poolInitState poolState

type (
	poolState  [poolStateSize]byte
	poolSample [poolSampleSize]byte
)

// This implements the entropy pool `add` function we've seen in homework.
func poolAdd(state poolState, sample poolSample) poolState {
	// NOTE: We do not promise that this is a secure implementation of an
	// entropy pool add function! The point of this problem is not to bother
	// with the specifics of the function. You should be able to implement your
	// attack for *any* deterministic `poolAdd` function.
	concatenated := append(state[:], sample[:]...)
	return sha256.Sum256(concatenated)
}

// *************** Miscellaneous utilities ***************

var debug bool = false

func debugPrintf(format string, a ...any) (n int, err error) {
	if debug {
		return fmt.Printf("[DEBUG] "+format, a...)
	}
	return 0, nil
}

// This comment explains the `if` branch in (*prng).Read. It has nothing to do
// with the ideas in this homework, and it's here just in case people are
// curious. You do *not* need to read this comment in order to complete this
// assignment.
//
// In order for this assignment to work, the process of generating a
// public/private key pair must depend *only* on the PRNG provided to the
// generation process (`rsa.GenerateKey`). The whole point of this assignment is
// that we're simulating *all the entropy in the world* (at least from the
// perspective of processes running on our toy "OS"). Of course, that's a lie -
// this is actually just a Go program that you're running on your Linux or Mac
// or Windows OS. But that's what we're trying to simulate.
//
// It would be great, then, if `rsa.GenerateKey` only used its `random` argument
// (its first positional argument) for its source of entropy. Then, we could
// rely on the same entropy producing the same key pair - which is the entire
// point of this assignment. Unfortunately, Go is a pRoDuCtIoN lAnGuAgE, and it
// cares about ReAl WoRlD uSe CaSeS. Whatever. This means that having `random`
// be the only source of entropy is problematic because then programmers do
// silly things like start to rely on `GenerateKey`'s output being deterministic
// (as a function of its `random` argument), which is bad from a security
// perspective.
//
// In order to stop programmers from doing this, the Go authors intentionally
// added in their own, separate source of randomness [1]. That way, even if the
// same stream of random bytes is produced by `random`, `GenerateKey` can still
// behave non-deterministically. This works by quering their own (not
// particularly secure) source of randomness for a single bit. That single bit
// is used to determine whether or not to read an extra byte from `random` at
// the beginning of the function. Of course, "bytes `0` through `n`" of a
// particular random stream are not the same as "bytes `1` through `n + 1`" of
// the same stream, so this has the effect of making `GenerateKey`
// non-deterministic even as a function of `random`.
//
// The implementation of this "maybe read one extra byte" is `MaybeReadByte`
// [2], and it's used from `GenerateKey` in [3].
//
// The point of this `if` is to defeat that behavior. The only code that calls
// this method is `GenerateKey`, and `GenerateKey` *only* generates 1-byte calls
// to this method via `MaybeReadByte`. No "real" uses of the PRNG ever draw 1
// byte at a time. Thus, if we just ignore all 1-byte calls, then we recover the
// determinism that we need for this assignment to work. It's a horrible,
// horrible hack, and if I had had more time to write this assignment, I (Josh)
// might have just hand-rolled an RSA implementation instead to work around the
// issue. Maybe next time ¯\_(ツ)_/¯
//
// [1] https://cs.opensource.google/go/go/+/6269dcdc24d74379d8a609ce886149811020b2cc
// [2] https://cs.opensource.gdfoogle/go/go/+/refs/tags/go1.22.0:src/crypto/internal/randutil/randutil.go;l=25-38
// [3] https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/crypto/rsa/rsa.go;l=299;bpv=1;bpt=0
