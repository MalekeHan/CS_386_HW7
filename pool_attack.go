package main

import (
	"time"
)

// Run the attacker process.
//
// The attacker is told how long the victim will sleep before drawing from the
// OS in order to generate its key pair.
//
// The attacker's job is to:
// - Compute the same key pair that the victim computes
// - Use this key pair to sign `document` and return the signature
func runAttacker(o *os, document string, victimSleepsBeforeGenerateKey time.Duration) []byte {
	// Your attack will probably want to make use of the following
	// functions/methods/values:
	// - time.Now
	// - time.Sleep
	// - (*os).draw
	// - poolInitState
	// - poolAdd
	// - prngInit
	// - prngDraw
	// - generateRsaKeyPair
	// - (*rsaPrivateKey).sign
	//
	// Finally, we recommend that you don't try to call `(*os).draw` at exactly
	// the same time as a sample is added or as the victim performs their own
	// draw. If you do, you won't be sure whether your draw came before or after
	// the other event. Instead, we recommend leaving a good amount of time
	// between other events. For example, if you know that the OS will add a
	// sample at t = 8 and that the victim will draw at t = 8.5, and you are
	// trying to draw your own sample in between these events, we recommend
	// drawing your sample at t = 8.25.

	return nil
}
