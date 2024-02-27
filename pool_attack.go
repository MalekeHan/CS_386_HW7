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

	/*
		t = 1.5
		s0 occurs at 0 seconds
		1s we get our
		1.5 seconds the victim draws
			- we would need to call draw at 1.25 seconds for the "A"
			- V happens at 1.5

		- so i am going through {0,1}^16 looking for one that matches for what I get at 1.25?

		Do the poolinit to get the original state
		- do go through all 2^16 and and run the add and then the draw
		- sample at 1.25
		- find the one that matches
		- do draw on it one more time
	*/
	s0 := poolInitState // get the initialstate of the entropy pool -- s0

	// enumerate through all the r's
	for i := 0; i < 1<<16; i++ {
		var sample poolSample
		sample[0] = byte(i >> 8)   // High byte
		sample[1] = byte(i & 0xFF) // Low byte

		newState := poolAdd(s0, sample)
		initState := prngInit(prngSeed(newState)) // this does the init part

		currentState, currentSample := prngDraw(initState) // this is the draw that we got from the sample // but how do i check if this matched? should i just save this? and then get to 1.25 and see if i have it?

		_, private := generateRsaKeyPair(correctDraw)

		signedDoc := private.sign([]byte(document))

		return signedDoc
	}
}
