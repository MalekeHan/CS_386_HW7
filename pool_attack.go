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
	startTime := time.Now()
	initialSleep := 250 * time.Millisecond
	interval := 1 * time.Second

	time.Sleep(initialSleep)
	var correctDraw prngSample
	var correctSign []byte

	// go run pool.go pool_solution.go 1.5s

	s0 := poolInitState // get the initialstate of the entropy pool -- s0

	for {
		// Sleep for the interval
		time.Sleep(interval)
		// Check if the total duration has been reached
		if time.Since(startTime) >= victimSleepsBeforeGenerateKey {
			break // Exit the loop if the specified duration is reached
		}

		os_draw := o.draw()

		for i := 0; i < 1<<16; i++ {
			var canidate poolSample
			canidate[0] = byte(i >> 8)   // High byte
			canidate[1] = byte(i & 0xFF) // Low byte

			s1 := poolAdd(s0, canidate)                              // do the add
			currentState := prngInit(prngSeed(s1))                   // do the init
			state_from_draw, guessedSample := prngDraw(currentState) // do the draw
			if os_draw == guessedSample {                            // check if the pnrg draw matches the os_draw
				debugPrintf("I GOT THE CORRECT SAMPLE: [%x ]\n", guessedSample)
				_, correctDraw = prngDraw(state_from_draw)
				prngGuess := newPrng(prngSeed(correctDraw))
				_, priv_key := generateRsaKeyPair(&prngGuess) // generateRsaKeyPair
				documentBytes := []byte(document)             // Convert document string to []byte
				correctSign = priv_key.sign(documentBytes)    // Use the sign method to sign the document
			}

		}

	}

	return correctSign
}
