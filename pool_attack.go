package main

import (
	"time"
)

func runAttacker(o *os, document string, victimSleepsBeforeGenerateKey time.Duration) []byte {
	startTime := time.Now()
	initialSleep := 250 * time.Millisecond
	interval := 1 * time.Second

	// Initial sleep before starting the attack process
	time.Sleep(initialSleep)
	var correctDraw prngSample
	var correctSign []byte
	currentPoolState := poolInitState // Start with the initial state of the entropy pool
	var maximumDraws int

	hasSigned := false // Flag to check if signing has occurred

	for {

		time.Sleep(interval) // Sleep for the interval duration

		// Check if the total duration has been reached
		if time.Since(startTime) >= victimSleepsBeforeGenerateKey {
			break // Exit the loop after signing
		}
		maximumDraws += 1
		if maximumDraws < 16 {
			os_draw := o.draw() // Draw once per interval from the OS

			for i := 0; i < 1<<16; i++ {
				var candidate poolSample
				candidate[0] = byte(i >> 8)   // High byte
				candidate[1] = byte(i & 0xFF) // Low byte

				// Update the pool state with the candidate for this interval
				nextPoolState := poolAdd(currentPoolState, candidate)
				prng := prngInit(prngSeed(nextPoolState))        // Initialize PRNG with the updated pool state
				state_from_draw, guessedSample := prngDraw(prng) // Perform a PRNG draw with the updated state

				// draw needs to change the second one

				//print these things out and see

				if os_draw == guessedSample {
					debugPrintf("I GOT THE CORRECT SAMPLE: [%x ]\n", guessedSample)
					// If the PRNG draw matches the OS draw, prepare for the next interval
					_, correctDraw = prngDraw(state_from_draw) // This does the second draw to get to V from A
					currentPoolState = nextPoolState           // Update the pool state for the next interval
					break                                      // Found the correct sample, break to update for the next interval
				}
			}
		}

	}

	debugPrintf("GOING TO SIGN NOW\n")

	if !hasSigned {
		// Perform the signing in the last interval
		prngGuess := newPrng(prngSeed(correctDraw))
		_, privKey := generateRsaKeyPair(&prngGuess) // Generate RSA key pair
		documentBytes := []byte(document)            // Convert document string to []byte
		correctSign = privKey.sign(documentBytes)    // Sign the document
		hasSigned = true
	}

	return correctSign // Return the signature
}
