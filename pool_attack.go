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

	var osDraws []prngSample          // Slice to store OS draws
	currentPoolState := poolInitState // Start with the initial state of the entropy pool
	var correctDraw prngSample
	var correctSign []byte
	var maximumDraws int

	hasSigned := false // Flag to check if signing has occurred

	// Collect OS draws during the victim's sleep period
	for {

		time.Sleep(interval) // Sleep for the interval duration
		// Check if the total duration has been reached
		if time.Since(startTime) >= victimSleepsBeforeGenerateKey {
			debugPrintf("HIT THE MAXIMUM TIME GONNA STOP: \n")
			break // Exit the loop after signing
		}
		maximumDraws += 1
		if maximumDraws <= 16 {
			debugPrintf("ENTERED THE LOOP CAUSE I AM NOT AT THE DRAWS LIMIT YET\n")
			osDraws = append(osDraws, o.draw()) // Append the draw from the OS
		}

	}

	// go through all the OS draws and do the attack
	for _, osDraw := range osDraws {
		for i := 0; i < 1<<16; i++ {
			var candidate poolSample
			candidate[0] = byte(i >> 8)   // High byte
			candidate[1] = byte(i & 0xFF) // Low byte

			// Update the pool state with the candidate
			nextPoolState := poolAdd(currentPoolState, candidate)
			prng := prngInit(prngSeed(nextPoolState))        // Initialize PRNG with the updated pool state
			state_from_draw, guessedSample := prngDraw(prng) // Perform a PRNG draw with the updated state

			if osDraw == guessedSample {
				debugPrintf("GOT THE CORRECT GUESS\n")
				_, correctDraw = prngDraw(state_from_draw) // This does the second draw to get to V from A
				currentPoolState = nextPoolState           // Update the pool state for the next interval
				break                                      // Found the correct sample, break to update for the next interval
			}
		}
	}

	// Perform the signing with the final correct state
	if !hasSigned {
		prngGuess := newPrng(prngSeed(correctDraw))
		_, privKey := generateRsaKeyPair(&prngGuess) // Generate RSA key pair
		documentBytes := []byte(document)            // Convert document string to []byte
		correctSign = privKey.sign(documentBytes)    // Sign the document
		hasSigned = true
	}

	return correctSign // Return the signature
}
