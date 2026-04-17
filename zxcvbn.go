package zxcvbn

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/trustelem/zxcvbn/feedback"
	"github.com/trustelem/zxcvbn/match"
	"github.com/trustelem/zxcvbn/matching"
	"github.com/trustelem/zxcvbn/scoring"
)

type Result struct {
	Guesses  float64
	Sequence []*match.Match
	Score    int
	CalcTime float64
	Feedback feedback.Feedback
}

func PasswordStrength(password string, userInputs []string) Result {
	result, _ := PasswordStrengthWithContext(context.Background(), password, userInputs)
	return result
}

// PasswordStrengthWithContext runs the strength check and returns early if ctx is cancelled.
// If the context is cancelled mid-computation, the returned error will be non-nil and
// the Result will be zero-valued (score 0, treated as weak).
func PasswordStrengthWithContext(ctx context.Context, password string, userInputs []string) (Result, error) {
	start := time.Now()
	var result Result
	if !utf8.ValidString(password) {
		return result, nil
	}
	matches, err := matching.OmnimatchWithContext(ctx, password, userInputs)
	if err != nil {
		return result, err
	}
	seq, err := scoring.MostGuessableMatchSequenceWithContext(ctx, password, matches, false)
	if err != nil {
		return result, err
	}
	end := time.Now()
	calcTime := end.Nanosecond() - start.Nanosecond()
	result.CalcTime = round(float64(calcTime)*time.Nanosecond.Seconds(), .5, 3)
	result.Sequence = seq.Sequence
	result.Guesses = seq.Guesses
	result.Score = guessesToScore(seq.Guesses)
	result.Feedback = feedback.GetFeedback(result.Score, result.Sequence)
	return result, nil
}
