package matching

import (
	"context"

	"github.com/dlclark/regexp2"
	"github.com/trustelem/zxcvbn/match"
	"github.com/trustelem/zxcvbn/scoring"
)

type repeatMatch struct{}

var greedy = regexp2.MustCompile(`(.+)\1+`, 0)
var lazy = regexp2.MustCompile(`(.+?)\1+`, 0)
var lazyAnchored = regexp2.MustCompile(`^(.+?)\1+$`, 0)

func runeToStringIndex(index int, password string) int {
	runes := 0
	for i := range password {
		if runes == index {
			return i
		}
		runes++
	}
	//shouldn't really get here
	return len(password)
}

func (repeatMatch) Matches(password string) []*match.Match {
	results, _ := repeatMatch{}.MatchesWithContext(context.Background(), password)
	return results
}

func (repeatMatch) MatchesWithContext(ctx context.Context, password string) ([]*match.Match, error) {
	var matches []*match.Match

	lastIndex := 0
	for lastIndex < len(password) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		greedyMatch, err := greedy.FindStringMatchStartingAt(password, lastIndex)
		if err != nil || greedyMatch == nil {
			break
		}
		lazyMatch, _ := lazy.FindStringMatchStartingAt(password, lastIndex)

		var rmatch *regexp2.Match
		var baseToken string
		if greedyMatch.Captures[0].Length > lazyMatch.Captures[0].Length {
			rmatch = greedyMatch
			if m, err := lazyAnchored.FindStringMatch(rmatch.Captures[0].String()); err == nil {
				baseToken = m.GroupByNumber(1).String()
			}
		} else {
			rmatch = lazyMatch
			baseToken = rmatch.GroupByNumber(1).String()
		}
		i := runeToStringIndex(rmatch.Index, password)
		j := runeToStringIndex(rmatch.Index+rmatch.Captures[0].Length-1, password)

		baseSubMatches, err := OmnimatchWithContext(ctx, baseToken, nil)
		if err != nil {
			return nil, err
		}
		baseAnalysis := scoring.MostGuessableMatchSequence(baseToken, baseSubMatches, false)
		matches = append(matches, &match.Match{
			Pattern:     "repeat",
			I:           i,
			J:           j,
			Token:       rmatch.Captures[0].String(),
			BaseToken:   baseToken,
			BaseGuesses: baseAnalysis.Guesses,
			BaseMatches: baseAnalysis.Sequence,
			RepeatCount: rmatch.Captures[0].Length / len(baseToken),
		})
		lastIndex = j + 1
	}
	return matches, nil
}
