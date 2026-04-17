package matching

import (
	"context"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/trustelem/zxcvbn/match"
	"github.com/trustelem/zxcvbn/scoring"
)

type repeatMatch struct{}

const (
	greedyPattern     = `(.+)\1+`
	lazyPattern       = `(.+?)\1+`
	lazyAnchoredPat   = `^(.+?)\1+$`
)

var greedy = regexp2.MustCompile(greedyPattern, 0)
var lazy = regexp2.MustCompile(lazyPattern, 0)
var lazyAnchored = regexp2.MustCompile(lazyAnchoredPat, 0)

// regexpsWithTimeout returns regexp instances with MatchTimeout set to the
// remaining context deadline, so that a long-running regexp match is interrupted
// when the context expires rather than blocking indefinitely.
func regexpsWithTimeout(ctx context.Context) (g, l, la *regexp2.Regexp) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return greedy, lazy, lazyAnchored
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = time.Millisecond
	}
	g = regexp2.MustCompile(greedyPattern, 0)
	g.MatchTimeout = timeout
	l = regexp2.MustCompile(lazyPattern, 0)
	l.MatchTimeout = timeout
	la = regexp2.MustCompile(lazyAnchoredPat, 0)
	la.MatchTimeout = timeout
	return g, l, la
}

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

	g, l, la := regexpsWithTimeout(ctx)

	lastIndex := 0
	for lastIndex < len(password) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		greedyMatch, err := g.FindStringMatchStartingAt(password, lastIndex)
		if err != nil || greedyMatch == nil {
			if err != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			break
		}
		lazyMatch, _ := l.FindStringMatchStartingAt(password, lastIndex)

		var rmatch *regexp2.Match
		var baseToken string
		if greedyMatch.Captures[0].Length > lazyMatch.Captures[0].Length {
			rmatch = greedyMatch
			if m, err := la.FindStringMatch(rmatch.Captures[0].String()); err == nil {
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
		baseAnalysis, err := scoring.MostGuessableMatchSequenceWithContext(ctx, baseToken, baseSubMatches, false)
		if err != nil {
			return nil, err
		}
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
