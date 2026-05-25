package engine

import (
	"regexp"
	"strings"
	"sync"
)

var (
	ssnRE    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccRE     = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	emailRE  = regexp.MustCompile(`\b[\w.+-]+@[\w-]+\.[\w.-]+\b`)
	phoneRE  = regexp.MustCompile(`\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
	apiKeyRE = regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`)

	// Restricted-term regexes are configured at startup via InitRestrictedTerms.
	// Default seed (tsmc) is set in init() so unit tests that import the engine
	// without explicit initialisation still behave as before.
	restrictedTermsMu      sync.RWMutex
	restrictedDomainRE     *regexp.Regexp
	restrictedWordRE       *regexp.Regexp
	restrictedSubstringREs []*regexp.Regexp
	restrictedTermsLower   []string

	nameTitleRE = regexp.MustCompile(
		`\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Madam|Mx)\.?\s+` +
			`[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b`,
	)
	nameFullRE = regexp.MustCompile(`\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}\b`)

	promptInjectionREs = []*regexp.Regexp{
		regexp.MustCompile(
			`(?i)\bignore\s+(?:all\s+|the\s+|any\s+)?` +
				`(?:previous|prior|above|preceding|earlier)\s+` +
				`(?:instructions?|prompts?|messages?|rules?|context|directives?)`,
		),
		regexp.MustCompile(
			`(?i)\bdisregard\s+(?:all\s+|the\s+|any\s+)?` +
				`(?:previous|prior|above|preceding|instructions?|rules?)`,
		),
		regexp.MustCompile(
			`(?i)\bforget\s+(?:everything|all\s+(?:previous|prior)|` +
				`(?:the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?))`,
		),
		regexp.MustCompile(
			`(?i)\b(?:override|bypass|disable|turn\s+off)\s+` +
				`(?:the\s+|all\s+)?(?:safety|security|guardrails?|filters?|` +
				`restrictions?|content\s+polic(?:y|ies))`,
		),
		regexp.MustCompile(
			`(?i)\b(?:reveal|show|print|output|leak|reproduce)\s+` +
				`(?:me\s+)?(?:your|the)\s+(?:system\s+|initial\s+|original\s+)?` +
				`(?:prompt|instructions?|rules?|guidelines?)`,
		),
		regexp.MustCompile(
			`(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|` +
				`roleplay\s+as|simulate)\s+(?:a\s+|an\s+)?` +
				`(?:DAN|jailbroken|unrestricted|uncensored|unfiltered|` +
				`evil|rogue|malicious)`,
		),
		regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
		regexp.MustCompile(`(?i)\bDAN\s+mode\b`),
		regexp.MustCompile(`(?i)\bjail[\s-]?(?:break(?:ing|ed|s)?|broken)\b`),
		regexp.MustCompile(`(?i)\b(?:developer|debug|admin|god)\s+mode\b`),
		regexp.MustCompile(`<\|im_(?:start|end)\|>`),
		regexp.MustCompile(`\[/?INST\]`),
		regexp.MustCompile(`<<SYS>>|<</SYS>>`),
	}
)

func init() {
	InitRestrictedTerms([]string{"tsmc"})
}

// InitRestrictedTerms compiles the regexes used both by the PII redactor
// (word-boundary + .com-suffix variants → `[REDACTED_COMPANY]`) and by the
// tool-checker (case-insensitive substring match). Safe to call repeatedly.
// Empty/whitespace terms are skipped; if no usable term remains, the
// patterns are cleared and matching becomes a no-op.
func InitRestrictedTerms(terms []string) {
	cleaned := make([]string, 0, len(terms))
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		cleaned = append(cleaned, t)
	}

	restrictedTermsMu.Lock()
	defer restrictedTermsMu.Unlock()

	if len(cleaned) == 0 {
		restrictedDomainRE = nil
		restrictedWordRE = nil
		restrictedSubstringREs = nil
		restrictedTermsLower = nil
		return
	}

	quoted := make([]string, len(cleaned))
	lowered := make([]string, len(cleaned))
	subs := make([]*regexp.Regexp, len(cleaned))
	for i, t := range cleaned {
		quoted[i] = regexp.QuoteMeta(t)
		lowered[i] = strings.ToLower(t)
		subs[i] = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(t))
	}
	alt := strings.Join(quoted, "|")

	restrictedDomainRE = regexp.MustCompile(`(?i)\b(?:` + alt + `)\.com\b`)
	restrictedWordRE = regexp.MustCompile(`(?i)\b\w*(?:` + alt + `)\w*\b`)
	restrictedSubstringREs = subs
	restrictedTermsLower = lowered
}

func snapshotRestrictedRedactors() (*regexp.Regexp, *regexp.Regexp) {
	restrictedTermsMu.RLock()
	defer restrictedTermsMu.RUnlock()
	return restrictedDomainRE, restrictedWordRE
}

func snapshotRestrictedSubstrings() []*regexp.Regexp {
	restrictedTermsMu.RLock()
	defer restrictedTermsMu.RUnlock()
	return restrictedSubstringREs
}
