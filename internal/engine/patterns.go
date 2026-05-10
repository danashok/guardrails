package engine

import "regexp"

var (
	ssnRE    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccRE     = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	emailRE  = regexp.MustCompile(`\b[\w.+-]+@[\w-]+\.[\w.-]+\b`)
	phoneRE  = regexp.MustCompile(`\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
	apiKeyRE = regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`)

	tsmcDomainRE = regexp.MustCompile(`(?i)\btsmc\.com\b`)
	tsmcWordRE   = regexp.MustCompile(`(?i)\b\w*tsmc\w*\b`)

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
