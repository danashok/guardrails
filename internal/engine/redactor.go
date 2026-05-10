package engine

type BlockKind string

const (
	BlockSSN             BlockKind = "SSN"
	BlockCreditCard      BlockKind = "CREDIT_CARD"
	BlockPromptInjection BlockKind = "PROMPT_INJECTION"
)

// CheckPIIBlock returns the BlockKind found, or "" if none.
// Only credit-card matches that pass Luhn count, to keep false positives down.
func CheckPIIBlock(text string) BlockKind {
	if ssnRE.MatchString(text) {
		return BlockSSN
	}
	for _, m := range ccRE.FindAllString(text, -1) {
		if Luhn(m) {
			return BlockCreditCard
		}
	}
	return ""
}

// CheckPromptInjection returns BlockPromptInjection on first signature match, else "".
func CheckPromptInjection(text string) BlockKind {
	for _, re := range promptInjectionREs {
		if re.MatchString(text) {
			return BlockPromptInjection
		}
	}
	return ""
}

// Redact applies all PII redaction rules in order. Order matters:
// the company-domain pattern runs before the bare-word pattern so
// "tsmc.com" is not partially consumed by the word match.
func Redact(text string) string {
	text = emailRE.ReplaceAllString(text, "[REDACTED_EMAIL]")
	text = phoneRE.ReplaceAllString(text, "[REDACTED_PHONE]")
	text = apiKeyRE.ReplaceAllString(text, "[REDACTED_API_KEY]")
	text = tsmcDomainRE.ReplaceAllString(text, "[REDACTED_COMPANY]")
	text = tsmcWordRE.ReplaceAllString(text, "[REDACTED_COMPANY]")
	text = nameTitleRE.ReplaceAllString(text, "[REDACTED_NAME]")
	text = nameFullRE.ReplaceAllString(text, "[REDACTED_NAME]")
	return text
}
