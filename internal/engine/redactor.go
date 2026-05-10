package engine

type BlockKind string

const (
	BlockPromptInjection BlockKind = "PROMPT_INJECTION"
)

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
// SSN and CC run before phone so their digit patterns are consumed first;
// the company-domain pattern runs before the bare-word pattern so
// "tsmc.com" is not partially consumed by the word match.
func Redact(text string) string {
	text = ssnRE.ReplaceAllString(text, "[REDACTED_SSN]")
	text = ccRE.ReplaceAllStringFunc(text, func(m string) string {
		if Luhn(m) {
			return "[REDACTED_CREDIT_CARD]"
		}
		return m
	})
	text = emailRE.ReplaceAllString(text, "[REDACTED_EMAIL]")
	text = phoneRE.ReplaceAllString(text, "[REDACTED_PHONE]")
	text = apiKeyRE.ReplaceAllString(text, "[REDACTED_API_KEY]")
	text = tsmcDomainRE.ReplaceAllString(text, "[REDACTED_COMPANY]")
	text = tsmcWordRE.ReplaceAllString(text, "[REDACTED_COMPANY]")
	text = nameTitleRE.ReplaceAllString(text, "[REDACTED_NAME]")
	text = nameFullRE.ReplaceAllString(text, "[REDACTED_NAME]")
	return text
}
