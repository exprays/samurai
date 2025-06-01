package auth

// PasswordPolicy defines configurable password requirements
type PasswordPolicy struct {
	MinLength           int  `json:"min_length"`
	MaxLength           int  `json:"max_length"`
	RequireUppercase    bool `json:"require_uppercase"`
	RequireLowercase    bool `json:"require_lowercase"`
	RequireNumbers      bool `json:"require_numbers"`
	RequireSpecialChars bool `json:"require_special_chars"`
	ForbidCommon        bool `json:"forbid_common"`
	MinScore            int  `json:"min_score"`
}

// DefaultPasswordPolicy returns the default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:           8,
		MaxLength:           128,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: true,
		ForbidCommon:        true,
		MinScore:            3,
	}
}

// RelaxedPasswordPolicy returns a more relaxed password policy
func RelaxedPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:           6,
		MaxLength:           128,
		RequireUppercase:    false,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: false,
		ForbidCommon:        true,
		MinScore:            2,
	}
}

// StrictPasswordPolicy returns a strict password policy
func StrictPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:           12,
		MaxLength:           128,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: true,
		ForbidCommon:        true,
		MinScore:            4,
	}
}
