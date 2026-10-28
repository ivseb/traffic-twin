package policy

// CodeAlnumMaxBytes bounds a value of the code shape alnum (sanitizer.md
// 5.6, spec v1.19).
const CodeAlnumMaxBytes = 16

// CodeAlnumValue reports whether s has the code shape alnum
// ^[A-Za-z0-9_.-]{1,16}$ (ASCII only).
func CodeAlnumValue(s []byte) bool {
	if len(s) < 1 || len(s) > CodeAlnumMaxBytes {
		return false
	}
	for _, c := range s {
		if !isAlpha(c) && !isDigit(c) && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// CodeShapeValue reports whether s is a code value for the shape of a code
// action (CodeShapeAlpha or CodeShapeAlnum).
func CodeShapeValue(shape string, s []byte) bool {
	if shape == CodeShapeAlnum {
		return CodeAlnumValue(s)
	}
	return CodeValue(s)
}
