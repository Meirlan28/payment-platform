// Package schemamigration owns how a migration file becomes statements and
// how their application is tracked.
//
// The splitter lives here rather than in the migrator binary because the tests
// that claim to verify the migration set must run the same code the migrator
// runs. A test that applied migrations its own way would prove something about
// that other way, and CockroachDB does not make a column added earlier in a
// batch visible to a later statement in it — so applying a whole file at once
// fails on migrations the real migrator applies without trouble.
package schemamigration

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"unicode/utf8"
)

// Statement is one reviewed statement from a migration file, with the checksum
// recorded when it is applied.
type Statement struct {
	Ordinal  int64
	Contents string
	Checksum [sha256.Size]byte
}

// Split is a conservative SQL lexical splitter. It honors
// quoted identifiers, standard/E strings, nested block comments and tagged or
// untagged dollar quotes used by PL/pgSQL bodies. It does not try to parse SQL;
// it only recognizes semicolons that are outside those lexical constructs.
func Split(contents []byte) ([]Statement, error) {
	var result []Statement
	start := 0
	inSingle := false
	singleBackslashEscapes := false
	inDouble := false
	lineComment := false
	blockDepth := 0
	dollarTag := ""

	for index := 0; index < len(contents); {
		if lineComment {
			if contents[index] == '\n' {
				lineComment = false
			}
			index++
			continue
		}
		if blockDepth > 0 {
			if index+1 < len(contents) && contents[index] == '/' && contents[index+1] == '*' {
				blockDepth++
				index += 2
				continue
			}
			if index+1 < len(contents) && contents[index] == '*' && contents[index+1] == '/' {
				blockDepth--
				index += 2
				continue
			}
			index++
			continue
		}
		if dollarTag != "" {
			if bytes.HasPrefix(contents[index:], []byte(dollarTag)) {
				index += len(dollarTag)
				dollarTag = ""
				continue
			}
			index++
			continue
		}
		if inSingle {
			if singleBackslashEscapes && contents[index] == '\\' && index+1 < len(contents) {
				index += 2
				continue
			}
			if contents[index] == '\'' {
				if index+1 < len(contents) && contents[index+1] == '\'' {
					index += 2
					continue
				}
				inSingle = false
				singleBackslashEscapes = false
			}
			index++
			continue
		}
		if inDouble {
			if contents[index] == '"' {
				if index+1 < len(contents) && contents[index+1] == '"' {
					index += 2
					continue
				}
				inDouble = false
			}
			index++
			continue
		}

		if index+1 < len(contents) && contents[index] == '-' && contents[index+1] == '-' {
			lineComment = true
			index += 2
			continue
		}
		if index+1 < len(contents) && contents[index] == '/' && contents[index+1] == '*' {
			blockDepth = 1
			index += 2
			continue
		}
		switch contents[index] {
		case '\'':
			inSingle = true
			singleBackslashEscapes = escapeStringPrefix(contents, index)
			index++
			continue
		case '"':
			inDouble = true
			index++
			continue
		case '$':
			if index == 0 || !identifierByte(contents[index-1]) {
				if tag, ok := readDollarTag(contents[index:]); ok {
					dollarTag = tag
					index += len(tag)
					continue
				}
			}
		case ';':
			appendStatement(&result, contents[start:index+1])
			start = index + 1
		}
		index++
	}
	if inSingle || inDouble || blockDepth != 0 || dollarTag != "" {
		return nil, errors.New("migration contains an unterminated SQL lexical construct")
	}
	appendStatement(&result, contents[start:])
	if len(result) == 0 {
		return nil, errors.New("migration contains no SQL statements")
	}
	return result, nil
}

func escapeStringPrefix(contents []byte, quote int) bool {
	if quote >= 1 && (contents[quote-1] == 'e' || contents[quote-1] == 'E') &&
		(quote == 1 || !identifierByte(contents[quote-2])) {
		return true
	}
	return quote >= 2 && contents[quote-1] == '&' &&
		(contents[quote-2] == 'u' || contents[quote-2] == 'U') &&
		(quote == 2 || !identifierByte(contents[quote-3]))
}

func identifierByte(character byte) bool {
	return (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') || character == '_' ||
		character == '$' || character >= utf8.RuneSelf
}

func readDollarTag(contents []byte) (string, bool) {
	if len(contents) == 0 || contents[0] != '$' {
		return "", false
	}
	for index := 1; index < len(contents); index++ {
		if contents[index] == '$' {
			return string(contents[:index+1]), true
		}
		character := contents[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9' && index > 1) || character == '_') {
			return "", false
		}
	}
	return "", false
}

func appendStatement(result *[]Statement, raw []byte) {
	statement := strings.TrimSpace(string(raw))
	if statement == "" {
		return
	}
	checksum := sha256.Sum256([]byte(statement))
	*result = append(*result, Statement{
		Ordinal: int64(len(*result) + 1), Contents: statement, Checksum: checksum,
	})
}
