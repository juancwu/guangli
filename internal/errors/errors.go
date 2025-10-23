package errors

import (
	"fmt"
	"net/http"
)

type Op string

type Severity int

func (severity Severity) String() string {
	switch severity {
	case SeverityInfo:
		return "Info"
	case SeverityDebug:
		return "Debug"
	case SeverityWarning:
		return "Warning"
	case SeverityError:
		return "Error"
	}

	return fmt.Sprintf("Severity(%d)", severity)
}

const (
	SeverityDebug Severity = iota
	// SeverityInfo is for anything that provides extra information
	// but doesn't need extra attention from developers.
	SeverityInfo
	// SeverityWarning is for things that went wrong but do not cause a system failure.
	SeverityWarning
	// SeverityError is for unexpected system failures
	SeverityError
)

type Kind int

func (kind Kind) String() string {
	switch kind {
	case KindUnauthorized:
		return "Unauthorized"
	case KindNotFound:
		return "NotFound"
	case KindInvalidInput:
		return "InvalidInput"
	case KindUnexpected:
		return "Unexpected"
	}
	return fmt.Sprintf("Kind(%d)", kind)
}

const (
	// For unepxected events
	KindUnexpected Kind = http.StatusInternalServerError
	// For not found events, such as resource not found
	KindNotFound Kind = http.StatusNotFound
	// For any kind of invalid input, e.g., func arguments or request body
	KindInvalidInput Kind = http.StatusBadRequest
	// For any action that is not allowed by user
	KindUnauthorized Kind = http.StatusUnauthorized
)

type Error struct {
	// The operation, e.g., "db.GetUser"
	Op Op
	// The category of the error
	Kind Kind
	// The log level
	Severity Severity
	// The original error
	Err error
	// Any application specific data that needs to be logged
	Metadata map[string]any
}

// Implements the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("[%s] op=%s kind=%s: %v", e.Severity.String(), e.Op, e.Kind.String(), e.Err)
}

// Unwrap allows for errors.Is and errors.As
func (e *Error) Unwrap() error {
	return e.Err
}

// E is a helper function to create a new Error
func E(args ...any) *Error {
	e := &Error{}

	for _, arg := range args {
		switch value := arg.(type) {
		case Op:
			e.Op = value
		case Kind:
			e.Kind = value
		case Severity:
			e.Severity = value
		case map[string]any:
			e.Metadata = value
		case error:
			e.Err = value
		default:
			panic("bad call to E")
		}
	}

	return e
}

// StackTrace creates a "stack trace" of operations.
func StackTrace(e *Error) []Op {
	ops := []Op{e.Op}

	subErr, ok := e.Err.(*Error)
	if !ok {
		return ops
	}

	ops = append(ops, StackTrace(subErr)...)

	return ops
}

// GetKind extracts a kind from an error
func GetKind(e error) Kind {
	err, ok := e.(*Error)
	if !ok {
		return KindUnexpected
	}
	return err.Kind
}
