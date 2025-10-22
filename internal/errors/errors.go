package errors

import "fmt"

type Severity uint8

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

	return "Unknown"
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

type Kind uint8

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
	return "Unknown"
}

const (
	// For unepxected events
	KindUnexpected = iota
	// For not found events, such as resource not found
	KindNotFound
	// For any kind of invalid input, e.g., func arguments or request body
	KindInvalidInput
	// For any action that is not allowed by user
	KindUnauthorized
)

type Error struct {
	// The operation, e.g., "db.GetUser"
	Op string
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
