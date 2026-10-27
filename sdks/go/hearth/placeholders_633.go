package hearth

import (
	"context"
	"time"
)

// Placeholders so that the #633 tests compile and fail on behaviour, not on a
// missing name. The fix commit replaces this file with the real definitions.

// DefaultHTTPTimeout is a placeholder (#633): no client uses it yet.
const DefaultHTTPTimeout = 10 * time.Second

// WithHTTPTimeout is a placeholder (#633) that changes nothing.
func WithHTTPTimeout(time.Duration) ClientOption { return func(*Client) {} }

// ClaimsFromContext is a placeholder (#633): no claims are stored yet.
func ClaimsFromContext(context.Context) (*Claims, bool) { return nil, false }
