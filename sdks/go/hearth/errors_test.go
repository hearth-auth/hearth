package hearth

import (
	"errors"
	"testing"
)

func TestRequiredActionErrorFields(t *testing.T) {
	e := &RequiredActionError{
		RequiredActions: []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"},
		RedirectURI:     "https://auth.example.com/required-actions",
	}
	if len(e.RequiredActions) != 2 {
		t.Errorf("RequiredActions len: %d", len(e.RequiredActions))
	}
	if e.RequiredActions[0] != "VERIFY_EMAIL" {
		t.Errorf("RequiredActions[0] = %q", e.RequiredActions[0])
	}
	if e.RedirectURI != "https://auth.example.com/required-actions" {
		t.Errorf("RedirectURI = %q", e.RedirectURI)
	}
}

func TestRequiredActionErrorMessage(t *testing.T) {
	e := &RequiredActionError{
		RequiredActions: []string{"VERIFY_EMAIL"},
	}
	msg := e.Error()
	if msg == "" {
		t.Error("Error() should return non-empty message")
	}
}

func TestRequiredActionErrorOptionalRedirectURI(t *testing.T) {
	e := &RequiredActionError{
		RequiredActions: []string{"UPDATE_PASSWORD"},
	}
	if e.RedirectURI != "" {
		t.Errorf("RedirectURI should default to empty, got %q", e.RedirectURI)
	}
}

func TestRequiredActionErrorImplementsError(t *testing.T) {
	var err error = &RequiredActionError{RequiredActions: []string{"VERIFY_EMAIL"}}
	var rae *RequiredActionError
	if !errors.As(err, &rae) {
		t.Error("errors.As should match *RequiredActionError")
	}
}

func TestRequiredActionErrorEmptyActions(t *testing.T) {
	// Must not panic when RequiredActions is empty.
	e := &RequiredActionError{}
	_ = e.Error()
}
