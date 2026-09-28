package hearth

import (
	"errors"
	"testing"
)

func TestRequiredActionErrorFields(t *testing.T) {
	e := &RequiredActionError{
		RequiredActions: []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"},
	}
	if len(e.RequiredActions) != 2 {
		t.Errorf("RequiredActions len: %d", len(e.RequiredActions))
	}
	if e.RequiredActions[0] != "VERIFY_EMAIL" {
		t.Errorf("RequiredActions[0] = %q", e.RequiredActions[0])
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

func TestRequiredActionErrorImplementsError(t *testing.T) {
	var err error = &RequiredActionError{RequiredActions: []string{"VERIFY_EMAIL"}}
	var rae *RequiredActionError
	if !errors.As(err, &rae) {
		t.Error("errors.As should match *RequiredActionError")
	}
}

func TestRequiredActionErrorEmptyActions(t *testing.T) {
	// Must not panic when RequiredActions is empty, and must still return the
	// stable "required action pending: []" message.
	e := &RequiredActionError{}
	msg := e.Error()
	if msg == "" {
		t.Fatal("Error() must return a non-empty message even with no actions")
	}
	if msg != "required action pending: []" {
		t.Fatalf("unexpected message for empty actions: %q", msg)
	}
}
