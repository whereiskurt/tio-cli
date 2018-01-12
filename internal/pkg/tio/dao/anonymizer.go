package dao

import (
	"github.com/whereiskurt/tio-cli/internal/pkg/tio"
)

type Anonymizer struct {
	Log *tio.Logger
}

func NewAnonymizer() (a *Anonymizer) {
	a = new(Anonymizer)
	return a
}
