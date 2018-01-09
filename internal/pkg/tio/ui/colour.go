package ui

import (
	"github.com/mgutz/ansi"
)

var BOLD = ansi.ColorCode("white+bh:black")
var RESET = ansi.ColorCode("reset")
var GREEN = ansi.ColorCode("green+b:black")
var YELLOW = ansi.ColorCode("yellow+h:black")
var RED = ansi.ColorCode("red+bh:black")
var GREY = ansi.ColorCode("white+bh:black")
var GRAY = GREY

var CRUNNING = ansi.ColorCode("green+b:black")
var CNEVER = ansi.ColorCode("black:white+h")

var CCRIT = ansi.ColorCode("white+h:red+b")
var CHIGH = ansi.ColorCode("red+h:black+b")
var CMED = ansi.ColorCode("black:yellow+h")
var CCNT = ansi.ColorCode("black:white+h")

func DisableColour() {
	BOLD = ""
	RESET = ""
	GREEN = ""
	YELLOW = ""
	RED = ""
	GREY = ""
	GRAY = ""
	CRUNNING = ""
	CNEVER = ""
	CCRIT = ""
	CHIGH = ""
	CMED = ""
	CCNT = ""
}
