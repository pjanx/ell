if exists("b:current_syntax")
	finish
endif

syn iskeyword 1-255,^[,^],^{,^},^(,^),^;,^@-@,^#,^',^9,^10,^13,^32
syn keyword ellSTL local set list values if map print .. system parse try throw
	\ + - * / not and or eq? lt? = < unless filter for break
	\ ne? le? ge? gt? <> <= >= >

syn match ellComment "#.*"
syn match ellSpecial "[][}{)(;@]"
syn match ellVar "\(@[\t ]*\)\@<=\k\+"
syn match ellEscape display "\\\([xX]\x\{2}\|.\|$\)" contained
syn region ellString start=+'+ skip=+\\\\\|\\'+ end=+'+ contains=ellEscape

let b:current_syntax = "ell"
hi def link ellSTL Function
hi def link ellComment Comment
hi def link ellSpecial Special
hi def link ellVar Identifier
hi def link ellEscape SpecialChar
hi def link ellString String
