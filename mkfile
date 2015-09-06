</$objtype/mkfile
BIN=/$objtype/bin
TARG=rsaenc rsadec rsasign rsaverify preenc postdec
</sys/src/cmd/mkmany
install:V:
	cp sign /rc/bin/sign
	cp verify /rc/bin/verify
	cp encrypt /rc/bin/encrypt
	cp decrypt /rc/bin/decrypt
	cp encsign /rc/bin/encsign
	cp verifdec /rc/bin/verifdec

