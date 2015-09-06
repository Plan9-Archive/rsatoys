#include <u.h>
#include <libc.h>
#include <bio.h>
#include <auth.h>
#include <mp.h>
#include <libsec.h>

RSApub *getpub(int argc, char **argv);

RSApub*
getpub(int argc, char **argv)
{
	char *file, *s, *p;
	int sz;
	RSApub *key;
	Biobuf *b;
	Attr *a;

	if(argc == 0)
		file = "#d/0";
	else
		file = argv[0];

	key = mallocz(sizeof(RSApriv), 1);
	if(key == nil)
		return nil;

	if((b = Bopen(file, OREAD)) == nil){
		werrstr("open %s: %r", file);
		return nil;
	}
	s = Brdstr(b, '\n', 1);
	if(s == nil){
		werrstr("read %s: %r", file);
		return nil;
	}
	if(strncmp(s, "key ", 4) != 0){
		werrstr("bad key format");
		return nil;
	}

	a = _parseattr(s+4);
	if(a == nil){
		werrstr("empty key");
		return nil;
	}
	if((p = _strfindattr(a, "proto")) == nil){
		werrstr("no proto");
		return nil;
	}
	if(strcmp(p, "rsa") != 0){
		werrstr("proto not rsa");
		return nil;
	}
	if((p = _strfindattr(a, "ek")) == nil){
		werrstr("no ek");
		return nil;
	}
	if((key->ek = strtomp(p, &p, 16, nil)) == nil || *p != 0){
		werrstr("bad ek");
		return nil;
	}
	if((p = _strfindattr(a, "n")) == nil){
		werrstr("no n");
		return nil;
	}
	if((key->n = strtomp(p, &p, 16, nil)) == nil || *p != 0){
		werrstr("bad n");
		return nil;
	}
	if((p = _strfindattr(a, "size")) == nil)
		fprint(2, "warning: missing size; will add\n");
	else if((sz = strtol(p, &p, 10)) == 0 || *p != 0)
		fprint(2, "warning: bad size; will correct\n");
	else if(sz != mpsignif(key->n))
		fprint(2, "warning: wrong size (got %d, expected %d); will correct\n",
			sz, mpsignif(key->n));

	a = _delattr(a, "ek");
	a = _delattr(a, "n");
	a = _delattr(a, "size");
	return key;
}

void
main(int argc, char **argv)
{
	int n;
	char *p;
	uchar buf[65535];
	Biobuf b;
	RSApub *rsapub;
	mpint *clr, *enc;
	char **publoc;

	fmtinstall('B', mpfmt);

	publoc = (char**)malloc(sizeof(publoc));
	publoc[0] = (char*)malloc(7);
	sprint(publoc[0], "rsapub");

	if(argc == 1)
		rsapub = getpub(1, publoc);
	else
		rsapub = getpub(1, &argv[1]);
	if(rsapub == nil)
		sysfatal("pub read failed");
	Binit(&b, 0, OREAD);
	clr = mpnew(0);
	enc = mpnew(0);

	p = Brdline(&b, '\n');
	strtomp(p, nil, 16, enc);		
	rsaencrypt(rsapub, enc, clr);
	n = mptole(clr, buf, sizeof(buf), nil);
	write(1, buf, n);

}

/* incorporates code taken from the plan 9 rsa libs and auth utilities */
