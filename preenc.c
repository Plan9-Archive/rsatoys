#include <u.h>
#include <libc.h>

void
main(int argc, char *argv[])
{
	uchar buf[1];
	int reps;
	int len;
	srand(time(0));

newchunk:
	/* print rfc2437 pkcs1.5 padding */
	reps=(nrand(8)*2);
	print("02");
	for(len=2; len<(18+reps); len++)
		print("%x", nrand(14)+1);
	print("00");
	len+=2;
	/* convert input to human readable hex */
	while(read(0,buf,1)){
		print("%.2ux",buf[0]);
		len+=2;
		if(len==64)
			goto newchunk;
	}
}
