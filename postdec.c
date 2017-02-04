#include <u.h>
#include <libc.h>

void
main(int argc,char *argv[])
{
	char buf[2];
	int len;
	ulong out;
	int n;

newchunk:
	/* read and ignore pkcs1.5 padding */
	n=read(0,buf,2);
	if(n==0)
		exits(nil);
	if(n==1)
		read(0,buf+1,1);
	if(strncmp(buf,"02",2)!=0){
		fprint(2,"padding length error\n");
		exits(nil);
	}
	len=2;
	while(strncmp(buf,"00", 2) != 0){
		n=read(0,buf,2);
		if(n==1)
			read(0,buf+1,1);
		len+=2;
	}
	/* convert from text-hex to original data */
	out=0;
	while(n=read(0,buf,2)){
		if(n==1)
			read(0,buf+1,1);
		out=strtoul(buf,nil,16);
		write(1,&out,1);
		len+=2;
		if(len==64)
			goto newchunk;
	}
}
