#include <stdio.h>
#include <stdlib.h>

int main(void) {
	FILE *pp,*in,*result;
	char out_name[128];
	int i,j;
	for(i=32;i<321;i+=32)
	{
	for(j=32;j<513;j+=32)
	{
	char command[128];
	sprintf(command,"sudo ./genaparam %d %d",i,j);
	sprintf(out_name,"%d_%d.param",i,j);
	result = fopen(out_name,"wb");
	printf("i = %d, j= %d\n",i,j);

	//run pipe and get the result. 
		pp = popen(command, "r");
		if (pp != NULL) {
		while (1) {
			char *line;
			char buf[1000];
			line = fgets(buf, sizeof(buf), pp);
			if (line == NULL) break;
		
			///if (1) printf("%s", line); /* line includes '\n' */
			fwrite(buf,1,strlen(buf),result);
			}
		pclose(pp);
			}
				fclose(result);
		}
	}

	return 0;
}
