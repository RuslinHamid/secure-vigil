// Enter your code here
// C program to implement
// the above approach
#include <stdio.h>
#define MAX 15

// Driver code
int main()
{
	char buf[MAX];
	fgets(buf, MAX, stdin);
	printf("%s", buf);
	return 0;
}
