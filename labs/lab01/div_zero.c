#include <stdio.h>
#include <stdlib.h>

int f2(int x, int y)
{
    int e = x % 2; 

    if (e == 0)
    {
        return y/x; 
    }
    return y/(x+1); 
}

int f1(int a, int b)
{
    int x = a+1;
    int y = b-1; 
    f2(x,y);
}

int main(int argc, char * argv[])
{
    int a, b; 

    if(argc < 3)
    {
        printf("Usage: %s <num1> <num2>\n", argv[0]);
        return 0; 
    }
    a = atoi(argv[1]);
    b = atoi(argv[2]);   
    printf("Result: %d\n", f1(a,b)); 
}
