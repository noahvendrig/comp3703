#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int f2(int x, int y)
{
    int e = y * y - x - 9; 
    int f = y/e; 
    return f; 
}

int f1(int a, int b)
{
    int x = a*a;
    f2(x,b);
}

int main(int argc, char * argv[])
{
    int a; 
    int r; 
    int i; 
    if(argc < 2)
    {
        printf("Usage: %s <num>\n", argv[0]);
        return 0; 
    }
    a = atoi(argv[1]);
    srand((unsigned) time(0));
    if (a == 0) {
        for(i=0; i < 10; ++i)
        {
            a = rand() % 10 ;
            r = f1(a, 5); 
        }
    }
    else r = f1(a % 10, 5); 
    printf("Result: %d\n", r); 
    return 0; 
}
