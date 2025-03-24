#include <stdio.h>
#include <stdlib.h>

void surreal(int x)
{
    asm volatile ("add $1, %rsp"); 

    char msg[]="You have outdone yourself, young Padawan!";
    if (x == 1234)
    {
        printf("%s\n", msg);
        exit(1); 
    }
    else printf("You are sooo close! Try again, Grasshopper\n!"); 
}

void notexist(int x)
{
    if(x == 42) {
        printf("I don't even exist, how can you reach me?\n"); 
    }
    exit(1); 
}

void unreachable()
{
    printf("You have reached the unreachable, well done!\n");
    exit(1); 
}

int main(int argc, char* argv[])
{
    int x = 0;
    if(x == 1) {
        unreachable();
    }
    else printf("Nothing to see here; move along folks\n"); 
}