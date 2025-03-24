#include <stdio.h>


int main()
{
   char *arr[] = {"Option 1", "Option 2"}; 
   int i;
   printf("You have two options: \n");
   printf("[1] %s\n", arr[0]);
   printf("[2] %s\n", arr[1]);
   printf("Enter 1 or 2: "); 
   scanf("%d", &i);
   if(i<1 || i>2) 
      return 0;

   printf("So you have chosen: %s\n", arr[i]); 

   return 0; 
}


