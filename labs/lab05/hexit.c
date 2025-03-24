// HEXIT
// A simple (and flawed) program to display the bytes of a file in hexadecimal. 
// This can be used to demonstrate a classic buffer overflow attack. 
// Copyright (c) 2022-2025 Alwen Tiu 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t nread=0; 
unsigned int offset = 0; 

void printhex(char * buffer)
{
  int i; 

  for(i=0; i < nread; ++i)
  {
    if(i % 16 == 0) {
      printf("\n%08x: ", offset);
      offset += 16;   
    }
    printf("%.02x ",(unsigned char)(buffer[i]) & 0xff);
  }
  printf("\n");  
}

void process_stdin(size_t blocksize) 
{
  char read_buffer[256];
  int i; 
  nread = blocksize; 
  offset = 0; 
  if(fgets(read_buffer, blocksize, stdin))
  {
    for(i = 0; i < blocksize; ++i)
      if(read_buffer[i] == '\n')
        break; 
    nread = i; 
    printhex(read_buffer);  
  }
}

void process_file(FILE *fp, size_t blocksize) 
{
  char read_buffer[256];

  nread = fread(read_buffer, sizeof(char), blocksize, fp); 
  
  while(nread != 0) 
  {
    printhex(read_buffer); 
    nread = fread(read_buffer, sizeof(char), blocksize, fp); 
    if(feof(fp) || ferror(fp))
      break; 
  }
  fclose(fp); 

}

int main(int argc, char* argv[]) 
{
  FILE *fp;
  int blocksize; 

  setbuf(stdin,NULL);
  setbuf(stdout,NULL);
  setbuf(stderr,NULL);

  if(argc < 2) {
    fprintf(stderr, "Usage: %s <blocksize> <filename>\n", argv[0]);
    exit(1);
  }
  blocksize = atoi(argv[1]); 

  if(argc >= 3)
  {
    fp = fopen(argv[2], "rb");

    if(!fp) {
      fprintf(stderr, "File %s does not exist\n", argv[2]);
      return 1;
    }
    process_file(fp, blocksize);
  } 
  else {
    process_stdin(blocksize); 
  }

  return 0;
}
