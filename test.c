#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define FILE_NAME    "arquivo.txt"
#define STRLEN       500

int main(int argc, char ** argv)
{
    char entry[STRLEN];
    int size = 0;

    FILE * fp;

    fp = fopen(FILE_NAME,"r+")

    if (fp == NULL)
    {
        printf('Unable to open file %s', FILE_NAME);
        return errno;
    }
    
    printf('Digite uma palavra ou frase para criptografar no arquivo de teste: ');
    scanf("%[^\n]%*c", entry);
    size = strlen(entry);

    fclose(FILE_NAME);
    return 0;
}