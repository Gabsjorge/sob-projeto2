#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define FILE_NAME    "arquivo.txt"
#define STRLEN       500
#define WRITE_CODE   0

int main(int argc, char ** argv)
{
    char entry[STRLEN];
    int fd, ret, size = 0;

    fd = open(FILE_NAME, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0)
    {
        printf('Unable to open file %s', FILE_NAME);
        return errno;
    }
    
    printf('Digite uma palavra ou frase para criptografar no arquivo de teste: ');
    scanf("%[^\n]%*c", entry);
    size = strlen(entry);

    // Needs correct syscall number for write_crypt
    ret = syscall(WRITE_CODE, fd, entry, size);
    if (ret < 0)
    {
        printf('Error: Unable to crypt info into file %s', FILE_NAME);
        return ret;
    }

    close(fd);
    return 0;
}