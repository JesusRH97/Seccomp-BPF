#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main (int argc, char *argv[])
{
    int fd=0;

    printf("\n");

    for(int i=0; i<3; i++)
        printf("%d: Hola mundo!\n\n", i+1);

    fd = open("filexxx.txt", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if(fd == -1) {
        perror("Error al crear fichero: ");
        exit(EXIT_FAILURE);
    }

    printf("\n");

    exit(EXIT_SUCCESS);
}