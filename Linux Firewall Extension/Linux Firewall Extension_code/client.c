#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFERLENGTH 200

/* Reads a file and passes its content line by line to the kernel */
int main (int argc, char **argv) {
    
    FILE *inputFile;
    int procFileFd;
    size_t len;
    char *line = NULL;
    char *filename;
    char *string;
    char* p = NULL;
    int i = 0;
    
    if(3 == argc) {
        
        if(0 != strcmp(argv[1], "W")) {
            fprintf (stderr, "Usage: %s L\n", argv[0]);
            fprintf (stderr, "Usage: %s W <input file>\n", argv[0]);
            exit (1);
        }
        
        inputFile = fopen (argv[2], "r"); /* open the input file for reading */
        procFileFd = open ("/proc/kernelWrite", O_WRONLY); /* open the proc-file for writing */
        
        if (!inputFile || (procFileFd == -1)) {
            fprintf (stderr, "Opening failed!\n");
            exit (1);
        }
        while (getline (&line, &len, inputFile) != -1) {
            string = malloc(sizeof(char)*BUFFERLENGTH);
            strcpy(string, line);
            while((p = strsep(&string, " \n\r")) != NULL) {
                if(i == 0) {
                    printf("port is: %d\n", atoi(p));
                    if (atoi(p) == 0) {
                        i = -1;
                        continue;
                    }
                    i++;
                } else if(i == 1) {
                    printf("filename is: %s\n", p);
                    filename = p;
                    if(access(filename, X_OK)!=0) {
                        printf("the file is wrong \n");
                        i = -1;
                        continue;
                    }
                    i++;
                }
            }
            
            if(i >= 2) {
                write (procFileFd, line, len); /* write line to kernel */
            }
            i = 0;
            free (line);
            free(string);
            string = NULL;
            line = NULL;
        }
        
        close (procFileFd); /* make sure data is properly written */
        fclose (inputFile);
        
        exit (0);
    } else if (2 == argc) {
        if(0 != strcmp(argv[1], "L")) {
            fprintf (stderr, "Usage: %s L\n", argv[0]);
            fprintf (stderr, "Usage: %s W <input file>\n", argv[0]);
            exit (1);
        }
        procFileFd = open ("/proc/kernelWrite", O_RDONLY); /* open the proc-file for writing */
        
        if ((procFileFd == -1)) {
            fprintf (stderr, "Opening failed!\n");
            exit (1);
        }
        read (procFileFd, NULL, 0); /* write line to kernel */
        
        close (procFileFd); /* make sure data is properly written */
        
        exit (0);
    } else {
        fprintf (stderr, "Usage: %s L\n", argv[0]);
        fprintf (stderr, "Usage: %s W <input file>\n", argv[0]);    
        exit (1);
    }
    
}
