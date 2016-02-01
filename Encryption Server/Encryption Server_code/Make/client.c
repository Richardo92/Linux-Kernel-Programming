#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define BUFFERLENGTH 256
#define FILE_NAME_MAX_SIZE 512 
#define PASSPHRASE_MAX_SIZE 64
#define COMMAND_MAX_SIZE 32

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[BUFFERLENGTH];
    if (argc < 4) {
       fprintf (stderr, "usage %s --[encrypt/decrypt] [hostname] [port]\n", argv[0]);
       exit(1);
    }
   
    /* create socket */
    portno = atoi (argv[3]);
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error ("ERROR opening socket");

    /* enter connection data */
    server = gethostbyname (argv[2]);
    if (server == NULL) {
        fprintf (stderr, "ERROR, no such host\n");
        exit (1);
    }
    bzero ((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy ((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons (portno);

    /* connect to the server */
    if (connect (sockfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0) 
        error ("ERROR connecting");

    /* prepare the command   */
    char command[COMMAND_MAX_SIZE + 1];
    bzero(command, sizeof(command)); 
    strcpy(command,argv[1]);
    bzero (buffer, BUFFERLENGTH);
    strncpy(buffer, command, strlen(command) > BUFFERLENGTH ? BUFFERLENGTH : strlen(command));

    /* send the command */
    n = write (sockfd, buffer, strlen(buffer));
    if (n < 0) 
         error ("ERROR writing to socket");
    bzero (buffer, BUFFERLENGTH);  

    /* prepare file_name */
    char file_name[FILE_NAME_MAX_SIZE + 1];  
    bzero(file_name, sizeof(file_name)); 
    printf("RULE:\n");
    printf("If your file needs to be encrypted,just send the filename. [xxx.txt]\n"); 
    printf("If your file needs to be decrypted,just send the source filename.Still [xxx.txt]\n");
    printf ("Please enter the filename: ");
    scanf("%s",file_name);
    bzero (buffer, BUFFERLENGTH);
    strncpy(buffer, file_name, strlen(file_name) > BUFFERLENGTH ? BUFFERLENGTH : strlen(file_name));

    /* send file_name */
    n = write (sockfd, buffer, strlen(buffer));
    if (n < 0) 
         error ("ERROR writing to socket");
    bzero (buffer, BUFFERLENGTH);

    /* wait the feedback of whether several threads are encrypting/decrypting a same file*/
    //wait for the feedback
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
        error ("ERROR reading from socket");
    /* test the feedback */
    if (strcmp ("Sametime", buffer) == 0) // several threads are encrypting or decrypting the same file
    {
	printf("ERROR! Several threads are encrypting or decrypting the same file.\n");
	return 0;
    }
    else if (strcmp ("noSametime", buffer) == 0)  // encryting or decryting the file on his own
    {
	printf("Good! You are just encryting or decryting the file on your own\n");
    }

    /* prepare passphrase */
    char passphrase[PASSPHRASE_MAX_SIZE + 1]; 
    bzero(passphrase, sizeof(passphrase));  
    printf ("Please enter the passphrase: ");
    scanf("%s",passphrase);
    bzero (buffer, BUFFERLENGTH);
    strncpy(buffer, passphrase, strlen(passphrase) > BUFFERLENGTH ? BUFFERLENGTH : strlen(passphrase));
  

    /* send passphrase */
    n = write (sockfd, buffer, strlen(buffer));
    if (n < 0) 
         error ("ERROR writing to socket");
    bzero (buffer, BUFFERLENGTH);

    //wait for the feedback
    n = read (sockfd, buffer, BUFFERLENGTH -1);
    if (n < 0) 
        error ("ERROR reading from socket");
    
    /* test the feedback */
    if (strcmp ("true", buffer) == 0) //the file which needs to be encrypted has already been on the server
    {
        printf("%s and passphrase have both been received.\n",file_name);
        printf("And the %s has already been on the server.\n",file_name);
        bzero(buffer, BUFFERLENGTH);  
    }
    else if(strcmp ("false", buffer) == 0) //the file which needs to be encrypted does not exist on the server
    {
        printf("%s and passphrase have both been received.\n",file_name);
        printf("But %s does not exist on the server.\n",file_name);
        printf("The client program will check whether %s is on the client.\n",file_name);
       
        //send file
        FILE *fp = fopen(file_name, "r");  
        if (fp == NULL)  // the file does not exist on the client,either 
        {  
            printf("ERROR! File:\t%s Not Found on the client!\n", file_name);

	    /* prepare a feedback */
            char feedback[30] = "nExistOnClient";
            bzero (buffer, BUFFERLENGTH);
            strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

           /* send the feedback */
           n = write (sockfd, buffer, strlen(buffer));
           if (n < 0) 
            	error ("ERROR writing to socket");
           bzero (buffer, BUFFERLENGTH); 

	   return 0;  
        }  
        else  // the file does exist on the client
        {  
            /* prepare a feedback */
            char feedback[30] = "ExistOnClient";
            bzero (buffer, BUFFERLENGTH);
            strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

           /* send the feedback */
           n = write (sockfd, buffer, strlen(buffer));
           if (n < 0) 
            	error ("ERROR writing to socket");
           
            /* send the file */
            bzero(buffer, BUFFERLENGTH);  
            int file_block_length = 0;  
            while( (file_block_length = fread(buffer, sizeof(char), BUFFERLENGTH, fp)) > 0)  
            {     
                if (send(sockfd, buffer, file_block_length, 0) < 0)  
                {  
                    printf("Send File:\t%s Failed!\n", file_name);  
                    break;  
                }  
  
                bzero(buffer, sizeof(buffer));  
            }  
            fclose(fp);  
            printf("File: %s Transfer Finished!\n", file_name);  
        }  
    }
    else if(strcmp("encrypted", buffer) == 0)  // the file which needs to be encrypted has already been encrypted on the server
    {
	printf("ERROR! The %s has already been encrypted on the server!\n",file_name);
    }
    else if(strcmp("yes_gpg", buffer) == 0)  // the file.gpg which needs to be decrypted has already been on the server
    {
	printf("The %s.gpg has already been on the server.\n",file_name);
    }
    else if(strcmp("no_gpg", buffer) == 0)  // the file.gpg which needs to be decrypted does not exist on the server
    {
	printf("ERROR!The %s is not encrypted on the server.\n",file_name);
    }
    else if (strcmp("invalid", buffer) == 0)  // invalid command
    {
	printf("INVALID COMMAND!\n");
    }

    bzero (buffer, BUFFERLENGTH);
   
    close(sockfd);
    return 0;
}
