/* A threaded server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#define BUFFERLENGTH 256
#define FILE_NAME_MAX_SIZE 512 
#define PASSPHRASE_MAX_SIZE 64
#define COMMAND_MAX_SIZE 32

// define a single linked list
typedef struct node
{
    char file_name[FILE_NAME_MAX_SIZE + 1]; // use the linked list to record the file_name
    struct node *pNext; // next point
}Node,*pNode;
pNode pHead = NULL; // define the head point in a linked list
     
/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
}


int isExecuted = 0;

pthread_mutex_t mut; /* the lock */

/* the procedure called for each request */
void *processRequest (void *args) {
  int *newsockfd = (int *) args;
  char buffer[BUFFERLENGTH];
  int n;
  int tmp;
  
  /* receive the command */ 
  n = read (*newsockfd, buffer, BUFFERLENGTH -1);
  if (n < 0) 
    error ("ERROR reading from socket");

  printf ("Here is the command: %s\n",buffer);
  char command[COMMAND_MAX_SIZE + 1];  //used to receive the file_name from the buffer 
  bzero(command, sizeof(command));  
  strcpy(command, buffer);
  bzero (buffer, BUFFERLENGTH);

 
  /*  receive filename  */
  n = read (*newsockfd, buffer, BUFFERLENGTH -1);
  if (n < 0) 
    error ("ERROR reading from socket");

  printf ("Here is the filename: %s\n",buffer);
  char file_name[FILE_NAME_MAX_SIZE + 1];  //used to receive the file_name from the buffer 
  bzero(file_name, sizeof(file_name));  
  strcpy(file_name, buffer);
  bzero (buffer, BUFFERLENGTH);

  /* lock the thread resourses */
  pthread_mutex_lock (&mut); 
  
  pNode pTail = pHead;
  while (pTail != NULL)
  {
	if(strcmp(pTail->file_name,file_name) == 0)
	{
		printf("ERROR! Several threads are encrypting or decrypting the same file.\n");

		/* prepare a feedback */
            	char feedback[15] = "Sametime";
            	bzero (buffer, BUFFERLENGTH);
            	strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

            	/* send the feedback */
           	 n = write (*newsockfd, buffer, strlen(buffer));
            	if (n < 0) 
           		error ("ERROR writing to socket");
            	bzero (buffer, BUFFERLENGTH); 

		close (*newsockfd); /* important to avoid memory leak */  
  		free (newsockfd);
		pthread_exit (NULL); 
 	}
	pTail = pTail-> pNext;     
  }

  pNode pNew = (pNode)malloc(sizeof(Node)); 
  strcpy(pNew->file_name, file_name);
  pNew->pNext = pHead;
  pHead = pNew; 
		
  pthread_mutex_unlock (&mut); /* release the lock */

  /* prepare a feedback to tell the client that he is just encryting or decryting the file on his own*/
  char feedback[15] = "noSametime";
  bzero (buffer, BUFFERLENGTH);
  strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

  /* send the feedback */
  n = write (*newsockfd, buffer, strlen(buffer));
  if (n < 0) 
          error ("ERROR writing to socket");
  bzero (buffer, BUFFERLENGTH); 
  
  /*  receive passphrase  */
  n = read (*newsockfd, buffer, BUFFERLENGTH -1);  
  if (n < 0) {
    error ("ERROR reading from socket");
  }

  printf ("Here is the passphrase: %s\n",buffer);
  char passphrase[PASSPHRASE_MAX_SIZE + 1];  //used to receive the passphrase from the buffer
  bzero(passphrase, sizeof(passphrase));         
  strcpy(passphrase, buffer);  
  
  /* Encrypt */
  if( strcmp("--encrypt", command) == 0)
  {
	/* test whether the file has already been encrypted */
        char file_name_gpg[FILE_NAME_MAX_SIZE + 6];
	strcpy(file_name_gpg, file_name);
	strcat(file_name_gpg, ".gpg");
	FILE *fgpg = fopen( file_name_gpg, "r+" );

    /* The file hasn't been encrypted on the server */
    if( fgpg == NULL ) 
    {
 	//test whether the file is on the server.If yes,then encrypt it at once.If not,tell the client to send the file to the server.
  	FILE *fu = fopen( file_name, "r+" );

        /* The file is not on the server. */
  	if( fu == NULL ) 
 	{
            printf("The %s does not exist on the server.\n", file_name);
            printf("And the client will check whether it is on the client.\n");
            /* prepare a feedback */
            char feedback[15] = "false";
            bzero (buffer, BUFFERLENGTH);
            strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

            /* send the feedback */
            n = write (*newsockfd, buffer, strlen(buffer));
            if (n < 0) 
           	error ("ERROR writing to socket");
            bzero (buffer, BUFFERLENGTH); 

	    //wait for the feedback
            n = read (*newsockfd, buffer, BUFFERLENGTH -1);
    	    if (n < 0) 
        	error ("ERROR reading from socket");
    
    	    /* test the feedback */
    	    if (strcmp ("nExistOnClient", buffer) == 0) //the file does not exist on the client,either
    	    {
		printf("The %s does not exist on the client,either.\n",file_name);

		/* quit the thread */
        	close (*newsockfd); /* important to avoid memory leak */  
		pHead = pHead->pNext;
                free(pNew);  		
		free (newsockfd);
		pthread_exit (NULL);
	    }
	    else if(strcmp ("ExistOnClient", buffer) == 0) // the file exists on the client
	    {
		printf("The %s does exist on the client and the client will send it to my server.\n",file_name);
               	/* create a new file */ 
        	FILE *ft = fopen(file_name, "w+");  
        	if (ft == NULL)  
        	{  
            	printf("File:\t%s Can Not Open To Write!\n", file_name);  
            	exit(1);  
        	}  
        	fclose(ft); 

        	//receive file
        	FILE *fp = fopen(file_name, "r+");  
        	if (fp == NULL)  
        	{  
            		printf("File:\t%s Can Not Open To Write!\n", file_name);  
            		exit(1);  
        	}  
        	// receive the file from the client to the buffer  
        	bzero(buffer, sizeof(buffer)); 
        	int length = 0;  
        	length = recv(*newsockfd, buffer, BUFFERLENGTH, 0); 
          
        	if (length < 0)  
        	{  
            		printf("Recieve Data From Client Failed!\n");  
            		return 0;  
       	 	}  

        	int write_length = fwrite(buffer,  sizeof(char), length, fp);  
        	//printf("write_length: %d, length: %d sizeof(char): %d \n",write_length,length,sizeof(char));            
        	bzero(buffer, sizeof(buffer));    
        	fclose(fp); 
 		printf("Recieve File:\t %s From Client Finished!\n", file_name);
            }     
  	}

        /* The file is on the server. */
  	else{
        	printf("The %s does exist on the server.\n",file_name);
        	/* prepare a feedback */
        	char feedback[15] = "true";
        	bzero (buffer, BUFFERLENGTH);
        	strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

        	/* send the feedback */
        	n = write (*newsockfd, buffer, strlen(buffer));
        	if (n < 0) 
            		error ("ERROR writing to socket");
        	bzero (buffer, BUFFERLENGTH); 
        	fclose(fu);
  	}
    }
    /* The file has already been encrypted on the server */
    else
    {
	printf("The %s has already been encrypted on the server.\n",file_name);
                
	/* prepare a feedback */
        char feedback[15] = "encrypted";
        bzero (buffer, BUFFERLENGTH);
        strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

        /* send the feedback */
        n = write (*newsockfd, buffer, strlen(buffer));
        if (n < 0) 
            	error ("ERROR writing to socket");
        bzero (buffer, BUFFERLENGTH); 
        fclose(fgpg);

        /* quit the thread */
        close (*newsockfd); /* important to avoid memory leak */  
	pHead = pHead->pNext;
        free(pNew);  	
	free (newsockfd);
	pthread_exit (NULL); 
   }
  }

  /* Decrypt */
  else if(strcmp("--decrypt", command) == 0)
  {
	//test whether the file.gpg is on the server.If yes,then decrypt it at once.If not,print ERROR and fire the client.
        //char gpgStr[10] = ".gpg"; 
	//strcat (file_name,gpgStr); 
	char file_name_gpg[FILE_NAME_MAX_SIZE + 6];
	strcpy(file_name_gpg, file_name);
	strcat(file_name_gpg, ".gpg");
	    
  	FILE *fu = fopen( file_name_gpg, "r+" );

        /* The file is not on the server. */
  	if( fu == NULL ) 
 	{
        	printf("The %s does not exist on the server.\n",file_name_gpg);
                
		/* prepare a feedback */
        	char feedback[15] = "no_gpg";
        	bzero (buffer, BUFFERLENGTH);
        	strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

        	/* send the feedback */
        	n = write (*newsockfd, buffer, strlen(buffer));
        	if (n < 0) 
            		error ("ERROR writing to socket");
        	bzero (buffer, BUFFERLENGTH); 

                /* quit the thread */ 
                close (*newsockfd); /* important to avoid memory leak */  
		pHead = pHead->pNext;
                free(pNew);  		
		free (newsockfd);
		pthread_exit (NULL); 
	}
	/* The file is on the server. */
	else
	{
		printf("The %s does exist on the server and it will be decrypted.\n",file_name_gpg);

		/* prepare a feedback */
        	char feedback[15] = "yes_gpg";
        	bzero (buffer, BUFFERLENGTH);
        	strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

        	/* send the feedback */
        	n = write (*newsockfd, buffer, strlen(buffer));
        	if (n < 0) 
            		error ("ERROR writing to socket");
        	bzero (buffer, BUFFERLENGTH); 
		fclose(fu);
	}               
  }
  /* invalid command */
  else
  {
  	printf("INVALID COMMAND!\n");

	/* prepare a feedback */
        char feedback[15] = "invalid";
        bzero (buffer, BUFFERLENGTH);
        strncpy(buffer, feedback, strlen(feedback) > BUFFERLENGTH ? BUFFERLENGTH : strlen(feedback));

        /* send the feedback */
        n = write (*newsockfd, buffer, strlen(buffer));
        if (n < 0) 
            	error ("ERROR writing to socket");
        bzero (buffer, BUFFERLENGTH); 

        close (*newsockfd); /* important to avoid memory leak */
        pHead = pHead->pNext;
        free(pNew);   
  	free (newsockfd);
	pthread_exit (NULL);        
  }


    char desStr[200] = "echo ";
    strcat (desStr,passphrase);
    if( strcmp("--encrypt", command) == 0)
    {
         printf("Now please wait for encrypting.\n");
         char otherStr[15] = " | gpg -c ";
         strcat (desStr,otherStr);
         strcat (desStr,file_name);
         printf("%s\n",desStr);
         system(desStr);
    }
    else
    {
         printf("Now please wait for decrypting.\n");
         char otherStr[25] = " | gpg -d --output ";
         char spaceStr[5] = " ";
         strcat (desStr,otherStr);
         strcat (desStr,file_name);
         strcat (desStr,spaceStr);
         strcat (desStr,file_name);
	 strcat (desStr,".gpg");
         printf("%s\n",desStr);
         system(desStr);            
    } 

    /* close socket */         
  close (*newsockfd); /* important to avoid memory leak */ 
  pHead = pHead->pNext;
  free(pNew); 
  free (newsockfd);

  pthread_exit (NULL);
}



int main(int argc, char *argv[])
{
     socklen_t clilen;
     int sockfd, portno;
     char buffer[BUFFERLENGTH];
     struct sockaddr_in serv_addr, cli_addr;
     int result;



     if (argc < 2) {
         fprintf (stderr,"ERROR, no port provided\n");
         exit(1);
     }
     
     /* create socket */
     sockfd = socket (AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");
     bzero ((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons (portno);

     /* bind it */
     if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) 
              error("ERROR on binding");

     /* ready to accept connections */
     listen (sockfd,5);
     clilen = sizeof (cli_addr);
     
     /* now wait in an endless loop for connections and process them */
     while (1) {

       pthread_t server_thread;

       int *newsockfd; /* allocate memory for each instance to avoid race condition */
       pthread_attr_t pthread_attr; /* attributes for newly created thread */

       newsockfd  = malloc (sizeof (int));
       if (!newsockfd) {
	 fprintf (stderr, "Memory allocation failed!\n");
	 exit (1);
       }

       /* waiting for connections */
       *newsockfd = accept( sockfd, 
			  (struct sockaddr *) &cli_addr, 
			  &clilen);
       if (*newsockfd < 0) 
	 error ("ERROR on accept");
       bzero (buffer, BUFFERLENGTH);

     /* create separate thread for processing */
     if (pthread_attr_init (&pthread_attr)) {
	 fprintf (stderr, "Creating initial thread attributes failed!\n");
	 exit (1);
     }

     if (pthread_attr_setdetachstate (&pthread_attr, !PTHREAD_CREATE_DETACHED)) {
       	 fprintf (stderr, "setting thread attributes failed!\n");
	 exit (1);
     }
     result = pthread_create (&server_thread, &pthread_attr, processRequest, (void *) newsockfd);
       if (result != 0) {
	 fprintf (stderr, "Thread creation failed!\n");
	 exit (1);
       }     
     }
     return 0; 
}
