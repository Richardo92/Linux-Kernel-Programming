/*
 *  chardev.c: Creates a read-only char device that says how many times
 *  you've read from the dev file
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for put_user */
#include <charDeviceDriver.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

/* 
 * This function is called whenever a process tries to do an ioctl on our
 * device file. We get two extra parameters (additional to the inode and file
 * structures, which all device functions get): the number of the ioctl called
 * and the parameter given to the ioctl function.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 *
 */

struct lineList {
    char *line;
    int lineLength;
    struct lineList *next;
}; /* the list-structure for keeping the data in the kernel */

DECLARE_RWSEM(list_semR);
DECLARE_RWSEM(list_semW);

struct lineList *kernelList = NULL; /* the global list of words */
struct lineList *kernelListEnd;

//DEFINE_MUTEX  (devLock);
int totalSize = 0;
int BUFFERLENGTH = 4096;                //4096;
int BUFFERTOTALLIMIT = 2097152;              //2097152;

/* 
 * 1 if the file is currently open by somebody 
 */
int Already_Empty = 0;
int Already_Full = 0;

/* 
 * Queue of processes who want our file 
 */
DECLARE_WAIT_QUEUE_HEAD(WaitRQ);
DECLARE_WAIT_QUEUE_HEAD(WaitWQ);

static long device_ioctl(struct file *file,	/* see include/linux/fs.h */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{

	/* 
	 * Switch according to the ioctl called 
	 */
	if (ioctl_param > BUFFERTOTALLIMIT) {
	    BUFFERTOTALLIMIT = ioctl_param;
	    printk(KERN_INFO "The total size of all messages has been changed to %d bits.\n", BUFFERTOTALLIMIT); 
	    Already_Full = 0;
	    wake_up(&WaitWQ);
	    return 0; 
	}

	else {
	    /* no operation defined - return failure */
	    printk(KERN_INFO "The total size of all messages has not been changed\n");
	    return -EINVAL;

	}
}


/*
 * This function is called when the module is loaded
 */
int init_module(void)
{
        Major = register_chrdev(0, DEVICE_NAME, &fops);

	if (Major < 0) {
	  printk(KERN_ALERT "Registering char device failed with %d\n", Major);
	  return Major;
	}

	printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);
	printk(KERN_INFO "the driver, create a dev file with\n");
	printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, Major);
	printk(KERN_INFO "Try various minor numbers. Try to cat and echo to\n");
	printk(KERN_INFO "the device file.\n");
	printk(KERN_INFO "Remove the device file and module when done.\n");

	return SUCCESS;
}

/*
 * This function is called when the module is unloaded
 */
void cleanup_module(void)
{
        /* clear up the kernel list */
       
        struct lineList *tmp;
        while (kernelList) {
        	tmp = kernelList->next;
        	kfree (kernelList->line);
        	kfree (kernelList);
        	kernelList = tmp;    
    	}
        

	/*  Unregister the device */
	unregister_chrdev(Major, DEVICE_NAME);
}

/*
 * Methods
 */

/* 
 * Called when a process tries to open the device file, like
 * "cat /dev/mycharfile"
 */
static int device_open(struct inode *inode, struct file *file)
{
    
    //mutex_lock (&devLock);
    //if (Device_Open) {
	//mutex_unlock (&devLock);
	//return -EBUSY;
    //}
    //Device_Open++;
    //mutex_unlock (&devLock);

    
    if ((file->f_flags & O_NONBLOCK) && Already_Empty)
		return -EAGAIN;

    //printk(KERN_INFO "33333\n");
    printk(KERN_INFO "1111\n");
    try_module_get(THIS_MODULE);

   
    
    return 0;
}

/* Called when a process closes the device file. */
static int device_release(struct inode *inode, struct file *file)
{
    //mutex_lock (&devLock);
	//Device_Open--;		/* We're now ready for our next caller */
    //mutex_unlock (&devLock);
    /* 
    * Decrement the usage count, or else once you opened the file, you'll
    * never get get rid of the module. 
    */
    
    
    //printk(KERN_INFO "22222\n");
    printk(KERN_INFO "2222\n");
    module_put(THIS_MODULE);

    return 0;
}

/* 
 * Called when a process, which already opened the dev file, attempts to
 * read from it.
 */
static ssize_t device_read(struct file *filp,	/* see include/linux/fs.h   */
			   char *buffer,	/* buffer to fill with data */
			   size_t length,	/* length of the buffer     */
			   loff_t * offset)
{

        //char errorReport[] = "Empty";
	char *kernelBuffer;
        struct lineList *tmp; 
	int byteRead = 0;
	
	

	if (kernelList == NULL ){
		Already_Empty = 1;
                while (Already_Empty) {
			int res;
			printk(KERN_INFO "The list now is empty. Please waiting..... \n");
wait:			res = wait_event_interruptible(WaitRQ, !Already_Empty);
			if (res == -ERESTARTSYS) {
				//printk(KERN_INFO "11111\n");
				//module_put(THIS_MODULE);
				return -EINTR;
			}
        	}
    		
		//return -EAGAIN;
        }

	down_write (&list_semR); /* lock for reading */	
	//printk(KERN_INFO "1111\n");
	if(Already_Empty == 1){
		printk(KERN_INFO "9999\n");
		up_write(&list_semR);
		goto wait;
	}

        tmp = kernelList->next;
	kernelBuffer = kernelList->line;
		
	totalSize -= kernelList->lineLength;
	
	while(length && kernelList->lineLength)
		{	
			put_user(*kernelBuffer, buffer);
			length--;
			kernelList->lineLength--;
			kernelBuffer++;
			buffer++;
			byteRead++;
		}
	printk(KERN_INFO "byteRead: %d\n", byteRead);
	printk(KERN_INFO "totalSize: %d\n", totalSize);
	/* To prevent the situation of memory is full */
	if (totalSize + BUFFERLENGTH < BUFFERTOTALLIMIT){
		Already_Full = 0;
		wake_up(&WaitWQ);
	}

        if (tmp == NULL){
		
		//copy_to_user(buffer, kernelList->line, strlen(kernelList->line) + 1);
		kfree(kernelList->line);
		kfree(kernelList);
                kernelList = NULL;
		Already_Empty = 1;
		up_write(&list_semR);
		//printk(KERN_INFO "5555\n");
                return byteRead;              
        }
	//copy_to_user(buffer, kernelList->line, strlen(kernelList->line) + 1);           
        kfree(kernelList->line);
	kfree(kernelList);
	kernelList = tmp;
       
	up_write(&list_semR);
	//printk(KERN_INFO "2222\n");
        return byteRead;
}

/* Called when a process writes to dev file: echo "hi" > /dev/hello  */
static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t * off)
{
	int byteWrite = 0;
        char *kernelBuffer;
	char *kernelBufferHead;
        struct lineList *newMessage;
        kernelBuffer = kmalloc(BUFFERLENGTH + 30, GFP_KERNEL);
        newMessage = kmalloc(sizeof(struct lineList), GFP_KERNEL);
	kernelBufferHead = kernelBuffer;

        if (!kernelBuffer){
        	return -ENOMEM;
        }
	if(!newMessage){
		return 0;
        }
        if(len > BUFFERLENGTH){
		printk(KERN_INFO "The size of this message has surpassed the limit.\n");
        	kfree(kernelBuffer);
		return -EINVAL;
        }
	
	

	newMessage->lineLength = len;
	while(len ){
		get_user(*kernelBuffer, buff);
		kernelBuffer++;
		buff++;
		len--;
		byteWrite++;
	}
	//*kernelBuffer = '\0';	
	kernelBuffer = kernelBufferHead;	        
	printk(KERN_INFO "byteWrite: %d\n", byteWrite);

        
        newMessage->line = kernelBuffer;
	
	down_write (&list_semW); /* lock for reading */	
	totalSize += byteWrite;
        if( kernelList == NULL ){
		
		printk(KERN_INFO "totalSize: %d\n", totalSize);
		if (totalSize > BUFFERTOTALLIMIT)
		{
			Already_Full = 1;
                	while (Already_Full) {
				int res;
				printk(KERN_INFO "The size of all messages has surpassed the limit. Please waiting..... \n");
				res = wait_event_interruptible(WaitWQ, !Already_Full);
				if (res == -ERESTARTSYS) {
					//module_put(THIS_MODULE);
					//up_write(&list_sem);
					return -EINTR;
				}
        		}

			//printk(KERN_INFO "The size of all messages has surpassed the limit.\n");
			//return -EAGAIN;
		}
		kernelList = newMessage; 
		kernelListEnd = kernelList;
		newMessage->next = NULL;

		Already_Empty = 0;   
    		wake_up(&WaitRQ);
		up_write(&list_semW);

        	return byteWrite;
	}
	
	printk(KERN_INFO "totalSize: %d\n", totalSize);
	if (totalSize > BUFFERTOTALLIMIT)
	{
		up_write(&list_semW);
		Already_Full = 1;
                while (Already_Full) {
			int res;
			printk(KERN_INFO "The size of all messages has surpassed the limit. Please waiting..... \n");
			res = wait_event_interruptible(WaitWQ, !Already_Full);
			if (res == -ERESTARTSYS) {
				//module_put(THIS_MODULE);
				printk(KERN_INFO "3333\n");
				//up_write(&list_sem);
				return -EINTR;
			}
       		}
		printk(KERN_INFO "4444\n");
		down_write (&list_semW); /* lock for reading */	
	}

	
        kernelListEnd->next = newMessage;
        newMessage->next = NULL;
	kernelListEnd = newMessage;

	Already_Empty = 0;   
    	wake_up(&WaitRQ);
	
	up_write(&list_semW);

        return byteWrite;
}

