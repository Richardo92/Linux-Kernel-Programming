#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/spinlock.h>



MODULE_AUTHOR ("Eike Ritter <E.Ritter@cs.bham.ac.uk>");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

//define the max size of buffer from the user space
#define BUFFERLENGTH 500

//define the proc file direct entry
static struct proc_dir_entry *Our_Proc_File;

//to lock multiple readers
//DECLARE_WAIT_QUEUE_HEAD(ReadQ);

//define iptraffic as the proc entry name
#define PROC_ENTRY_FILENAME "iptraffic"


/* make IP4-addresses readable */
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

//define nf_hook_ops
struct nf_hook_ops *reg;

//to test wether the list has been loaded
int flag = 0;  

//define the structure of writeList
struct writeList{
	int port[64];
};
//define the structure of readList
struct readList{
	char *line;
	int port;
	struct readList *next;
};

//define the head of writeList
struct writeList *kernelWriteList = NULL;
//define the head of readList
struct readList *kernelReadList = NULL;

// to count how many ports,it must <=64
int portCount;
//to symbolize how many pieces of information in one specific port
int pairCount[64];

//intialize the spin lock for reader
DEFINE_SPINLOCK(read_lock);
//intialize the spin lock for writer
DEFINE_SPINLOCK(write_lock);

//kernelWrite to transfer the buffer in the user space into the kernel space
ssize_t kernelWrite (struct file *file, const char __user *buffer, size_t count, loff_t *offset) {

    char *writeBuffer; /* the kernel buffer */
    char *p;
    int i = 0;
    struct writeList *portList;
    struct readList *tmp;//be used to free the read list when flag == 1
    
    unsigned int port;// to get the port from buffer
    printk (KERN_INFO "kernelWrite entered\n");
    
    portCount = 0; 
    portList = kmalloc (sizeof(struct writeList), GFP_KERNEL);  
    writeBuffer = kmalloc (BUFFERLENGTH, GFP_KERNEL); /* allocate memory */
    
    if (!writeBuffer) {
        return -ENOMEM;
    }
    
    
    if (count > BUFFERLENGTH) { /* make sure we don't get buffer overflow */
        kfree (writeBuffer);
        return -EFAULT;
    }
    
    /* when the user retype the write command, we should clear up the past list both for writing and reading */
    if(flag == 1){
	if(kernelWriteList)
		kfree (kernelWriteList);
        while(kernelReadList){
		tmp = kernelReadList->next;
		kfree(kernelReadList->line);
		kfree(kernelReadList);
		kernelReadList = tmp;
    	}
	for(i = 0; i < 64; i++){    // also clean up the number of pieces of information stored in pairCount[64]
		pairCount[i] = 0;
	}	
        flag = 0;  
    }
    kernelWriteList = portList;
    portCount = 0; //used to record the number of ports, it cannot be beyond 64

    /* copy data from user space */
    if (copy_from_user (writeBuffer, buffer, count)) {
        kfree (writeBuffer);
        return -EFAULT;
    }
    writeBuffer[BUFFERLENGTH -1]  ='\0'; /* safety measure: ensure string termination */   
    printk (KERN_INFO "%s\n", writeBuffer);

    while( (p = strsep(&writeBuffer, ",")) != NULL){       //to separate string by ","
	if(portCount >64){   // the max size of port is 64
		printk(KERN_INFO "ERROR: The number of ports has been beyond 64!\n");
		return -EINVAL;
	}
	if( kstrtouint(p,0,&port) ){ //to transfer the string to integer; if fail, it return true,so it will report fault to the client
		printk(KERN_INFO "ERROR: You don't permit the grammar rules!\n");		
		return -EINVAL;
	}	
	printk(KERN_INFO "The port number is: %u\n", port);
        portList->port[portCount] = port;
	portCount++;
    }
    

    return count;

}


/* the function called to write data into the proc-buffer */
ssize_t kernelRead (struct file *fp,
		 char __user *buffer,  /* the destination buffer */
		 size_t buffer_size,  /* size of buffer */
		 loff_t *offset  /* offset in destination buffer */
	        ) {
	struct readList *tmp;
	int maxBuffer;
	tmp = kernelReadList;
	strcpy(buffer, "BEGIN\n");
	
	spin_lock(&read_lock);//spinlock the reading process
	while(tmp){  // traverse the whole read list and integrate all information into the buffer and transfer it to the user space
		strcat(buffer, tmp->line);
		tmp = tmp->next;
	}
	
	strcat(buffer, "END\n");
	maxBuffer= strlen(buffer);
	buffer[maxBuffer] = '\0';
	printk(KERN_INFO "maxBuffer: %d\n", maxBuffer);
	spin_unlock (&read_lock);
	return maxBuffer;
}


unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct iphdr *ip;
    struct readList *newList;
    struct readList *tmp;
    struct readList *tmpNext;
    char *line;
    char srcPortStr[10];
    char desPortStr[10];
    char srcAddrStr[30];
    int readCount; // to symbolize the port
    int i;

    newList = kmalloc (sizeof(struct readList), GFP_KERNEL);  
    line = kmalloc(100 * sizeof(char), GFP_KERNEL);
    readCount = 0;
    i = 0;

    ip = ip_hdr (skb);
    if (!ip) {
	printk (KERN_INFO "firewall: Cannot get IP header!\n!");
    }
    
    //    printk (KERN_INFO "The protocol received is %d\n", ip- >protocol);
    if (ip->protocol == IPPROTO_TCP) { 
	//	printk (KERN_INFO "TCP-packet received\n");

    /* get the tcp-header for the packet */
	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
	if (!tcp) {
	    printk (KERN_INFO "Could not get tcp-header!\n");
	    return NF_ACCEPT;
       }

       if (tcp->syn && tcp->ack) {
	
	   printk (KERN_INFO "firewall: Received SYN-ACK-packet \n");
	   printk (KERN_INFO "firewall: Source address = %u.%u.%u.%u\n", NIPQUAD(ip->saddr));
	   printk (KERN_INFO "firewall: destination port = %d\n", htons(tcp->dest)); 
	   printk (KERN_INFO "firewall: source port = %d\n", htons(tcp->source)); 
	   /* traverse the write list to find whether there is a port matching with the tcp->source port */	
	   while(readCount <= portCount){
		if(htons(tcp->source) == kernelWriteList->port[readCount]){	
			spin_lock(&write_lock);	//spinlock the write process		
			pairCount[readCount] = pairCount[readCount] + 1;
			/* if pieces of information are beyond 32,delete the oldest information 
				and add the new information to the head of read list */
			if(pairCount[readCount] > 32){
				printk (KERN_INFO "2222\n");
				tmp = kernelReadList;
				tmpNext = tmp->next;
				if(tmp->port == kernelWriteList->port[readCount])
					i++;
				while((tmpNext->next)){ // traverse the write list to find the final node of specific port, delete it
					if(tmpNext->port == kernelWriteList->port[readCount])
						i++;					
					if(i == 32)
						break;					
					tmp = tmpNext;
					tmpNext = tmpNext->next;
				}
				tmp->next = tmpNext->next;
				kfree(tmpNext->line);
				kfree(tmpNext);				
				sprintf(srcPortStr, "%d" , htons(tcp->source));
				sprintf(desPortStr, "%d" , htons(tcp->dest));
				sprintf(srcAddrStr, "%u.%u.%u.%u" , NIPQUAD(ip->saddr));
				strcpy(line, srcPortStr);
				strcat(line, ":");
				strcat(line, desPortStr);
				strcat(line, ":");
				strcat(line, srcAddrStr);
				strcat(line, "\n");
			
				newList->line = line;
				newList->next = kernelReadList;
				newList->port = kernelWriteList->port[readCount]; 
				kernelReadList = newList;
				pairCount[readCount] = 32;
				printk (KERN_INFO "1111\n");
				printk (KERN_INFO "line: %s", line);
				printk (KERN_INFO "count: %d\n", pairCount[readCount]);
				spin_unlock (&write_lock);
				break;
			}
			sprintf(srcPortStr, "%d" , htons(tcp->source));
			sprintf(desPortStr, "%d" , htons(tcp->dest));
			sprintf(srcAddrStr, "%u.%u.%u.%u" , NIPQUAD(ip->saddr));
			strcpy(line, srcPortStr);
			strcat(line, ":");
			strcat(line, desPortStr);
			strcat(line, ":");
			strcat(line, srcAddrStr);
			strcat(line, "\n");
			
			newList->line = line;
			newList->next = kernelReadList;
			newList->port = kernelWriteList->port[readCount]; 
			kernelReadList = newList;
			printk (KERN_INFO "line: %s", line);
			printk (KERN_INFO "count: %d\n", pairCount[readCount]);
			spin_unlock (&write_lock);
			break;
		}
		readCount++;
	   }
	   if(kernelReadList == NULL){
		kfree(line);
		kfree(newList);
	   }
       }
    }
    return NF_ACCEPT;	
}


static struct nf_hook_ops firewallExtension_ops = {
	.hook    = FirewallExtensionHook,
	.owner   = THIS_MODULE,
	.pf      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_IN
};


/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
int procfs_open(struct inode *inode, struct file *file)
{
    printk (KERN_INFO "iptraffic opened\n");
    try_module_get(THIS_MODULE);
    return 0;
}

/*
 * The file is closed - again, interesting only because
 * of the reference count.
 */
int procfs_close(struct inode *inode, struct file *file)
{
    flag = 1; // to change the flag to 1 so that next time when users type in new writing command, it can delete the past lists
    printk (KERN_INFO "iptraffic closed\n");
    module_put(THIS_MODULE);
    return 0;		/* success */
}


//to define the file operations
const struct file_operations File_Ops_4_Our_Proc_File = {
    .owner    = THIS_MODULE,
    .write    = kernelWrite,
    .open     = procfs_open,
    .release  = procfs_close,
    .read     = kernelRead,
};


int init_module(void)
{

  int errno;

  /* create the /proc/iptraffic */
  Our_Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &File_Ops_4_Our_Proc_File, NULL);
    
  /* check if the /proc file was created successfuly */
  if (Our_Proc_File == NULL){
  	printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",PROC_ENTRY_FILENAME);
        return -ENOMEM;
    }
    
  printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);


  errno = nf_register_hook (&firewallExtension_ops); /* register the hook */
  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered!\n");
  } 
  else {
    printk(KERN_INFO "Firewall extensions module loaded\n");
  }

  // A non 0 return means init_module failed; module can't be loaded.
  return errno;
}


void cleanup_module(void)
{
    struct readList *tmp;
    kfree (kernelWriteList);

    while(kernelReadList){
	tmp = kernelReadList->next;
	kfree(kernelReadList->line);
	kfree(kernelReadList);
	kernelReadList = tmp;
    }
    //remove the /proc/iptraffic
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);  


    nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
    printk(KERN_INFO "Firewall extensions module unloaded\n");

}  
