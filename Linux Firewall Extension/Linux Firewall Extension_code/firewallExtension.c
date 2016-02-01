#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <asm/uaccess.h>


MODULE_AUTHOR ("Eike Ritter <E.Ritter@cs.bham.ac.uk>");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

#define BUFFERSIZE 80 //readInodes
/* kernelWrite  */
#define BUFFERLENGTH 256
#define ADD_ENTRY 'A'
#define SHOW_TABLE 'S'
#define PROC_ENTRY_FILENAME "kernelWrite"

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

/* firewallExtension */
struct nf_hook_ops *reg;

int flag = 0;  //to test wether the list has been loaded
DECLARE_RWSEM(list_sem); /* semaphore to protect list access */

static struct proc_dir_entry *Our_Proc_File;

struct lineList {
    char *line;
    struct lineList *next;
}; /* the list-structure for keeping the data in the kernel */


struct lineList *kernelList = NULL; /* the global list of words */

/* get the port string in the line*/
char * getPortStr(char *line, char *tmp)
{
    int i = 0;
    while(*(line + i) != ' ')
    {
        *(tmp + i) = *(line + i);
        i++;
    }
    *(tmp + i) = '\0';
    return tmp;
    
}

/* get the filename in the line */
char * getFilename(char *line, char *tmp)
{
    int i = 0;
    while(*(line + i) != ' ')
    {
        i++;
    }
    i++;
    tmp = line + i;
    return tmp;
}



/* adds line from user space to the list kept in kernel space */
struct lineList *add_entry (struct lineList *lineList, char *line) {
    
    struct lineList *newEntry;

    
    /* allocate memory for new list element */
    newEntry = kmalloc (sizeof (struct lineList), GFP_KERNEL);
    if (!newEntry) {
        return NULL;
    }
    

    newEntry->line = line;
    printk (KERN_INFO "newEntry->line: %s\n", newEntry->line);
    
    /* protect list access via semaphore */
    down_write (&list_sem);
    newEntry->next = lineList;
    lineList = newEntry;
    up_write (&list_sem);
    
    /* return new list */
    printk (KERN_INFO "lineList: %s\n", lineList->line);
    return lineList;
    
}

/* displays the kernel table - for simplicity via printk */
void show_table (struct lineList *lineList) {
    
    struct lineList *tmp;
    down_read (&list_sem); /* lock for reading */
    tmp = lineList;
    while (tmp) {
        printk (KERN_INFO "kernelWrite:The next entry is %s\n", tmp->line);
        tmp = tmp->next;
    }
    up_read (&list_sem); /* unlock reading */
    
}

/* This function reads in data from the user into the kernel */
ssize_t kernelWrite (struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
    
    
    char *kernelBuffer; /* the kernel buffer */
    
    struct lineList *tmp;
    
    printk (KERN_INFO "kernelWrite entered\n");
    
    kernelBuffer = kmalloc (BUFFERLENGTH, GFP_KERNEL); /* allocate memory */
    
    if (!kernelBuffer) {
        return -ENOMEM;
    }
    
    
    if (count > BUFFERLENGTH) { /* make sure we don't get buffer overflow */
        kfree (kernelBuffer);
        return -EFAULT;
    }
    
    
    /* copy data from user space */
    if (copy_from_user (kernelBuffer, buffer, count)) {
        kfree (kernelBuffer);
        return -EFAULT;
    }

    kernelBuffer[BUFFERLENGTH -1]  ='\0'; /* safety measure: ensure string termination */

    if(flag == 1)
    {
        while (kernelList) {
            tmp = kernelList->next;
            kfree (kernelList->line);
            kfree (kernelList);
            kernelList = tmp;
        }
        flag = 0;

    }
    switch (kernelBuffer[0]) {
        case '0':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '1':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '2':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '3':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '4':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '5':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '6':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '7':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '8':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        case '9':
            tmp = add_entry (kernelList, &(kernelBuffer[0]));
            if (!tmp) {
                kfree (kernelBuffer);
                return -EFAULT;
            }
            else {
                kernelList = tmp;
            }
            break;
        default:
            printk (KERN_INFO "ok done \n");
    }
    return count;
}



/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
int procfs_open(struct inode *inode, struct file *file)
{
    printk (KERN_INFO "kernelWrite opened\n");
    try_module_get(THIS_MODULE);
    return 0;
}

/*
 * The file is closed - again, interesting only because
 * of the reference count.
 */
int procfs_close(struct inode *inode, struct file *file)
{
    flag = 1;
    printk (KERN_INFO "kernelWrite closed\n");
    module_put(THIS_MODULE);
    return 0;		/* success */
}
ssize_t kernelRead (struct file *fp,
                    char __user *buffer,  /* the destination buffer */
                    size_t buffer_size,  /* size of buffer */
                    loff_t *offset  /* offset in destination buffer */
) 
{
    show_table (kernelList);    
    return 0;
}
const struct file_operations File_Ops_4_Our_Proc_File = {
    .owner    = THIS_MODULE,
    .write    = kernelWrite,
    .open     = procfs_open,
    .release  = procfs_close,
    .read     = kernelRead,
};


/*  firewallExtension */
/* make IP4-addresses readable */
unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *)) {
    
    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct mm_struct *mm;
    struct sock *sk;
    /* readInodes */
    struct path path;
    pid_t mod_pid;
    struct dentry *procDentry;
    struct dentry *parent;
    char filename[200];
    char temp[200];
    char cmdlineFile[BUFFERSIZE];
    int res;
    /* get the port number and filename from the line */
    int distance;
    struct lineList *tmp;
    char tcpDest[10];
    char rulePortStr[10];
    char ruleFilename[100];
    char *tmpPortStr;
    char *tmpFilename;
    tmpPortStr = kmalloc (10 * sizeof(char), GFP_KERNEL);
    tmpFilename = kmalloc (100 * sizeof(char), GFP_KERNEL);
    
    sk = skb->sk;
    if (!sk) {
        //printk (KERN_INFO "firewall: netfilter called with empty socket!\n");;
        return NF_ACCEPT;
    }
    
    if (sk->sk_protocol != IPPROTO_TCP) {
        //printk (KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
        return NF_ACCEPT;
    }
    
    
    
    /* get the tcp-header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp) {
        //printk (KERN_INFO "Could not get tcp-header!\n");
        return NF_ACCEPT;
    }
    if (tcp->syn) {
        struct iphdr *ip;
        
        //printk (KERN_INFO "firewall: Starting connection \n");
        ip = ip_hdr (skb);
        if (!ip) {
            //printk (KERN_INFO "firewall: Cannot get IP header!\n!");
        }
        else {
            //printk (KERN_INFO "firewall: Sourse address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
        }
        //printk (KERN_INFO "firewall: destination port = %d\n", htons(tcp->dest));
        
        
        
        if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
            printk (KERN_INFO "Not in user context - retry packet\n");
            return NF_ACCEPT;
        }
        mmput (mm); /* decrease counter controlling access to memory mapping tables */
        
        
        
        tmp = kernelList;
        while( tmp )
        {
            strcpy(rulePortStr, getPortStr(tmp->line, tmpPortStr));
            strcpy(ruleFilename, getFilename(tmp->line, tmpFilename));
            sprintf(tcpDest, "%d" , htons(tcp->dest));
            if (strcmp(tcpDest, rulePortStr) == 0) {
                
                /*   get the filename by using readInodes  */
                
                
                printk (KERN_INFO "readInodes module loading\n");
                mod_pid = current->pid;
                printk (KERN_INFO "current->pid: %d\n",mod_pid);
                snprintf (cmdlineFile, BUFFERSIZE, "/proc/%d/exe", mod_pid);
                printk (KERN_INFO "cmdlineFile: %s\n",cmdlineFile);
                res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
                printk (KERN_INFO "res: %d\n",res);
                if (res) {
                    printk (KERN_INFO "Could not get dentry for %s!\n", cmdlineFile);
                    return -EFAULT;
                }
                
                procDentry = path.dentry;
                strcpy(filename, procDentry->d_name.name);
                parent = procDentry->d_parent;
                
                while(parent->d_name.name[0] != '/')
                {
                    strcpy(temp, parent->d_name.name);
                    strcat(temp, "/");
                    strcat(temp,filename);
                    strcpy(filename, temp);
                    memset(temp, 0, sizeof(temp));
                    parent = parent->d_parent;
                }
                strcpy(temp, parent->d_name.name);
                strcat(temp,filename);
                strcpy(filename, temp);
                memset(temp, 0, sizeof(temp));
                distance = strlen(ruleFilename);
                printk (KERN_INFO "The length is %d\n", distance);
                ruleFilename[distance - 1] = '\0';
                printk(KERN_INFO "Rule is: %s\n",ruleFilename);
                printk (KERN_INFO "Filename is %s\n", filename);
                if(strcmp(ruleFilename, filename) == 0)
                {
                    printk (KERN_INFO "success done\n");
                    return NF_ACCEPT;
                }

                tcp_done (sk); /* terminate connection immediately */
                return NF_DROP;
            }
            tmp = tmp->next;
        }
        kfree(tmpPortStr);
        kfree(tmpFilename);
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}

EXPORT_SYMBOL (FirewallExtensionHook);

static struct nf_hook_ops firewallExtension_ops = {
    .hook    = FirewallExtensionHook,
    .owner   = THIS_MODULE,
    .pf      = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_OUT
};

int init_module(void)
{
    int errno;
    /*  kernelWrite  */
    /* create the /proc file */
    Our_Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &File_Ops_4_Our_Proc_File, NULL);
    
    /* check if the /proc file was created successfuly */
    if (Our_Proc_File == NULL){
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
               PROC_ENTRY_FILENAME);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);
    
    /* firewallExtension */
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
    /* kernelWrite */
    struct lineList *tmp;
    
    
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
    printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);  
    
    
    /* free the list */
    while (kernelList) {
        tmp = kernelList->next;
        kfree (kernelList->line);
        kfree (kernelList);
        kernelList = tmp;
    }
    
    printk(KERN_INFO "kernelWrite:Proc module unloaded.\n");
    
    /* firewallExtension */
    nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
    printk(KERN_INFO "Firewall extensions module unloaded\n");
    
    /*  readInodes  */
    printk(KERN_INFO "readInodes module unloaded \n");
}  


