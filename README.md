## Linux Namespaces

The subject of this tutorial is about Linux namespaces, with the objective of understanding and using them in order to implement basic containers. Containers introduces a lightweight kind of virtualization,
all software that runs inside it, thinks that is running in physically host. Linux since kernel 2.6.23 offers tools to achieve this behaviour, namely Linux namespaces. Today we can use 6 namespaces:


| Namespaces        | Constant           | Isolates  |
| ------------- |:-------------:| -----:|
| Cgroup    | CLONE_NEWCGROUP | Cgroup root directory  |
| IPC    | CLONE_NEWIPC | System V IPC, POSIX message queues  |
| Network    | CLONE_NEWNET | Network devices, stacks, ports, etc.  |
| Mount    | CLONE_NEWNS | Mount points  |
| PID |  CLONE_NEWPID | Process IDs  |
| User |  CLONE_NEWUSER | User and group IDs  |
| UTS | CLONE_NEWUTS  | Hostname and NIS domain name  |

Each namespace wraps a particular global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource.


## Cgroups

Cgroup namspace gives the possibility of administrate a number of resources and set resource limits to them by using certain resources controllers also known as  Cgroup subsystems.
With tihs we can adminbstrate CPU, memory, network brandwith and I/O amonsgst hierarchically ordered groups of processes. In the hierarchies the are composed by slices, they dont have any 
processes instead, they prodive a blueprint for organizing a hierarchy around processes. A slice can have a scope (transient processes, eg: VM, user sessins) or a service (system services, normally started via systemd).


systemd-------
	     !
         
	     !
         
       ______!_____
      !      !	   !
    Service Scope  Slice

There are four default slices:

1) -.slice: The root slice at the top of the Cgrpup tree

2) System.slice: The default place for all system services

3) User.slice: The default +lace for all user sessions

4) Machine.slice: VM and containers.

![SystemD](https://image.ibb.co/jhhW5d/Screenshot_from_2018_05_13_23_28_08.png)

```bash
# See Cgroup hierarchy of processes
systemd-cgls 


# See the number of tasks, CPU consuption, Memory, I/O
systemd-cgtop

#Run transient process in a new sclice 
systemd-run --unit=top --slice=nuno.slice top -b


#Check if is running
systemctl status nuno.slice

#Check again
systemd-cgls

#stop it
systemctl stop nuno.slice

#Apply Cgroup limit

#Run a program that requires 2g of RAM
echo "while true; do memhog 2g; sleep 2; done" > memhogtest.sh

cat <<EOF > memhogtest.service
[Unit]
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=notify
ExecStart=/home/nuno/memtest.sh -DBACKGROUND
ExecStop=/bin/kill -WINCH ${MAINPID}
killSignal=SIGTERM
PrivateTmp=true

[Install]
WantedBy=multi-user.target

EOF

cp memhogtest.service /usr/lib/systemd/system

systemctl deamon-reaload
systemctl enable memhogtest.service

#Force Ram limit
systemctl set-property --runtime memhogtest.service MemoryLimit=1G

systemctl deamon-reaload

#Check if the proccess was killed
systemctl status memhogtest.service

```

![SystemDD](https://image.ibb.co/c7Q7dy/Screenshot_from_2018_05_13_23_30_42.png)


Other way of limit process resources is to manipulate the files that kernel expose. To our goal we will limit the memory usage up to 100MB using Cgroups. 
All containers that will be spawned will be this resource limited. The kernel exposes cgroups through the /sys/fs/cgroup directory.



```bash
ls /sys/fs/cgroup
#create new memory group

mkdir /sys/fs/cgroup/memory/cogsi

```


![Cg](https://image.ibb.co/erjL0d/Screen_Shot_2018_05_15_at_01_54_24.png)


Once created the kernel creates all files that we can mannually configure. our goal is to set memory up to 100Mb and disable swap



```bash
echo "100000000" > /sys/fs/cgroup/memory/cogsi/memory.limit_in_bytes
echo "0" > /sys/fs/cgroup/memory/demo/memory.swappiness
```

The special task file, holds all PIDs that will have this policy activated, later on we will show a full container that 
have this restriction.
 
## Network

This let us have isolated network environments on a single host, each nampespace has its own interfaces and routing table.


```bash
#List all inherit namespaces
ip netns

```


-----------------------
!    Linux Kernel     !
!  ______________     !

!  !_Default NS_!     !
!_____________________!



To our project will have add two namespaces:

1) net1

2) net2


```bash

ip netstat add net1
ip netstat add net2

```

    Default NS
                     
   net1     net2     



```bash
#Check if was created
ip netns list
```

once a namespace is added, a new file is created in /var/run/netns with the same name as the namespace. Our next goal os to ping each other, using virtual switch.


```bash
apt-get install openvswitch-switch

#start
systemctl start openvswitch

#Create a virtual switch
ovs-vsctl add-br name_switch

#Show created switch
ovs-vsctl show

```


We need 2 virtual ethernets to connect each network namespace, we can created a type of veth that create pair of tubes, we conect the one exterminty to the switch an other to the created namespace.


```bash
# netX-netsn will be in namespace, and the netX-ovs will bve on switch side
ip link add net1-netns type veth peer name net1-ovs
ip link add net2-netns type veth peer name net2-ovs

# Connect the netX-netns to the netX namespace
ip link set net1-netns netns net1
ip link set net2-netns netns net2

# Connect netX-ovs to the virtual switch
ovs-vsctl add-port name_switch net1-ovs
ovs-vsctl add-port name_switch net2-ovs

```

       OpenSwitch
-------------------
!  __net1-ovs __ net2-ovs	
! !  !	     !  !  !
! !--!	     !--!  !	
---!-----------!---
 
   !	       !	
   !           !
   !	       !	
net1-netns   net2-netns  
   !           ! 
   !           !
 _ !_	     _ !__	
!net1!	    ! net2!	


```bash
#Now we can enable the devices in the 'default' namespace
sudo ip link set net1-ovs up
sudo ip link set net2-ovs up

#Enable into namespaced land
sudo ip netns exec net1 ip link set dev lo up
sudo ip netns exec net1 ip link set dev net1-netns up

sudo ip netns exec net2 ip link set dev lo up
sudo ip netns exec net2 ip link set dev net2-netns up

#Assign static address
sudo ip netns exec net1 ip addr add 10.0.0.1/24 dev net1-netns
sudo ip netns exec net2 ip addr add 10.0.0.2/24 dev net2-netns

#Ping between namespaces using ip command
sudo ip netns exec net1 ping 10.0.0.2

#Ping between namespaces using a friendly way
sudo ip netns exec net1 /bin/bash
#enter inside the namespace
ping 10.0.0.2

```

This configurations let us have a local netowrk only for namspaces purposes.

![Network](https://image.ibb.co/haAvWJ/Screenshot_from_2018_05_14_00_50_41.png)

On a fully isolated container (alike docker)
![Container](https://image.ibb.co/bPGoJy/Screenshot_from_2018_05_14_01_04_04.png)


## Mount

This namespace isolates the mounting points seen by the processes in a namespace. Exists four types or markers that we can give to a specific 
mounting point, the marker determinates the event propragation between them. Currently exists 4 type:

1) MS_SHARED - All events are propageted to his peers

2) MS_PRIVATE - No event is propagated to his peers

3) MS_SLAVE - Events in a master are propagated, but not from slave to the master.

4) MS_UNBINDABLE - Like private, thus  cannot bind mount operation

To acheive our goal, we will create a master slave configuration. The master will share a read only mounting point that contains config
files and executable files, while the container has their own mounting point, that only it has permission to write. For emulate real block device,
we will create RAM disks. RAM disks use the normal RAM in main memory as if it were a partition on a hard drive rather than 
actually accessing the data bus normally used for secondary storage such as hard disk.

```bash

mkfs -q /dev/ram1 8192
mkfs -q /dev/ram2 8192

mkdir -p /mnt/ram1
mkdir -p /mnt/ram2

mkfs -t ext4 -q /dev/ram1 8192
mkfs -t ext4 -q /dev/ram2 8192

mount /dev/ram1 /opt/container/shared

mount --make-shared /opt/container/shared

# Share a read only filesystem into two containers
mount --bind -o ro /opt/container/shared /opt/container/rootfs/shared
mount --bind -o ro /opt/container/shared /opt/container/otherfs/shared

```

### Docker Alike Container.

This leads to the final of this sprint, that we have a program written in C that uses the namepsace API to compose
allmost all of the mentioned namespaces. Soo far, we already have two network namespaces that can be used by two containers that 
require communication, one shared mounting point, that the two can read from, and one that they share.

This completes by joining to the network namespace with setns sys call, wich have a well known file. Before 
spwan a container we need a container image.

```bash
# Download image
wget https://github.com/NunuM/containers/archive/v0.1.0.zip

mkdir -p /opt/container

mv v0.1.0.zip /opt/container

cd /opt/container

unzip v0.1.0.zip

cd -

# Compile the source code
gcc file.c -o launcher

#spawning a container
./launcher -n -u -i -m -p -N net1 -M zion chroot /opt/container/rootfs /bin/bash

```
This image is based on devian jessie, and has python. Now that we make are in our fresh container,
restained by RAM, let's create an hungry python program.

```bash
cat <<EOF > hungry.py
f = open("/dev/urandom", "r")
data = ""

i=0
while True:
    data += f.read(10000000) # 10mb
    i += 1
    print "%dmb" % (i*10,)
EOF

/usr/bin/python hungry.py

```
Note that if we want to execute the script it will fail, since we do not have the special file /dev/urandom, we need to create it.


```bash
mknod -m 444 /dev/urandom c 1 9
```


![Run Inside container](https://image.ibb.co/e59HDy/Screen_Shot_2018_05_15_at_02_49_22.png)

The script is killed by the control group that is associated with it.

Next we want to have internet access inside the two containers. We almost have all set. To accomplish, was created a port in open vSwitch bridge 'name_switch' that we have created. The port 
will bind the physically ethernet interface with 'name_switch'. (The host loses the internet connectivity, since the interface is not connected no more to the default IP stack of the system).
In order to recover internet connection, two steps were required: 1) remove physically interface address; 2) assign my_bridge with address. The systems will looks like: IP stack -> name_bridge -> enp0s25 

```bash
#find enp0s25 address
ip addr

#add physicall interface - CAUTION : Lost cconnectivity after this command
ovs-vsctl add-port name_switch enp0s25

#delete adrress
ip addr del 192.168.2.60/24 dev enp0s25

#configure name_switch
dhclient name_switch
```

To test the result of the documented steps were launched two containers in two diferrent terminals:

```bash
#copy a program to a shared filesystem
cat <<EOF > /opt/container/shared/hungry.py
f = open("/dev/urandom", "r")
data = ""

i=0
while True:
    data += f.read(10000000) # 10mb
    i += 1
    print "%dmb" % (i*10,)
EOF

#launch zion - terminal 1
./launcher -i -m -n -p -u -N net1 -H zion chroot /opt/container/rootfs /bin/bash
ping localhost

ping 10.0.0.2

ping 8.8.8.8

ping google.pt

#launch moon - terminal 2
./launcher -i -m -n -p -u -N net2 -H moon chroot /opt/container/otherfs /bin/bash

```
As result

![Inside a container](https://image.ibb.co/jENNFd/Screenshot_from_2018_05_15_14_41_56.png)


We also can install other sofware using apt tool command.

![APT Tool](https://image.ibb.co/koiq1J/Screenshot_from_2018_05_15_14_46_04.png)

run a program from a shared filesystem

![python prd](https://image.ibb.co/fO9mad/Screenshot_from_2018_05_15_14_48_26.png)

The last part is to demonstrate how to mount a filesystem in a running container, this will share a mounting point only and only between the two containers,
event the parent tree does not see this subtree.


```bash
#We can cat the /sys/fs/cgroup/memory/cogsi/tasks
cat /sys/fs/cgroup/memory/cogsi/tasks

#or uses ps
ps aux | grep bash
#and to be sure  send a message to a pseudo-terminal, and repeat the process to find the other container
echo "Is you container?" > /dev/pts/18

```
100% positive that we have find the PID

![telephone ](https://image.ibb.co/ctLv1J/Screenshot_from_2018_05_15_14_57_45.png)

```bash
#now we can create the private filesystem
nsenter -m -t [zion_PID] mount --make-slave --read-write /dev/ram2 /opt/container/rootfs/private
nsenter -m -t [moon_PID] mount --make-slave --read-write /dev/ram1 /opt/container/otherfs/private

#In a zion container - this file only is visible by the two containers
echo "I am private" > /private/text.txt

#In moon container
ls /private

#We also can mount proc using this command
nsenter -p -t [zion_PID] mount -t proc proc /opt/container/rootfs/proc
```

Nsenter command allows us to executes commands inside a running container.

![private](https://image.ibb.co/mxnuTy/Screenshot_from_2018_05_15_15_08_39.png)

![proc](https://image.ibb.co/jdUmad/Screenshot_from_2018_05_15_15_16_24.png)



```c

#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>


#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

struct child_args {
    char **argv;        /* Command to be executed by child, with arguments */
    char * hostname;    /* Set Hostname UTS */
    char * netns;       /* Set network namespace */
    int    pipe_fd[2];  /* Pipe used to synchronize parent and child */
};

static int verbose;

static void
usage(char *pname)
{
    fprintf(stderr, "Usage: %s [options] cmd [arg...]\n\n", pname);
    fprintf(stderr, "Create a child process that executes a shell command in a new user namespace,\n");
    fprintf(stderr, "Options can be:\n\n");
#define fpe(str) fprintf(stderr, "    %s", str);
    fpe("-i          New IPC namespace\n");
    fpe("-m          New mount namespace\n");
    fpe("-n          New network namespace\n");
    fpe("-p          New PID namespace\n");
    fpe("-u          New UTS namespace\n");
    fpe("-U          New user namespace\n");
    fpe("-M uid_map  Specify UID map for user namespace\n");
    fpe("-G gid_map  Specify GID map for user namespace\n");
    fpe("            If -M or -G is specified, -U is required\n");
    fpe("-N          Join to network namespace\n");
    fpe("-H          Set UTS namespace\n");
    fpe("-v          Display verbose messages\n");
    fpe("\n");
    fpe("Map strings for -M and -G consist of records of the form:\n");
    fpe("\n");
    fpe("    ID-inside-ns   ID-outside-ns   len\n");
    fpe("\n");

    exit(EXIT_FAILURE);
}

static void update_map(char *mapping, char *map_file)
{
    int fd, j;
    size_t map_len;     /* Length of 'mapping' */

    map_len = strlen(mapping);
    for (j = 0; j < map_len; j++)
        if (mapping[j] == ',')
            mapping[j] = '\n';

    fd = open(map_file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "open %s: %s\n", map_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (write(fd, mapping, map_len) != map_len) {
        fprintf(stderr, "write %s: %s\n", map_file, strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(fd);
}

static int childFunc(void *arg)
{
    struct child_args *args = (struct child_args *) arg;
    char ch;

    close(args->pipe_fd[1]);

    if (read(args->pipe_fd[0], &ch, 1) != 0) {
        fprintf(stderr, "Failure in child: read from pipe returned != 0\n");
        exit(EXIT_FAILURE);
    }

    if(args->hostname != NULL && strlen(args->hostname) > 0){
       if (sethostname(args->hostname, strlen(args->hostname)) == -1){
           errExit("sethostname");
	}
    }

    int nslen = 0;
    if(args->netns != NULL && (nslen = strlen(args->netns)) > 0){
        char * buf = (char *) malloc(124);
	snprintf(buf, nslen + 18, "/var/run/netns/%s", args->netns);
        int fd = open(buf, O_RDONLY); /* Get file descriptor for namespace */
        if (fd == -1){
            errExit("open");
	}
        if (setns(fd, 0) == -1){ /* Join network namespace */
            errExit("setns");
	}
    }

    /* Execute a shell command */

    execvp(args->argv[0], args->argv);
    errExit("execvp");
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];    /* Space for child's stack */

int main(int argc, char *argv[])
{
    int flags, opt, fd,res;
    pid_t child_pid;
    struct child_args args;
    char *uid_map, *gid_map,*hostname,*netns;
    char map_path[PATH_MAX];

    flags = 0;
    verbose = 0;
    gid_map = NULL;
    uid_map = NULL;
    while ((opt = getopt(argc, argv, "+imnpuUM:G:H:N:v")) != -1) {
        switch (opt) {
        case 'i': flags |= CLONE_NEWIPC;        break;
        case 'm': flags |= CLONE_NEWNS;         break;
        case 'n': flags |= CLONE_NEWNET;        break;
        case 'p': flags |= CLONE_NEWPID;        break;
        case 'u': flags |= CLONE_NEWUTS;        break;
        case 'v': verbose = 1;                  break;
        case 'M': uid_map = optarg;             break;
        case 'G': gid_map = optarg;             break;
        case 'U': flags |= CLONE_NEWUSER;       break;
	case 'H': args.hostname = optarg;	break;
	case 'N': args.netns = optarg;		break;
        default:  usage(argv[0]);
        }
    }

    if ((uid_map != NULL || gid_map != NULL) &&
            !(flags & CLONE_NEWUSER))
        usage(argv[0]);

    args.argv = &argv[optind];


    if (pipe(args.pipe_fd) == -1)
        errExit("pipe");

    /* Create the child in new namespace(s) */

    child_pid = clone(childFunc, child_stack + STACK_SIZE,
                      flags | SIGCHLD, &args);
    if (child_pid == -1)
        errExit("clone");

    /* Parent falls through to here */

    if (verbose)
        printf("%s: PID of child created by clone() is %ld\n",
                argv[0], (long) child_pid);

    /* Update the UID and GID maps in the child */

    if (uid_map != NULL) {
        snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map",
                (long) child_pid);
        update_map(uid_map, map_path);
    }
    if (gid_map != NULL) {
        snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map",
                (long) child_pid);
        update_map(gid_map, map_path);
    }

    /* Limit child memory */
    fd = open("/sys/fs/cgroup/memory/cogsi/tasks", O_RDWR);
    if(fd == -1){
	errExit("open");
    }

    const int n = snprintf(NULL, 0, "%lu", (long) child_pid);
    char buf[n+1];
    int c = snprintf(buf, n+1, "%lu", (long) child_pid);

    res = write(fd, buf, n);
    if(res == -1){
        errExit("write");
    }

    close(args.pipe_fd[1]);

    if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
        errExit("waitpid");

    if (verbose)
        printf("%s: terminating\n", argv[0]);

    exit(EXIT_SUCCESS);
}


```
