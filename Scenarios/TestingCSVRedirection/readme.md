# About the lab

The intention is to create lab with SAN/SharedSpaces/S2D to test redirected traffic flow

The script creates three two-node clusters. It will create ReFS/NTFS volumes on each, and on each volume it creates VM

You can ten open perfmon to monitor redirected traffic when each VM starts.

Lab uses NanoServers (altrought it's not recommended for bare metal) as it is really small and consumes much less resources.

# Hyper-V backed by SAN

* Scenario simulates NTFS and ReFS disks.
* VMs on non-coordinator node SAN1
* Disks owned by node SAN2

![](/Hyper-V/TestingRedirection/Screenshots/SAN_VMs.PNG)
![](/Hyper-V/TestingRedirection/Screenshots/SAN_Disks.PNG)

* NTFS state is Direct on both nodes
* ReFS state is FileSystemRedirected on both nodes

![](/Hyper-V/TestingRedirection/Screenshots/SAN_CSVState.png)

## IO flow - SAN

### NTFS - SAN
* VM reads and writes directly into volume
* No redirected IO

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_Direct.png)
![](/Hyper-V/TestingRedirection/Screenshots/SAN.PNG)

### ReFS - SAN

* ReFS is File System Redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/SAN.PNG)


# Hyper-V backed by Shared Storage Spaces

* NTFS, Tiered NTFS and ReFS
* VMs on non-coordinator node SharedSS1
* Disks owned by node SharedSS2

![](/Hyper-V/TestingRedirection/Screenshots/SharedSS_VMs.PNG)
![](/Hyper-V/TestingRedirection/Screenshots/SharedSS_Disks.PNG)


* NTFS is BlockRedirected on non-coordinator (SharedSS1)
* TieredNTFS and ReFS are FileSystemRedirected

![](/Hyper-V/TestingRedirection/Screenshots/SharedSS_CSVState.png)


## IO Flow - SharedSS

### NTFS - SharedSS

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to  CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/SharedSS.PNG)

### Tiered NTFS - SharedSS

* Tiered NTFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/SharedSS.PNG)

### ReFS - SharedSS

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/SharedSS.PNG)


# Hyper-V backed by Storage Spaces Direct

* Simulation of NTFS and ReFS disks
* VMs on non-coordinator node S2D1
* Disks owned by node S2D2

![](/Hyper-V/TestingRedirection/Screenshots/S2D_VMs.PNG)
![](/Hyper-V/TestingRedirection/Screenshots/S2D_Disks.PNG)

* To CSV it looks the same as Shared Storage Spaces (Therefore same applies)
* NTFS is BlockRedirected on non-coordinator
* ReFS is FileSystemRedirected

![](/Hyper-V/TestingRedirection/Screenshots/S2D_CSVState.png)

## IO Flow - Storage Spaces Direct

### NTFS - Storage Spaces Direct

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/S2D.PNG)

### ReFS - Storage Spaces Direct

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Hyper-V/TestingRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Hyper-V/TestingRedirection/Screenshots/S2D.PNG)