# About the lab

The intention is to create lab with SAN/SharedSpaces/S2D to test redirected traffic flow

The script creates three two-node clusters. It will create ReFS/NTFS volumes on each, and on each volume it creates VM

You can ten open perfmon to monitor redirected traffic when each VM starts.

Lab uses NanoServers (altrought it's not recommended for bare metal) as it is really small and consumes much less resources.

# Hyper-V backed by SAN

* Scenario simulates NTFS and ReFS disks.
* VMs on non-coordinator node SAN1
* Disks owned by node SAN2

![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_VMs.PNG)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_Disks.PNG)

* NTFS state is Direct on both nodes
* ReFS state is FileSystemRedirected on both nodes

![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_CSVState.png)

## IO flow - SAN

### NTFS - SAN
* VM reads and writes directly into volume
* No redirected IO

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_Direct.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN.PNG)

### ReFS 3.0+ - SAN

* ReFS is File System Redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN.PNG)


# Hyper-V backed by Shared Storage Spaces

* NTFS, Tiered NTFS and ReFS
* VMs on non-coordinator node SharedSS1
* Disks owned by node SharedSS2

![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_VMs.PNG)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_Disks.PNG)


* NTFS is BlockRedirected on non-coordinator (SharedSS1)
* TieredNTFS and ReFS are FileSystemRedirected

![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_CSVState.png)


## IO Flow - SharedSS

### NTFS - SharedSS

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to  CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS.PNG)

### Tiered NTFS - SharedSS

* Tiered NTFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS.PNG)

### ReFS 3.0+ - SharedSS

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS.PNG)


# Hyper-V backed by Storage Spaces Direct

* Simulation of NTFS and ReFS disks
* VMs on non-coordinator node S2D1
* Disks owned by node S2D2

![](/Scenarios/TestingCSVRedirection/Screenshots/S2D_VMs.PNG)
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D_Disks.PNG)

* To CSV it looks the same as Shared Storage Spaces (Therefore same applies)
* NTFS is BlockRedirected on non-coordinator
* ReFS is FileSystemRedirected

![](/Scenarios/TestingCSVRedirection/Screenshots/S2D_CSVState.png)

## IO Flow - Storage Spaces Direct

### NTFS - Storage Spaces Direct

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D.PNG)

### ReFS 3.0+ - Storage Spaces Direct

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D.PNG)