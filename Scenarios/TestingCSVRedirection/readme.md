# About the lab

The intention is to create lab with SAN/SharedSpaces/S2D/SAN with Storage Replica to test redirected traffic flow

The script creates three two-node clusters and one four-node stretch cluster. It will create ReFS/NTFS volumes on each, and on each volume it creates VM

You can ten open perfmon to monitor redirected traffic when each VM starts.

Lab uses NanoServers (altrought it's not recommended for bare metal) as it is really small and consumes much less resources.

# Summary

Scenario | NTFS Volume State | ReFS Volume State | Tiered NTFS Volume State
---------|-------------------|-------------------|-------------------------
Hyper-V backed by SAN| Direct on all nodes | FS Redirected on all nodes | N\A
Hyper-V backed by Shared Spaces | Direct on Coordinator, Block Redirected on non-coordinator | FS Redirected on all nodes | FS Redirected on all nodes
Hyper-V backed by Storage Spaces Direct | Direct on Coordinator, Block Redirected on non-coordinator | FS Redirected on all nodes | N\A
Hyper-V with SR enabled, backed by SAN | Direct on Coordinator, Block Redirected on non-coordinator | FS Redirected on all nodes | N\A

# Hyper-V backed by SAN

* Scenario simulates NTFS and ReFS disks.
* VMs on non-coordinator node SAN1
* Disks owned by node SAN2

![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_VMs.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_Disks.png)

* NTFS state is Direct on both nodes
* ReFS state is FileSystemRedirected on both nodes

![](/Scenarios/TestingCSVRedirection/Screenshots/SAN_CSVState.png)

## IO flow - SAN

### NTFS - SAN
* VM reads and writes directly into volume
* No redirected IO

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_Direct.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN-NTFS.png)

### ReFS 3.0+ - SAN

* ReFS is File System Redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SAN-ReFS.png)


# Hyper-V backed by Shared Storage Spaces

* NTFS, Tiered NTFS and ReFS
* VMs on non-coordinator node SharedSS1
* Disks owned by node SharedSS2

![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_VMs.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_Disks.png)


* NTFS is BlockRedirected on non-coordinator (SharedSS1)
* TieredNTFS and ReFS are FileSystemRedirected

![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS_CSVState.png)


## IO Flow - SharedSS

### NTFS - SharedSS

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to  CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS-NTFS.png)

### Tiered NTFS - SharedSS

* Tiered NTFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS-TieredNTFS.png)

### ReFS 3.0+ - SharedSS

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SharedSS-ReFS.png)


# Hyper-V backed by Storage Spaces Direct

* Simulation of NTFS and ReFS disks
* VMs on non-coordinator node S2D1
* Disks owned by node S2D2

![](/Scenarios/TestingCSVRedirection/Screenshots/S2D_VMs.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D_Disks.png)

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
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D-NTFS.png)

### ReFS 3.0+ - Storage Spaces Direct

* ReFS is FileSystem redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/S2D-ReFS.png)

# Hyper-V with Storage Replica enabled, backed by SAN

* Scenario simulates NTFS and ReFS disks.
* VMs on non-coordinator node SRSite1_Node1
* Disks owned by node SRSite1_Node2

![](/Scenarios/TestingCSVRedirection/Screenshots/SR_VMs.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SR_Disks.png)

* NTFS is BlockRedirected on non-coordinator
* ReFS state is FileSystemRedirected on both nodes
* Volume2 is Log formatted with NTFS

![](/Scenarios/TestingCSVRedirection/Screenshots/SR_CSVState.png)

## IO flow - SR SAN

### NTFS - SR SAN

* NTFS is block redirected
* IO flows through CSVFS (direct IO) to CSV Volume Manager
* Volume Manager redirects it to coordinator over the network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_BlockRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SR-NTFS.png)

### ReFS 3.0+ - SR SAN

* ReFS is File System Redirected
* CSVFS redirects IO to coordinator
* Notice 0 in CSV volume manager as CSVFS did send it over network

![](/Scenarios/TestingCSVRedirection/Screenshots/Drawing_FileSystemRedirected.png)
![](/Scenarios/TestingCSVRedirection/Screenshots/SR-ReFS.png)

