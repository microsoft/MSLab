[global_tags]
  # clustername = 

[agent]
  interval = "10s"
  round_interval = true
  metric_buffer_limit = 1000
  flush_buffer_when_full = true
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  debug = false
  quiet = false
  logfile = ""
  hostname = ""

[[outputs.influxdb]]
  urls = ["PlaceInfluxDBUrlHere"] 
  database = "telegraf"
  precision = "s"
  timeout = "5s"

[[inputs.exec]]
  commands = ["powershell C:/PROGRA~1/telegraf/telegraf.ps1"]
  timeout = "9s"

[[inputs.win_perf_counters]]
  [[inputs.win_perf_counters.object]]
    # Processor usage, alternative to native, reports on a per core.
    ObjectName = "Processor"
    Instances = ["*"]
    Counters = [
      "% Idle Time",
      "% Interrupt Time",
      "% Privileged Time",
      "% User Time",
      "% Processor Time",
      "% DPC Time"
    ]
    Measurement = "win_cpu"
    # Set to true to include _Total instance when querying for all (*).
    IncludeTotal=true

  [[inputs.win_perf_counters.object]]
    # Disk times and queues
    ObjectName = "LogicalDisk"
    Instances = ["*"]
    Counters = [
      "% Idle Time",
      "% Disk Time",
      "% Disk Read Time",
      "% Disk Write Time",
      "Current Disk Queue Length",
      "% Free Space",
      "Free Megabytes"
    ]
    Measurement = "win_disk"
    # Set to true to include _Total instance when querying for all (*).
    #IncludeTotal=false

  [[inputs.win_perf_counters.object]]
    ObjectName = "PhysicalDisk"
    Instances = ["*"]
    Counters = [
      "Disk Read Bytes/sec",
      "Disk Write Bytes/sec",
      "Avg. Disk sec/Transfer",
      "Avg. Disk sec/Read",
      "Avg. Disk sec/Write",
      "Disk Transfers/sec",
      "Current Disk Queue Length",
      "Disk Reads/sec",
      "Disk Writes/sec",
      "% Disk Time",
      "% Disk Read Time",
      "% Disk Write Time",
      "% Idle Time",
      "Split IO/Sec"
    ]
    Measurement = "win_diskio"

  [[inputs.win_perf_counters.object]]
    ObjectName = "Network Interface"
    Instances = ["*"]
    Counters = [
      "Bytes Received/sec",
      "Bytes Sent/sec",
      "Bytes Total/sec",
      "Packets Received/sec",
      "Packets Sent/sec",
      "Packets Received Discarded",
      "Packets Outbound Discarded",
      "Packets Received Errors",
      "Packets Outbound Errors"
    ]
    Measurement = "win_net"

  [[inputs.win_perf_counters.object]]
    ObjectName = "System"
    Counters = [
      "Context Switches/sec",
      "System Calls/sec",
      "Processor Queue Length",
      "System Up Time"
    ]
    Instances = ["------"]
    Measurement = "win_system"
    # Set to true to include _Total instance when querying for all (*).
    #IncludeTotal=false

  [[inputs.win_perf_counters.object]]
    # Example query where the Instance portion must be removed to get data back,
    # such as from the Memory object.

  [[inputs.win_perf_counters.object]]
    # Example query where the Instance portion must be removed to get data back,
    # such as from the Paging File object.
    ObjectName = "Paging File"
    Counters = [
      "% Usage"
    ]
    Instances = ["_Total"]
    Measurement = "win_pagefile"

#########
# From other github
# https://github.com/janegilring/WindowsPerformance/tree/master/Storage%20Spaces%20Direct
#########

  [[inputs.win_perf_counters.object]]
    # Example query where the Instance portion must be removed to get data back,
    # such as from the Memory object.
    ObjectName = "Memory"
    Counters = [
      "Available Bytes",
      "Cache Faults/sec",
      "Demand Zero Faults/sec",
      "Page Faults/sec",
      "Pages/sec",
      "Page Reads/sec",
      "Page Writes/sec",
      "Transition Faults/sec",
      "Pool Nonpaged Bytes",
      "Pool Paged Bytes",
      "Standby Cache Reserve Bytes",
      "Standby Cache Normal Priority Bytes",
      "Standby Cache Core Bytes",
      "Cache Bytes"
    ]
    # Use 6 x - to remove the Instance bit from the query.
    Instances = ["*"]
    Measurement = "win_mem"
    # Set to true to include _Total instance when querying for all (*).
    IncludeTotal=true

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Virtual Machine Health Summary"
    Instances = ["------"]
    Measurement = "hyperv_health"
    Counters = [
      "Health Ok",
      "Health Critical"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Hypervisor"
    Instances = ["------"]
    Measurement = "hyperv_hypervisor"
    Counters = [
      "Logical Processors",
      "Partitions"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Hypervisor Virtual Processor"
    Instances = ["*"]
    Measurement = "hyperv_processor"
    Counters = [
      "% Guest Run Time",
      "% Hypervisor Run Time",
      "% Idle Time",
      "% Total Run Time"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Hypervisor Logical Processor"
    Instances = ["*"]
    Measurement = "hyperv_host_processor"
    Counters = [
      "% Guest Run Time",
      "% Hypervisor Run Time",
      "% Idle Time",
      "% Total Run Time"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Dynamic Memory VM"
    Instances = ["*"]
    Measurement = "hyperv_dynamic_memory"
    Counters = [
      "Current Pressure",
      "Guest Visible Physical Memory"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V VM Vid Partition"
    Instances = ["*"]
    Measurement = "hyperv_vid"
    Counters = [
      "Physical Pages Allocated"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Virtual Switch"
    Instances = ["*"]
    Measurement = "hyperv_vswitch"
    Counters = [
      "Bytes Received/Sec",
      "Bytes Sent/Sec",
      "Packets Received/Sec",
      "Packets Sent/Sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Virtual Network Adapter"
    Instances = ["*"]
    Measurement = "hyperv_vmnet"
    Counters = [
      "Bytes Received/Sec",
      "Bytes Sent/Sec",
      "Packets Received/Sec",
      "Packets Sent/Sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Virtual IDE Controller"
    Instances = ["*"]
    Measurement = "hyperv_vmdisk"
    Counters = [
      "Read Bytes/Sec",
      "Write Bytes/Sec",
      "Read Sectors/Sec",
      "Write Sectors/Sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Hyper-V Virtual Storage Device"
    Instances = ["*"]
    Measurement = "hyperv_storage"
    Counters = [
      "Write Operations/Sec",
      "Read Operations/Sec",
      "Read Bytes/Sec",
      "Write Bytes/Sec",
      "Latency",
      "Throughput"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster CSV File System"
    Instances = ["*"]
    Measurement = "cluster_csv_filesystem"
    Counters = [
      "Flushes/sec",
      "Reads/sec",
      "Writes/sec",
      "Read Latency",
      "Write Latency",
      "Redirected Write Bytes/sec",
      "Redirected Read Bytes/sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster CSVFS"
    Instances = ["*"]
    Measurement = "cluster_csv_fs"
    Counters = [
      "Reads/sec",
      "Writes/sec",
      "Read Bytes/sec",
      "Write Bytes/sec",
      "Avg. sec/Read",
      "Avg. sec/Write"
    ]
    IncludeTotal=true

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster Storage Hybrid Disks"
    Instances = ["*"]
    Measurement = "cluster_csv_caching"
    Counters = [
      "Cache Hit Read Bytes/sec",
      "Cache Miss Read Bytes/sec",
      "Cache Hit Reads/sec",
      "Cache Miss Reads/sec",
      "Direct Write Bytes",
      "Direct Write Bytes/sec",
      "Destage Bytes",
      "Destage Bytes/sec",
      "Destage Transfers/sec",
      "Disk Read Bytes/sec",
      "Disk Reads/sec",
      "Disk Writes Bytes/sec",
      "Disk Writes/sec",
      "Cache First Hit Populated Bytes",
      "Cache First Hit Populated Bytes/sec",
      "Cache First Hit Written Bytes/sec",
      "Cache Write Bytes/sec",
      "Cache Writes/sec",
      "Cache Pages Dirty",
      "Cache Pages Dirty Hot",
      "Cache Pages Standby",
      "Disk Bytes",
      "Disk Transfers/sec",
      "Cache Populate Bytes",
      "Cache Populate Bytes/sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster Storage Cache Stores"
    Instances = ["*"]
    Measurement = "cluster_csv_stores_caching"
    Counters = [
      "Update Bytes",
      "Update Bytes/sec",
      "Update Transfers/sec",
      "Cache Pages",
      "Cache Pages Bytes",
      "Cache Pages Dirty",
      "Cache Pages Free",
      "Cache Pages Standby",
      "Bindings Enabled",
      "Bindings Active",
      "Cache Usage %",
      "Cache Usage Efficiency %",
      "Cache Stores",
      "Destage Bytes",
      "Destage Bytes/sec",
      "Destage Transfers/sec",
      "Devices Hybrid",
      "Page ReMap/sec",
      "Destaged At Normal Pri. %",
      "Destaged At Low Pri. %"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster Storage Hybrid Disks IO Profile"
    Instances = ["*"]
    Measurement = "cluster_csv_profile_caching"
    Counters = [
      "Reads/sec Paging IO",
      "Writes/sec Paging IO"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster CSVFS Block Cache"
    Instances = ["*"]
    Measurement = "cluster_csv_block_caching"
    Counters = [
      "% Cache Valid",
      "Cache IO Read - Bytes/sec",
      "Cache Size - Configured",
      "Cache Size - Current",
      "Disk IO Read - Bytes/sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster Disk Counters"
    Instances = ["*"]
    Measurement = "cluster_csv_disk_caching"
    Counters = [
      "Read/sec",
      "Writes/sec",
      "Read - Bytes/sec",
      "Write - Bytes/sec",
      "Read Latency",
      "Write Latency"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "SMB Server Shares"
    Instances = ["*"]
    Measurement = "cluster_csv_server_shares"
    Counters = [
      "Data Requests/sec",
      "Read Requests/sec",
      "Write Requests/sec",
      "Data Bytes/sec",
      "Read Bytes/sec",
      "Write Bytes/sec",
      "Transferred Bytes/sec",
      "Received Bytes/sec",
      "Sent Bytes/sec"
    ]

  [[inputs.win_perf_counters.object]]
    ObjectName = "RDMA Activity"
    Instances = ["*"]
    Counters = [
      "RDMA Accepted Connections",
      "RDMA Active Connections",
      "RDMA Completion Queue Errors",
      "RDMA Failed Connection Attempts",
      "RDMA Inbound Bytes/sec",
      "RDMA Outbound Bytes/sec"
    ]
    Measurement = "rdma_activity"

  [[inputs.win_perf_counters.object]]
    ObjectName = "Cluster NetFt Heartbeats"
    Counters = [
      "Missing heartbeats"
    ]
    Instances = ["*"]
    Measurement = "missing_cluster_heartbeats"

  [[inputs.win_perf_counters.object]]
    ObjectName = "Mellanox WinOF-2 Port QoS"
    Counters = [
      "Bytes Received",
      "Bytes Sent",
      "Rcv Pause Frames",
      "Sent Pause Frames"
    ]
    Instances = ["*"]
    Measurement = "mellanox_adapter_qos"

  [[inputs.win_perf_counters.object]]
    ObjectName = "Storage Spaces Drt"
    Counters = [
      "Dirty Count",
      "Dirty Bytes",
      "Synchronizing Count",
      "Limit",
      "Locked Bytes"
    ]
    Instances = ["*"]
    Measurement = "storage_spaces_drt"
