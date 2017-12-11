# Running ws2016lab in Azure

I was always wondering how fast will be Azure VM to host ws2016lab since we [announced](https://azure.microsoft.com/en-us/blog/nested-virtualization-in-azure/) availability of nested virtualization in Azure. Thanks to @DaveKawula tweet I decided to give it a try as i have MSDN subscription with ~120eur credit/month

## Creating VM

To create VM, click on New and select Windows Server 2016 VM.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM01.png)

Provide some basic input, such as username and password you will use to connect to the VM.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM02.png)

The only machines with nested virtualization are D and E v3 machines. In MSDN you can consume up to 20 cores, therefore I selected D16S V3.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM03.png)

Select managed disks and also don't forget to enable Auto-Shutdown. Auto-Shutdown is really cool feature. Helps a lot managing costs of your lab. 

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM04.png)

Validate the settings and click on Create

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM05.png)

Once VM will finish deploying, you will be able to see it running on your dashboard.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/CreateVM06.png)

## Adding storage

**Note:** Premium disk is not the best choice as it drains your credit quite fast. So either use it and destroy, or use temp storage instead. You can store ws2016lab on OS and just copy to temp disk to deploy it there.

To add storage, click on add data disk under disks.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage01.png)

You will be able to specify disk. Since I did not have disk created, you can click on Create disk and wizard will open.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage02.png)

In wizard configure 4TB disk, just to have 7500 IOPS.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage03.png)

After disk is configured, you can configure host caching to Read/Write (since you don't care about loosing data)

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/AddStorage04.png)

## Overall experience

In machine overview you are able to connect (after click it will download rdp file with server IP in it), or you can just copy IP to clip and run remote desktop client from your pc. To cut down cots, you can stop VM from here

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/VMOverview.png)

Network is quite fast. Downloading image from eval center is ~ 200Mbits. I was able to see here also speeds around 500Mbits. I guess its because limited speed of source during the day in US.

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/DownloadSpeeds.png)

Performance during file copy inside S2D cluster was quite impressive. Usually its around 200MB/s. On this screenshot you can see peak almost 800MB/s

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DSpeed.png)

Hydration of ws2016 lab took 81 minutes

DC and 4 s2d nodes takes 5,6 minutes

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterHydration.png)

Scenario finishes in ~32 minutes

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterScenarioScript.png)

Enjoy!

![](/Scenarios/Running%20ws2016lab%20in%20Azure/Screenshots/S2DClusterScenarioScriptFinished.png)