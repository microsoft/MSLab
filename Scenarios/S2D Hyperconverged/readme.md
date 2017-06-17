# Scenario Description

* In this scenario 2-16 node S2D cluster can be created.
* It is just simulation "how it would look like". Performance is not a subject here.
* It is just to test look and feel
* Script is well tested, on both real and simulated environments. However if you need assist, ask your Premier Field Engineer
* This is just one of many scripts that I did internally for Microsoft employees. Shoud be used for education purposes. For real-world deployments it may differ, therefore never ever just paste the script into production! If you want assist, please ask your Technical Accout Manager, or ping me at jaromirk@microsoft.com


# Scenario requirements

* Windows 10 1511 with enabled Hyper-V or Windows 10 1607 (if nested virtualization is enabled)
* 8GB Memory or 20GB if nested virtualization is used (for 4 node configuration)
* SSD (with HDD it is really slow)

# How it looks like end-to-end (when you just paste the script). 
Note, there are small differences (we did not configure fault domains, but it is displayed on GIF as I did it a while ago.

![](https://github.com/Microsoft/ws2016lab/blob/master/Docs/Screenshots/s2d_Hyperconverged.gif)
