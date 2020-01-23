---
title: WSLab Introduction
description: Introduction to WSLab tools, that allows anyone to prepare lab environment for Windows Client and Windows Server
ms.prod: windows-server
ms.topic: article
author: JaromirKaspar
ms.author: Jaromirk
ms.technology: WSLab
ms.date: 01/23/2020
ms.localizationpriority: low
---

# WSLab Introduction

WSLab is a GitHub project that aims to provide virtual environments in Hyper-V, that can be built in consistent way. It comes at no additional cost, it's free and open sourced on [GitHub](https://aka.ms/wslab).

Unlike other solutions, WSLab focuses on simplicity (all actions can be done without typing complex scripts) and low profile (all disks are differencing, minimum requirements are 8GB RAM and 40GB free space). There is no special hardware requirement. WSLab can run on almost any machine that has SSD and decent amount of memory.

![](/media/Hyper-V_Manager01.png)

## Requirements

* Windows 10 Pro/Enterprise (as Hyper-V is required) or Windows Server 2016/2019
* 8GB RAM
* CPU with Virtualization support
* SSD
* 40GB free space

## Scripts

The main part of WSLab are [Scripts](https://aka.ms/wslabzip) that will help preparing lab files ([Hydration Phase](/WSLab-Hydration)). This phase is the most time consuming (1-2hours), but needs to be done only once. It will create virtual hard disks out of provided ISO and will create Domain Controller. [WSLab Deployment](/WSLab-Deployent) takes only few minutes as it will just import Domain Controller and will add other Virtual Machines as specified in LabConfig.ps1

![](/media/Explorer01.png)

## Use cases

### Prototyping

WSLab is ideal for prototyping. It will quickly spin Windows Server/Client environments that are connected to Internet and ready to be played with. If something goes wrong, there is nothing easier than just run Cleanup and then Deploy again

### Hands on Labs

WSLab virtual machines are defined in LabConfig.ps1 as simple hash table. This way you can share your configurations and create consistent, complex environments. Labs are easy to distribute. Once you are done with Hydration Phase, you can just copy result folder to multiple computers and deliver entire classes.

### Issue reproduction

Many times happened, that there was an issue that was hard to reproduce. And even if you could reproduce it, another person did not have the same environment, so even with the same steps, the issue might not occur again. WSLab changes this as all WSLab environments with the same LabConfig are the same. So only thing you need to share to other person to reproduce issue are steps and LabConfig.ps1.