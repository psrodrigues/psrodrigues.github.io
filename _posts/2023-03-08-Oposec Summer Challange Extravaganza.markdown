---
layout: post
title:  "Oposec Summer Challange Extravaganza"
date:   2023-03-08 01:01:00 +0100
categories: CTF
---

# Oposec Summer Challange Extravaganza

During the last summer, in colaboration with the [Oposec Metup](https://www.meetup.com/en/0xoposec/), we develop a CTF to be solved during the summer. The description of the environment and all the preparation is going to be shown in this article. 

Oposec is a metup arround Porto to gather and share Security related knowledge. It is a great experience to be on the lookout for new vectors and threats and to deepen the knowledge of the area. 

With that in mind it was proposed to create an environment where participants could enter and break the security of such machines at will in order to solve the challanges that they were presented.

# Preparation

Due to past incidents we knew that it would be risky to expose such assets in an uncontrolled manner. Exposing vulnerable assets will most surely get us compromised and makes us spend more money than we have available. For instance, lsat time someone tried to expose a Domain Controller attackers tried to bruteforce every single password combination and with that generated a lot of traffic, causing us to be billed more than we intended. 

The CTF would be mainly Windows based since all other challanges were Web based and we wanted to do something different so everyone can learn something new and call us names when stuff doesn't work the first time.

This is obviously undesired, so we decided to host everything behind a VPN. Now we are left with the design for the environment. We quickly noticed that provisioning 5 VMs over the whole summer will cost more than to buy the hardware itself and host us ourselves. Down the line we keep the hardware for later challenges. 

It was settled! We would buy stuff, keep it as a secret from our wifes and hope she could't tell by the noise of the server that we were hosting a complete CTF from our Home office =D.

# Hardware

To keep the secret from our ladies we needed to have a discrete server. Luckly nowadays there are several alternatives to do so. 

We could look at Raspbery PIs but since our environment would be primarly Windows-based (more on that later) it wouldn't work. It doesn't even have the necessary hardware requirements to virtualize all the necessary servers that we intended. 

We took the oportunity to look at Micro Workstations such as the HP HPE ProLiant MicroServe, Dell OptiPlex 3070 Micro, and ThinkCentre M710q. Big shout out to project miniMicro from Server the home where he showcased all "Micro Architecture" (They are acutaly called SFF or Small Form Factor Computers) (https://www.youtube.com/watch?v=bx4_QCX_khU&list=PLC53fzn9608B-MT5KvuuHct5MiUDO8IF4) PCs that help us choose one to our needs!

However those are quiet, great looking machines, they are still expensive. At the time, before the massive increase in prices we were looking at 1000+ euros for a new machine, so we decided to look at the used marked in stores such as BackMarket or OLX. Luckly we were able to get a Thinkcentre for 350 euros! Its not great but it is the start of something.

<insert image do sellerpt>

We knew that the specs were not going to be sufficient, we had a 128Gb NVME SSD, a Intel I5-10500M CPU and only 8Gb of RAM. But the hardware allows for great expansion. 
We scrape some parts from the old bin and we found an additional 250GB SSD and we proceeded in ordering an additional 8Gb SODIMM stick and a 1TB NVME SSD (Storage was going to be an issue with Machines).

To virtualize everything the obvious choice was Proxmox Virtual Environment. It offers enterprise grade solutions for free. You don't have any support but looking forward to work with templates,replications, clusters, and storages is far easier to 

So, in short we were left out with the following specs:

* Intel I5-10500M CPU
* 16GB of RAM
* Storage
    * 128GB NVME SSD (OS)
    * 250GB SSD
    * 1TB NVME SSD (For Good Luck)
* Proxmox Virtualization Server (OS)

# Network

As stated we shouldn't expose vulnerable assets to the Internet. This could bring unwanted attention to our address and it would impact legit players from interacting with the lab.

With that consideration in mind we needed to create a VPN for players to play at will. This brings several requirements to the lab.

Since this was a home connection, proper segregation and segmentation should exist of the lab itself. Only VPN client connections should be able to connect to the lab. 

Furthermore, no outbound connections should be allowed. This will prevent users with malicious intentions to pivot on the lab as a proxy to attack other Internet services. We should be liable in maintaining the lab only playable with the learning intent, and not as a pivot point to attack other networks. This brings a huge downside: no reverse shells are possible to the Internet.
We also wanted to block connections to the VPN Clients themselves that were not originated from the clients. Why? again, to avoid pivoting into the lab and reaching other VPN clients, blocking their "fun".
In other words... no reverse shell for you! Bind shells are OK.

The lab should be easabily reachable once the user has VPN access (one single segment to start should be enough to simulate one badly configured network).

We all these in mind we decided that we needed a firewall to easily manage all rules and VPN access to clients. 

Luckly, once again we were blessed with the marvalous Netgate 2100 with pfSense+ software to configure all these and to take the hit with all the connections. Previous tests were conducted and we could manage 15 concurrent connections performing scans with bandwith and processing power to spare! (We will take a look on all configurations in just a bit, we went a bit crazy with the security settings).

## Networks

### Network Rules

## Certificate Authority

## VPN

## Virtualized environment

### All machines

# Write-UP

# Conclusion and next steps