---
layout: post
title:  "Path Traversal Reprise Licence Manager (CVE-2018-5716)"
date:   2018-02-16 17:20:51 +0100
categories: web path-traversal
---

This post will demonstrate a vulnerability in the **Reprise Licence Manager (RLM) version 11.0**  found while doing a pentest. The vulnerability in question allows a user with access to the Web Management Interface to access (and sometimes write) files in the System.

This vulnerability allows to access files, and therefore gather aditional info about the system, and also delete the log file of the RLM server (in case of the file write permission).

This situation was reported to the **Reprise Software Inc.** and was promply considered **NOT A VULNERABILITY** since the application was to be installed as a non-priviledged user. However I strongly disagree since an attacker can access some files that are available for all users on the system. This issue could be easly resolved by having a list of files where the application can access and limit the access to the Web Application only.

A **CVE ID (CVE-2018-5716)** was issue for this vulnerability and is going to be released soon.

Without any further ado here comes the details of it:

An attacker who can access the Web Management Interface can edit licence files, license files have an arbitrary path where a person can edit. Changing the path to some other file will render it access to that file.

One interesting aspect is that you can write any extension for the file so .EXE files where an attacker could write executable files. However, **the [<>&] aren't allowed** so introducing WebShells won't be so easy.

![Uploading an EXE Extension File]({{ "images/reprise_path_traversal/reprise_exe_upload.png" | absolute_url}})

The vector itself that this vulnerability is refering will be located on the http(s)://ipOfServer:port/**/goform/edit_lf_get_data**. Analysing the request with burp we can see the parameter where a full path of a file is being send:

![Request with potention Arbitrary file Read]({{ "images/reprise_path_traversal/reprise_path_trans.png" | absolute_url}})

If we change the path to some file out of the directory structure, like for example the hosts file in windows we can see the response in the Web browser where the file will be presented:
![Arbitrary File Read]({{ "images/reprise_path_traversal/reprise_path_hosts.png" | absolute_url}})
![Arbitrary File Read 2]({{ "images/reprise_path_traversal/reprise_exploited.png" | absolute_url}})


As we can see in the picture above a file outside the Web root was acessed without any control. The matter is worsen since the application accepts in the user interface any file, by direct input thus Reprise Software Inc. won't consider this a vulnerability. However an attacker can overwrite some important files, like the application log hence hidding their tracks. A solution passes by limiting the file access to the directory structure or to a license folder, avoiding the writting of files with different extensions.

Next I present to you the form where you can input any file to be read (and then overwritten, giving the permissions):
![Arbitrary File Read 3]({{ "images/reprise_path_traversal/reprise_arb1.png" | absolute_url}})
![Arbitrary File Read 4]({{ "images/reprise_path_traversal/reprise_arb2.png" | absolute_url}})


For testing and record next is the about page where it states the product version:
![About]({{ "images/reprise_path_traversal/reprise_about.png" | absolute_url}})


On conclusion, this is my opinion **only**, that this behaviour represents a danger since the attacker can read arbitrary data provided its stored on the disk **AND** we have permission to read. However a lot of information can be retrieved from files that have low permissions standards. The recomendation that the company gave me is to lower the permissions level so the application can't read critical files, but I think that solution won't be enough and based on the OWASP Path Transversal ([OWASP Path Transversal](https://www.owasp.org/index.php/Path_Traversal)) it is still considered a vulnerability. There is the possibility to disable the interface. 

I hereby don't incentivize to exploit this vulnerability for malicious purposes and me research was only an academic one without interference or harm to any people.


