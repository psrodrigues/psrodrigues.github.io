---
layout: post
title:  "XSS on Bibliopac (CVE-2018-16139)"
date:   2018-10-22 11:00:51 +0100
categories: web XSS
---


Good morning. Today I bring to attention a XSS vulnerability in a library management/inventory software, **Bibliopac** from Bibliosoft.
This software is used mainly in the Portuguese geographic region by several entities and it's somewhat old.
The reason that this could be dangerous has to do with the environment of the vulnerability.

![Bibliopac XSS 1]({{ "images/bibliopac/bibliopacIntro.png" | absolute_url}})

**Quick introduction to XSS attacks**

XSS vulnerabilities allow attackers to inject code (often Javascript code) into a webpage. By injecting Javascript code an attacker can try to steal authentication tokens, inject keyloggers ( [XSS-Keylogger](https://wiremask.eu/articles/xss-keylogger-tutorial/)) or even try to exploit several vulnerabilities in the WebKit engine to try to achieve remote code execution (like in the PS4 and Switch case [What do Nintendo Switch and iOS 9.3 have in common? CVE-2016-4657 walk-through](https://www.youtube.com/watch?v=xkdPjbaLngE)).
This type of vulnerability affects the clients itself and not the server data, at least in a direct way. Imagine if there is a backoffice. An a system administrator opens the link or visits the page with the payload and get their session cookie stolen. The attacker can now impersonate the identity of the administrator and escalate privileges.
The matter gets worst if, considering the environment there is a single sign-on authentication and the attacker is able to steal those authentication tokens then it can login in other applications that have connectors to that SSO authentication.


In my research I found on Google 176 results of this application running on several servers. The matter gets worst when we look at what institutions are running it.
Institutions related to education, city halls or even court-related institutions.

![Bibliopac XSS 1]({{ "images/bibliopac/bibliopacGoogle.png" | absolute_url}})

After discovering this vulnerability I contacted the developer of this application, however they stated that the software is deprecated and no patch will be issued. Confirming on their website, it is indeed an old software version and a new product is available (I did not test the new product).

Despite that the vulnerability still exists and can be exploited. The following URLs are prone to XSS:


* **/bibliopac/bin/wxis.exe/bibliopac/?IsisScript=bin/bibliopac.xic&db=BIBLIO*&lang=P&start=**
![Bibliopac XSS 1]({{ "images/bibliopac/xss1.png" | absolute_url}})


* **/bibliopac/bin/wxis.exe/bibliopac/?IsisScript=bin/bibliopac.xic&action=EXTRASEARCH*&search=**
![Bibliopac XSS 2]({{ "images/bibliopac/xss2.png" | absolute_url}})

Keep in mind that the db parameter could be different since the application allow for different Databases to be instaled.

If we analyze the source code we can se the * reflected on the page. Weaponizing the vulnerability we can trigger an alert message to prove that it works:
In the second injection point we see that it capitalizes the input so we need to (for example) point to a script on another location in order to fully exploit it.

**Concluding**

An attacker can exploit this vulnerability to extract additional information from a clients website. If for any change you need to have this product exposed mitigations are need to be placed to block this attack. There is also the possibility to have other injection points in the software but that wasn't fully tested.

**Timeline**

* 27/08/2018 - First contact to request security contact of the company
* 28/08/2018 - First response
* 31/08/2018 - Details sent
* 31/08/2018 - Response (deprecated 5 years ago) won't fix
* 31/08/2018 - Query to known if clients are going to be notified
* 22/10/2018 - No Response, publishing


**References**

[OWASP-XSS](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
[OWASP-XSS Mitigation](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)


I hereby don't incentivize to exploit this vulnerability for malicious purposes and my research was only an academic one without interference or harm to any people.


