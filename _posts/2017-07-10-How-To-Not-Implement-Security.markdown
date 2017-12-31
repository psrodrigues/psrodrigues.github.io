---
layout: post
title:  "How to not implement Security - A tale of Hidden Text"
date:   2017-07-10 00:00:00 +0100
categories: JavaScript
---
Finnaly with some time to write. This time I want to point out a very usual mistake done in Web Applications programming wich is hidding content with JavaScript. Time and time again I see this "Mistake", on Universities, Shopping sites and on web newspappers.

Recently I was browsing a news site and suddenly I couldn't load the whole story since I was using an ad-blocker and since I didn't pay for a subscription (Obviously). Altough it was a very interesting story and I really wanted to read.

![Reaching Limit of Articles]({{ site.url }}/images/publicoStory/limitedeArtigos.png)


And after the limit is reached we are presented with this:

![Limit Reached]({{ site.url }}/images/publicoStory/limiteReached.png)


The very first thing that I saw was a subtle fade-out of the text on the story and I started wondering were the hell the text went. Of course, being me the very next thing is to see the source-code and, surprise surprise. There was the rest of the story. Not in a so friendly view but I could finish reading it.

![Source Code of the Article]({{ site.url }}/images/publicoStory/sourceLimiteReached.png)

I then check other stories and the same thing happend, the story will be loaded but it will be hidden. Python to the rescue then! I created a litle script that recieves the URL of the story and clean everything to present with the raw text of the story. I could obviously create a document with all the images and stuff but, normally, the images appear on the header of the page and are not hidden (Some exceptions apply). 

{%highlight python %}

import urllib2,re,sys
from bs4 import BeautifulSoup

#This script will show, in a more user-friendly way, the hidden news in the publico.pt website

#Check for news link

if len(sys.argv) != 2:
    print "No News Portal was passed"
    sys.exit(1)

#Execute the request

req = urllib2.Request(sys.argv[1])
response = urllib2.urlopen(req)
noticia = response.read()

#Parse the data to be more user-friendly

soup = BeautifulSoup(noticia,'html.parser')
story = soup.find(id="story-body")

for entry in story.find_all('p'):
    prep = str(entry)
    stripExtra = re.sub(r"<[a-zA-Z/]*>",r"",prep)
    print stripExtra

sys.exit(0)


{% endhighlight %}

![Article from the Script]({{ site.url }}/images/publicoStory/pythonInAction.png)

To summarize, if you are building a web portal. Check permissions first hand and don't just hide information. A simple mitigation for this issue is to, when clicking on the button to read the whole story an AJAX request is made to the server where is going to check the login information. This will help the changes not be so abrupt to the application.
Also, this is just an example of what could happen I don't endorse this method and if you really want to read some the news on this or another paid website, you should contribuite to that newspapper so they can keep doing their good job.

