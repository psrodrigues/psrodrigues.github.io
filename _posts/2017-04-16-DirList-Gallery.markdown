---
layout: post
title:  "DirList PHP Partial Path Transversion (PNG/JPG and MP3 Files)"
date:   2017-04-16 19:00:00 +0100
categories: Web PHP Path_Transversion
---
When I was auditing a website I came across a directory List using a well-known code, DirList. This code supplies the client to a directory list of files and allow for management with a nice interface without having to remotly login in the web server.
I quickly check for exploits and, at this date, there was two [Arbitrary File Upload](https://www.exploit-db.com/exploits/41083/) and [Local File Inclusion](https://www.exploit-db.com/exploits/37617/). However these exploit were already patched. So I download a copy for myself and start thinkering to see if someone forgot something.

When I check the exploits both were mitigated, however there was a piece of code that caught my eye.
In the "Media" files the flawed code was present.

{% highlight php %}
$folder = '../'.$dir_to_browse.base64_decode($_GET['folder']);

if(!is_dir($folder)) die("<b>Error:</b> Folder specified does not exist. This could be because you manually entered the folder name in the URL or you don't have permission to access this folder");

$content = get_dir_content($folder);

foreach($content['files']['name'] as $key => $val)
{
	if(in_array(strtolower(strrchr($val, '.')), array('.jpg', '.jpeg', '.png', '.gif')))
	{
		$path = $folder.'/'.$val;
		$images_paths[] = $path;

		@$js_images_names .= '\''.$val.'\', ';
		@$js_images_file_sizes .= '\''.letter_size(filesize($path)).'\', ';

		$dimensions = getimagesize($path);
		$images_widths[] = $dimensions[0];
		$images_heights[] = $dimensions[1];

		@$js_images_heights .= '\''.$dimensions[1].'\', ';
		@$js_images_widths .= '\''.$dimensions[0].'\', ';
		@$js_images_download_link .= '\''.base64_encode($dir_to_browse.base64_decode($_GET['folder']).'/'.$val).'\', ';
	}
}
{% endhighlight %}

You can notice on this piece of code that the GET parameter is passed to the "$folder" variable without being verified for illegal characters. This allows someone to choose an arbitrary location.
However in the foreach cycle it checks the file extension for images, since this is a media gallery.
The main concern is to encode our path to base64 so it can be decoded when it reaches to the attribuition to the "$folder" variable.

To test if it can be indeed vulnerable I encoded a common path in my testing machine ("../../../../etc/grub.d/backup/boot_grub/themes/ubuntu-mate/") and finally I got a result.


![GettingPartialPathTransversial]({{ site.url }}/assets/images/dirListPathTransversial.png)

This allows an attacker to search for images on the web application and outside of it.
This is a limited attack but since it's common to see one server hosting several applications it can be usefull in some scenarios. One scenario that I can immagine is if a Scanner is attached or it has a folder where clients drop proof of purchase and the filename is unknown It can be usefull not only to get the filename but the image if it is uploaded as images.

A similar vulnerability is present in "media_player_files/generate_playlist.php". This file will generate a playlist of mp3 files but it suffers from the same vulnerability as the previous one, but insted of images its ".mp3" files. 


{% highlight php %}
$folder = '../../'.$dir_to_browse.base64_decode($_GET['folder']);
$dir_content = get_dir_content($folder);
$mp3s = array();

//filter out to keep only mp3 files
foreach($dir_content['files']['name'] as $val)
	if(strtolower(strrchr($val, '.')) == '.mp3')
		$mp3s[] = $val;
{% endhighlight %}

Mitigation: Normally sysadmins deploy these files but don't actually need them. One option is not to deploy them. The other one is to parse the input to a list of known available directories so they can be listed or filter the input to decode the base64 and prevent illegal chars (illegal such as .. and . aswell as others).

Probably there could be even more problems but I haven't look at it. I encourage everyone to test them.
