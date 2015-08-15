Anti-HTTP flood (Apache Only)
============

This script helps to prevent and neutralize Apache floods / DDoS attacks. 
Unfortunately it is not as effective as it used to be because many DDoS attacks are not layer-7, 
but if you have no protection at all and keep getting HTTP floods using apache server, then this
will help you weed out some of the drive-by bad guys hitting your server.

I am no longer using this script so I have made it open source and unlicensed it in hopes that 
it will be useful to someone who cannot afford advanced DDoS protection and is simply being
hit by low-bandwidth layer-7 attacks.

Requirements
============

This library requires `PHP >= 5.x`, and `Apache 2.x` but will probably also work on PHP4 if you're still using it. 
You must have mod_status enabled AND viewable by 127.0.0.1/localhost in Apache for the scanner to work. 

Installation
============

To install, upload antiflood.php to a folder on your server where you have permission to execute. It would be best to execute this
script as someone with root permissions. Create a subfolder called flood_logs so you will get a log/snapshot of the status page whenever 
an IP is banned.

Usage
=====

The script can be tested by simply running `./antiflood.php` at the terminal. It will immediately begin scanning the server
for excessive connections.  The values I have placed are particularly high by default, but everyone's server and needs are
different so you may be required to adjust them. Each setting is explained below:

`$apache_connections_limit = "67";` - This is the maximum number of connections an IP address can have on apache's /server-status page. 
The default is 67 and worked well for me. If your users are known to have more concurrent connections than this, then raise it. It assumes
a KeepAliveTimeOut of 3.

`$connections_limit = "650";` - This is the maximum number of open sockets to allow a single IP address to have, regardless of current state. 
It works independently of Apache

$SYNRECV_connections_limit = "150";  - This is the maximum number of SYN_REC (Syn Received) to allow a single IP address to have. This means
the connection hasn't been established yet and it's waiting. A lot of these is very bad to have from one IP.

$ESTABLISHED_connections_limit = "60";  // This is the maximum number of fully established connections to allow a single IP address to have. Many
of these is bad if you're ONLY hosting an HTTP server as connections seem to come and go. The default is 60; but be careful with this if
you're hosting other services where a constant connection is normal.