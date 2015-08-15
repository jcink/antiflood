#!/usr/bin/php -c /etc/php-cmd.ini
<?php


/***************************************************
 * Anti HTTP Flood (Apache)
 *
 * @author      John Cuppi
 * @code        http://github.com/jcink/antiflood
 * @license     http://unlicense.org/UNLICENSE
 * @version     1.0
 * @updated     11:36 PM Friday, April 29, 2011
 * @description Protects Apache from HTTP floods.
 *
 ****************************************************/
 
set_time_limit(0); 
ini_set('default_socket_timeout',    1); 

$apache_connections_limit = "67"; // apache connections limit
$connections_limit = "650"; // open connections in general

$SYNRECV_connections_limit = "150";  // max SYN_RECs to allow in limbo
$ESTABLISHED_connections_limit = "60";  // max ESTABLISHEDs to allow in limbo

echo "----------------------------------- \n";
echo "Anti HTTP flood script \n";
echo "-----------------------------------\n\n";

system("uname -a");

while(1) {

$raw_nstat = `nice --adjustment=19 netstat -ntu`;

$data = fopen("netstat.txt","w");
fwrite($data, $raw_nstat);
fclose($data);

# ------------------------------------------------------------
# Basic floods with a complete/incomplete handshake
# Doesn't really matter much which
# ------------------------------------------------------------

$netstat_query_1 = `cat netstat.txt | grep ':' | awk '{print \$5}' | awk '{sub("::ffff:","");print}' | cut -f1 -d ':' | sort | uniq -c | sort -nr`;
$sorted_data = explode("\n", $netstat_query_1);

foreach ($sorted_data as $k=>$v) {
	$ip_info = explode(" ", trim($v));
	if($ip_info[0] > $connections_limit) {
		
		firewall($ip_info[1], "{$ip_info[0]} total open tcp connections detected.");

	}
}

# ------------------------------------------------------------
# SYN_RECVs. This is to detect/help with a SYN flood.
# These will jam up the http server pretty quickly.
# ------------------------------------------------------------

$netstat_query_2 = `cat netstat.txt | grep 'SYN_RECV' | grep ':' | awk '{print \$5}' | awk '{sub("::ffff:","");print}' | cut -f1 -d ':' | sort | uniq -c | sort -nr`;
$sorted_data = explode("\n", $netstat_query_2);

foreach ($sorted_data as $k=>$v) {
	$ip_info = explode(" ", trim($v));
	if($ip_info[0] > $SYNRECV_connections_limit) {

		firewall($ip_info[1], "{$ip_info[0]} SYN_RECV connections detected.");
	
	}
}

# ------------------------------------------------------------
# ESTABLISHEDs. This will block off slow POST floods
# ala wikileaks, slowloris type attacks.
# ------------------------------------------------------------

$netstat_query_3 = `cat netstat.txt | grep 'ESTABLISHED' | grep ':80' | awk '{print \$5}' | awk '{sub("::ffff:","");print}' | cut -f1 -d ':' | sort | uniq -c | sort -nr`;
$sorted_data = explode("\n", $netstat_query_3);

foreach ($sorted_data as $k=>$v) {
	$ip_info = explode(" ", trim($v));
	if($ip_info[0] > $ESTABLISHED_connections_limit) {

		firewall($ip_info[1], "{$ip_info[0]} ESTABLISHED connections detected.");
	
	}
}


# ------------------------------------------------------------
# Query apache's server_status page and remove offending IPs
# http://localhost/server-status or otherwise, needs mod_status
# ------------------------------------------------------------

// the request for server status
$server_status = file_get_contents("http://localhost/server-status");

if ( $server_status ) {

// Our great regex
preg_match_all("@((?:\d{1,3}\.){3}\d{1,3})@",$server_status,$matches); 

// Gather up connection and IP info
foreach ($matches[1] as $k=>$v) {
	$iparray[$v]++;
}

// Sort it all out
foreach ($iparray as $k=>$v) {
if($v > $apache_connections_limit) {
	
	$snap_log=1;
	
	firewall($k, "$v httpd connections detected.");

}
}

unset($iparray);

// Did IPs get banned? Take an HTML based snapshot of the
// page so we can see what it looked like.

if($snap_log) {
	$server_status_log=@fopen("./flood_logs/server-status-".time().".txt","a");
	@fwrite($server_status_log, $server_status);
	@fclose($server_status_log);
}
	unset($snap_log);


						}

sleep(4);
echo "Checking...\n";

}

// Firewall function, this
// does all of the bannage.

function firewall($ip,$reason) {
global $session_banned;

	if($ip != "127.0.0.1" AND $ip != "::1" AND !$session_banned[$ip]) {

		// Tell us about a blockage.
		print "[ $ip ] blocked: $reason \n";

		// Block in IPtables
		system("iptables -I INPUT -s {$ip} -j DROP");
		
		$deny = fopen("deny_hosts.rules","a");
		$today = @date("F j, Y, g:i a");  
		fwrite($deny, "# Banned on {$today} with reason: $reason \n");
		fwrite($deny, "$ip");
		fwrite($deny, "\n");
		fclose($deny);
		
		// we banned this IP already for this run
		$session_banned[$ip]=1;
	}
	
}

?>
