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
            return "only accept letters"

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
            return "only letters"
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
        return "cannot reach"

    return final_list

import socket

def port_scanner(ip:str,port:int) -> int:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)

        #returns zero if successful
        return s.connect_ex((ip, port))

####### work in progress
#from scapy.all import PcapReader
#def ip_pcap_parser(path:str,ip:str) -> list:

#    with PcapReader('path') as reader:


