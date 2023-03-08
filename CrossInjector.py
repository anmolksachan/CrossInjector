import os
import sys
import requests
import argparse
import time
import urllib.parse as urlparse
from termcolor import colored
from urllib.parse import parse_qs

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Selenium and webdriver_manager modules not found. Please make sure they are installed.")
    sys.exit(1)




def load_animation():

        load_str = "preparing the CrossInjector...."
        ls_len = len(load_str)


        animation = "|/-\\"
        anicount = 0

        counttime = 0

        i = 0

        while (counttime != 100):


                time.sleep(0.075)


                load_str_list = list(load_str)

                x = ord(load_str_list[i])

                y = 0

                if x != 32 and x != 46:
                        if x>90:
                                y = x-32
                        else:
                                y = x + 32
                        load_str_list[i]= chr(y)

                res =''
                for j in range(ls_len):
                        res = res + load_str_list[j]

                sys.stdout.write("\r"+res + animation[anicount])
                sys.stdout.flush()


                load_str = res


                anicount = (anicount + 1)% 4
                i =(i + 1)% ls_len
                counttime = counttime + 1

        if os.name =="nt":
                os.system("cls")

        else:
                os.system("clear")

# Function to check if a given URL is alive
def is_alive(url):
    try:
        response = requests.head(url, timeout=5)
        return response.status_code < 400
    except requests.exceptions.RequestException:
        return False

# Function to get all the URLs from a given file
def get_urls_from_file(file_path):
    with open(file_path, "r") as f:
        urls = f.read().splitlines()
    return urls

# Function to get all the XSS payloads from a given file
def get_payloads_from_file(file_path):
    with open(file_path, "r") as f:
        payloads = f.read().splitlines()
    return payloads

# Function to check if a given URL has a query string
def has_query_string(url):
    return bool(urlparse.urlparse(url).query)

# Function to inject a payload into a given URL
def inject_payload(url, payload):
    if has_query_string(url):
        url_parts = list(urlparse.urlparse(url))
        query = dict(parse_qs(url_parts[4]))
        for key in query:
            query[key] = f"{query[key]}{payload}"
        url_parts[4] = urlparse.urlencode(query)
        url = urlparse.urlunparse(url_parts)
    else:
        url += f"{payload}"
    return url

# Function to scan a given URL for XSS vulnerabilities
# Function to scan a given URL for XSS vulnerabilities
def scan_url(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        payload_url = inject_payload(url, payload)
        if payload in requests.get(payload_url).text:
            print(colored(f"[VULNERABLE] {payload_url}", "red"))
            vulnerable_urls.append(payload_url)
        else:
            print(colored(f"[NOT VULNERABLE] {payload_url}", "green"))
    if vulnerable_urls:
        driver.execute_script("window.open('');")
        driver.switch_to.window(driver.window_handles[-1])
        for vulnerable_url in vulnerable_urls:
            driver.get(vulnerable_url)
    return vulnerable_urls

# Function to write vulnerable URLs to a file
def write_vulnerable_urls_to_file(file_path, urls):
    with open(file_path, "w") as f:
        f.write("\n".join(urls))

# Main function
def main():
    load_animation()
    print("""
     ▄████▄   ██▀███   ▒█████    ██████   ██████  ██▓ ███▄    █  ▄▄▄██▀▀▀▓█████   ██████ ▄▄▄█████▓▓█████  ██▀███  
    ▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▒██    ▒ ▒██    ▒ ▓██▒ ██ ▀█   █    ▒██   ▓█   ▀ ▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
    ▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒░ ▓██▄   ░ ▓██▄   ▒██▒▓██  ▀█ ██▒   ░██   ▒███   ░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
    ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░  ▒   ██▒  ▒   ██▒░██░▓██▒  ▐▌██▒▓██▄██▓  ▒▓█  ▄   ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
    ▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░▒██████▒▒▒██████▒▒░██░▒██░   ▓██░ ▓███▒   ░▒████▒▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒. 
    ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒  ▒▓▒▒░   ░░ ▒░ ░▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░▒  ░ ░░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░ ▒ ░▒░    ░ ░  ░░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░
    ░          ░░   ░ ░ ░ ░ ▒  ░  ░  ░  ░  ░  ░   ▒ ░   ░   ░ ░  ░ ░ ░      ░   ░  ░  ░    ░         ░     ░░   ░ 
    ░ ░         ░         ░ ░        ░        ░   ░           ░  ░   ░      ░  ░      ░              ░  ░   ░     
    ░                                                                                                                 
    """)
    print(colored('                                  Coded with Love by Anmol K Sachan @Fr13ND0x7f\n','green')) 
    parser = argparse.ArgumentParser(description="Scan a list of URLs for XSS vulnerabilities")
    parser.add_argument("-p", "--payloads", required=True, help="File containing XSS payloads")
    parser.add_argument("-u", "--urls", required=True, help="File containing list of URLs")
    args = parser.parse_args()

    urls = get_urls_from_file(args.urls)
    payloads = get_payloads_from_file(args.payloads)
    s = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=s)
    affected_targets = []
    for url in urls:
        if not is_alive(url):
            print(colored(f"[SKIPPED] {url} (host is down)", "yellow"))
            continue
        print(colored(f"[SCANNING] {url}", "blue"))
        vulnerable_urls = scan_url(url, payloads, driver)
        if vulnerable_urls:
            affected_targets.append(url)
            write_vulnerable_urls_to_file("affected_target_name.txt", vulnerable_urls)
    if affected_targets:
        print(colored("The following targets are affected:", "red"))
        for target in affected_targets:
            print(colored(target, "red"))
    else:
        print(colored("No targets were found to be vulnerable", "green"))
    driver.quit()

if __name__ == "__main__":
    main()
