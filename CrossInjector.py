import os
import sys
import json
import requests
import argparse
import time
import urllib.parse as urlparse
from urllib.parse import urljoin
from termcolor import colored
from urllib.parse import parse_qs
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.common.exceptions import NoAlertPresentException, TimeoutException
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
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

# Function to get all the XSS payloads from a given directory
def get_payloads_from_directory(directory_path):
    payloads = []
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            with open(os.path.join(directory_path, filename), "r") as f:
                payloads.extend(f.read().splitlines())
    return payloads

# Function to check if a given URL has a query string
def has_query_string(url):
    return bool(urlparse.urlparse(url).query)

# Function to inject a payload into a given URL
def inject_payload(url, payload, context="get"):
    if context == "get":
        if has_query_string(url):
            url_parts = list(urlparse.urlparse(url))
            query = dict(parse_qs(url_parts[4]))
            for key in query:
                query[key] = f"{query[key][0]}{payload}"
            url_parts[4] = urlparse.urlencode(query, doseq=True)
            return urlparse.urlunparse(url_parts)
        else:
            return f"{url}{payload}"
    elif context == "path":
        url_parts = list(urlparse.urlparse(url))
        url_parts[2] += f"/{payload}"
        return urlparse.urlunparse(url_parts)
    return url

# Function to scan a given URL for GET-based XSS vulnerabilities
def scan_get(url, payloads):
    vulnerable_urls = []
    for payload in payloads:
        get_url = inject_payload(url, payload)
        try:
            if payload in requests.get(get_url).text:
                print(colored(f"[VULNERABLE - GET] {get_url}", "red"))
                vulnerable_urls.append({"url": get_url, "type": "GET", "payload": payload})
            else:
                print(colored(f"[NOT VULNERABLE - GET] {get_url}", "green"))
        except requests.exceptions.RequestException:
            pass
    return vulnerable_urls

# Function to extract forms from a URL
def get_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []

# Function to scan for POST-based XSS in forms
def scan_post_forms(url, payloads):
    vulnerable_urls = []
    forms = get_forms(url)
    if not forms:
        return vulnerable_urls

    print(colored(f"[INFO] Found {len(forms)} forms on {url}", "blue"))
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()

        if method != "post":
            continue

        action_url = urljoin(url, action)
        inputs = form.find_all(["input", "textarea", "select"])
        form_data = {}
        for i in inputs:
            name = i.get("name")
            value = i.get("value", "")
            form_data[name] = value

        for payload in payloads:
            for input_name in form_data.keys():
                if not input_name:
                    continue
                data_to_send = form_data.copy()
                data_to_send[input_name] = payload
                try:
                    response = requests.post(action_url, data=data_to_send)
                    if payload in response.text:
                        print(colored(f"[VULNERABLE - POST Form] {action_url} with payload in '{input_name}'", "red"))
                        vulnerable_urls.append({"url": action_url, "type": "POST", "parameter": input_name, "payload": payload})
                except requests.exceptions.RequestException as e:
                    print(colored(f"[ERROR] Failed to submit form to {action_url}: {e}", "yellow"))
    return vulnerable_urls

# Function to scan for path-based XSS
def scan_path(url, payloads):
    vulnerable_urls = []
    for payload in payloads:
        path_url = inject_payload(url, payload, context="path")
        try:
            if payload in requests.get(path_url).text:
                print(colored(f"[VULNERABLE - Path] {path_url}", "red"))
                vulnerable_urls.append({"url": path_url, "type": "Path", "payload": payload})
            else:
                print(colored(f"[NOT VULNERABLE - Path] {path_url}", "green"))
        except requests.exceptions.RequestException:
            pass
    return vulnerable_urls

# Function to scan for XSS in request headers
def scan_headers(url, payloads):
    vulnerable_urls = []
    headers_to_test = ["User-Agent", "Referer"]
    for payload in payloads:
        for header in headers_to_test:
            headers = {header: payload}
            try:
                if payload in requests.get(url, headers=headers).text:
                    print(colored(f"[VULNERABLE - Header {header}] {url} with payload {payload}", "red"))
                    vulnerable_urls.append({"url": url, "type": "Header", "header": header, "payload": payload})
                else:
                    print(colored(f"[NOT VULNERABLE - Header {header}] {url} with payload {payload}", "green"))
            except requests.exceptions.RequestException:
                pass
    return vulnerable_urls

# Function to scan for cookie-based XSS
def scan_cookie(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        driver.get(url)
        driver.add_cookie({"name": "xss", "value": payload})
        driver.refresh()
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            print(colored(f"[VULNERABLE - Cookie] {url} with payload {payload}", "red"))
            vulnerable_urls.append({"url": url, "type": "Cookie", "payload": payload})
        except (NoAlertPresentException, TimeoutException):
            print(colored(f"[NOT VULNERABLE - Cookie] {url} with payload {payload}", "green"))
    return vulnerable_urls

# Function to scan for DOM-based XSS using URL fragment
def scan_fragment(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        fragment_url = f"{url}#{payload}"
        driver.get(fragment_url)
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            print(colored(f"[VULNERABLE - Fragment] {fragment_url}", "red"))
            vulnerable_urls.append({"url": fragment_url, "type": "Fragment", "payload": payload})
        except (NoAlertPresentException, TimeoutException):
            print(colored(f"[NOT VULNERABLE - Fragment] {fragment_url}", "green"))
    return vulnerable_urls

# Function to write vulnerable URLs to a file
def write_vulnerable_urls_to_file(file_path, urls):
    with open(file_path, "w") as f:
        json.dump(urls, f, indent=4)

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
    parser.add_argument("-p", "--payloads", required=True, help="Directory containing XSS payloads")
    parser.add_argument("-u", "--urls", required=True, help="File containing list of URLs")
    parser.add_argument("--scan-get", action="store_true", help="Scan GET parameters")
    parser.add_argument("--scan-post", action="store_true", help="Scan POST parameters")
    parser.add_argument("--scan-path", action="store_true", help="Scan URL path")
    parser.add_argument("--scan-headers", action="store_true", help="Scan request headers")
    parser.add_argument("--scan-cookie", action="store_true", help="Scan cookies")
    parser.add_argument("--scan-fragment", action="store_true", help="Scan URL fragment")
    main.args = parser.parse_args()

    urls = get_urls_from_file(main.args.urls)
    payloads = get_payloads_from_directory(main.args.payloads)

    driver = None
    if main.args.scan_cookie or main.args.scan_fragment:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        s = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=s, options=options)

    affected_targets = []
    for url in urls:
        if not is_alive(url):
            print(colored(f"[SKIPPED] {url} (host is down)", "yellow"))
            continue
        print(colored(f"[SCANNING] {url}", "blue"))
        all_vulnerable_urls = []
        if main.args.scan_get:
            all_vulnerable_urls.extend(scan_get(url, payloads))
        if main.args.scan_post:
            all_vulnerable_urls.extend(scan_post_forms(url, payloads))
        if main.args.scan_path:
            all_vulnerable_urls.extend(scan_path(url, payloads))
        if main.args.scan_headers:
            all_vulnerable_urls.extend(scan_headers(url, payloads))
        if main.args.scan_cookie:
            all_vulnerable_urls.extend(scan_cookie(url, payloads, driver))
        if main.args.scan_fragment:
            all_vulnerable_urls.extend(scan_fragment(url, payloads, driver))

        if all_vulnerable_urls:
            affected_targets.append(url)
            write_vulnerable_urls_to_file("affected_target_name.txt", all_vulnerable_urls)
    if affected_targets:
        print(colored("The following targets are affected:", "red"))
        for target in affected_targets:
            print(colored(target, "red"))
    else:
        print(colored("No targets were found to be vulnerable", "green"))
    if driver:
        driver.quit()

if __name__ == "__main__":
    main()
