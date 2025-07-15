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
        url_parts[2] += f"/{payload.replace('/', '%2F')}"
        return urlparse.urlunparse(url_parts)
    elif context == "header":
        return payload
    elif context == "cookie":
        return payload
    elif context == "fragment":
        return payload
    return url

# Function to get all the forms from a given URL
def get_forms(url):
    try:
        response = requests.get(url)
        # Use BeautifulSoup to parse the HTML and find all the forms
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []

# Function to scan a given URL for XSS vulnerabilities
def scan_url(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        # Test GET parameters
        if main.args.scan_get:
            get_url = inject_payload(url, payload)
            try:
                if payload in requests.get(get_url).text:
                    print(colored(f"[VULNERABLE - GET] {get_url}", "red"))
                    vulnerable_urls.append(get_url)
                else:
                    print(colored(f"[NOT VULNERABLE - GET] {get_url}", "green"))
            except requests.exceptions.RequestException:
                pass

        # Test POST form data
        if main.args.scan_post:
            forms = get_forms(url)
            for form in forms:
                form_details = {}
                action = form.attrs.get("action", url)
                method = form.attrs.get("method", "get")
                if method.lower() != "post":
                    continue

                inputs = form.find_all("input")
                for input_tag in inputs:
                    input_name = input_tag.attrs.get("name")
                    input_type = input_tag.attrs.get("type", "text")
                    input_value = input_tag.attrs.get("value", "")
                    if input_type == "text":
                        form_details[input_name] = f"{input_value}{payload}"
                    else:
                        form_details[input_name] = input_value

                try:
                    if payload in requests.post(urlparse.urljoin(url, action), data=form_details).text:
                        print(colored(f"[VULNERABLE - POST Form] {url} with payload {payload}", "red"))
                        vulnerable_urls.append(f"{url} - POST Form - {payload}")
                    else:
                        print(colored(f"[NOT VULNERABLE - POST Form] {url} with payload {payload}", "green"))
                except requests.exceptions.RequestException:
                    pass

        # Test POST JSON
        if main.args.scan_post and has_query_string(url):
            json_data = {key: f"{value[0]}{payload}" for key, value in parse_qs(urlparse.urlparse(url).query).items()}
            try:
                if payload in requests.post(url, json=json_data).text:
                    print(colored(f"[VULNERABLE - POST JSON] {url} with payload {payload}", "red"))
                    vulnerable_urls.append(f"{url} - POST JSON - {payload}")
                else:
                    print(colored(f"[NOT VULNERABLE - POST JSON] {url} with payload {payload}", "green"))
            except requests.exceptions.RequestException:
                pass

    if vulnerable_urls:
        driver.execute_script("window.open('');")
        driver.switch_to.window(driver.window_handles[-1])
        for vulnerable_url in vulnerable_urls:
            if vulnerable_url.startswith("http"):
                driver.get(vulnerable_url)
    return vulnerable_urls

# Function to scan for path-based XSS
def scan_path(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        path_url = inject_payload(url, payload, context="path")
        try:
            if payload in requests.get(path_url).text:
                print(colored(f"[VULNERABLE - Path] {path_url}", "red"))
                vulnerable_urls.append(path_url)
            else:
                print(colored(f"[NOT VULNERABLE - Path] {path_url}", "green"))
        except requests.exceptions.RequestException:
            pass
    return vulnerable_urls

# Function to scan for XSS in request headers
def scan_headers(url, payloads, driver):
    vulnerable_urls = []
    headers_to_test = ["User-Agent", "Referer", "Cookie"]
    for payload in payloads:
        for header in headers_to_test:
            headers = {header: payload}
            try:
                if payload in requests.get(url, headers=headers).text:
                    print(colored(f"[VULNERABLE - Header {header}] {url} with payload {payload}", "red"))
                    vulnerable_urls.append(f"{url} - Header {header} - {payload}")
                else:
                    print(colored(f"[NOT VULNERABLE - Header {header}] {url} with payload {payload}", "green"))
            except requests.exceptions.RequestException:
                pass
    return vulnerable_urls

# Function to scan for cookie-based XSS
def scan_cookie(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        try:
            driver.get(url)
            driver.add_cookie({"name": "xss", "value": payload})
            driver.refresh()
            if payload in driver.page_source:
                print(colored(f"[VULNERABLE - Cookie] {url} with payload {payload}", "red"))
                vulnerable_urls.append(f"{url} - Cookie - {payload}")
            else:
                print(colored(f"[NOT VULNERABLE - Cookie] {url} with payload {payload}", "green"))
        except:
            pass
    return vulnerable_urls

# Function to scan for DOM-based XSS using URL fragment
def scan_fragment(url, payloads, driver):
    vulnerable_urls = []
    for payload in payloads:
        fragment_url = f"{url}#{payload}"
        try:
            driver.get(fragment_url)
            # This is a simple check. A more robust solution would involve
            # checking for script execution or other DOM manipulations.
            if payload in driver.page_source:
                print(colored(f"[VULNERABLE - Fragment] {fragment_url}", "red"))
                vulnerable_urls.append(fragment_url)
            else:
                print(colored(f"[NOT VULNERABLE - Fragment] {fragment_url}", "green"))
        except:
            pass
    return vulnerable_urls

# Function to write vulnerable URLs to a file
def write_vulnerable_urls_to_file(file_path, urls):
    with open(file_path, "w") as f:
        f.write("\n".join(urls))

# Main function
def main():
    import subprocess
    p = subprocess.Popen([sys.executable, 'test_app.py'])

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
    parser.add_argument("--scan-get", action="store_true", help="Scan GET parameters")
    parser.add_argument("--scan-post", action="store_true", help="Scan POST parameters")
    parser.add_argument("--scan-path", action="store_true", help="Scan URL path")
    parser.add_argument("--scan-headers", action="store_true", help="Scan request headers")
    parser.add_argument("--scan-cookie", action="store_true", help="Scan cookies")
    parser.add_argument("--scan-fragment", action="store_true", help="Scan URL fragment")
    main.args = parser.parse_args()

    try:
        urls = get_urls_from_file(main.args.urls)
        payloads = get_payloads_from_file(main.args.payloads)
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        try:
            s = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=s, options=options)
        except:
            from selenium.webdriver.chrome.options import Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
        affected_targets = []
        for url in urls:
            if not is_alive(url):
                print(colored(f"[SKIPPED] {url} (host is down)", "yellow"))
                continue
            print(colored(f"[SCANNING] {url}", "blue"))
            all_vulnerable_urls = []
            if main.args.scan_get or main.args.scan_post:
                all_vulnerable_urls.extend(scan_url(url, payloads, driver))
            if main.args.scan_path:
                all_vulnerable_urls.extend(scan_path(url, payloads, driver))
            if main.args.scan_headers:
                all_vulnerable_urls.extend(scan_headers(url, payloads, driver))
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
        driver.quit()
    finally:
        p.terminate()

if __name__ == "__main__":
    main()
