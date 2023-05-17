'''
1.) Extract user input web forms.
2.) Check whether webpage has SQL errors in it.
3.) Scan for SQL attacks and test on html forms.
'''

import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

# Select Interpreter
# C:\Users\jagno\.virtualenvs\sqli-s-mwyxEY
# Scripts\python.exe

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

"creating func for obtaining html form tags when provided with a webpage"


def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")


def form_details(form):

    # instntatiating dictionary
    detailsOfForm = {}

    # utilizing getter/setter methodology below
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")

    # instantiating list
    inputs = []

    for input_tag in form.find_all("input"):  # searching for html tags below

        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get(
            "value", "")  # initial value is empty

        inputs.append({  # constructor
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs

    return detailsOfForm  # response output


"Human error vulnerabilities."


def vulnerable(response):

    errors = {"Quoted string not properly terminated",
              "Open quotation mark after the charachter string",
              "Error in you SQL syntax"
              }

    for error in errors:  # search
        if error in response.content.decode().lower():
            return True
    return False  # boolean test


"Injection vulerabiliy."


def sql_injection_scan(url):

    forms = get_forms(url)  # input webpage
    print(f"[+] Detected {len(forms)} forms on {url}.")  # syntaxing

    for form in forms:  # search
        details = form_details(form)  # dicationary created for details

        for i in "\"'":  # search
            data = {}  # instantiation

            for input_tag in details["inputs"]:
                # authentication & verification
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + \
                        i  # if verification passes, interates
                elif input_tag["type"] != "submit":  # if form in webpage not submitted
                    # test that ieration immediately
                    data[input_tag['name']] = f"test{i}"

            print(url)
            form_details(form)

            # using post method on session class (s) for inputted webapge's(url) user-agent
            if details["method"] == "post":
                res = s.post(url, data=data)
            # using get method on session class (s) for inputted webapge's(url) user-agent
            elif details["method"] == "get":
                res = s.get(url, params=data)

            if vulnerable(res):
                print("ALERT: SQL injection attack vulnerability in link: ", url)

                # below is a simple reporting tool I created to ensure that there is a threat assesment component to the scanner
                print(
                    "REPORT: Please carefully review the following specfics of the alert.")
                print(
                    "....................................................................")
                print("Potential malicious content for review:", res.content)
                print("Response status code: ", res.status_code)
                print("Response headers: ", res.headers)
            else:
                print("No SQL injection attack vulnerability detected")
                break


if __name__ == "__main__":  # testing + UI
    urlToBeChecked = "https://www.stevens.edu/"
    sql_injection_scan(urlToBeChecked)
