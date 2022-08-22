import urllib3
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


disable_https_warning = {
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
}
