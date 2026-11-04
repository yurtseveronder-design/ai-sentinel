import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class APIClient:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()

        # Define exponential backoff retry strategy for transient errors (500, 502, 503, 504)
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, endpoint, **kwargs):
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint, data=None, json=None, **kwargs):
        return self._request("POST", endpoint, data=data, json=json, **kwargs)

    def put(self, endpoint, data=None, json=None, **kwargs):
        return self._request("PUT", endpoint, data=data, json=json, **kwargs)

    def delete(self, endpoint, **kwargs):
        return self._request("DELETE", endpoint, **kwargs)

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault("timeout", self.timeout)
        logging.info(f"Sending {method} request to: {url}")
        response = self.session.request(method, url, **kwargs)
        logging.info(f"Received status code: {response.status_code} from {url}")
        return response