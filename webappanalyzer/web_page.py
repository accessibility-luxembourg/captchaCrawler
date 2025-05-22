from http.cookiejar import CookieJar

from bs4 import BeautifulSoup
from requests import Response
from requests.structures import CaseInsensitiveDict


class WebPage:
    def __init__(self, url: str, html: bytes, headers: CaseInsensitiveDict, cookies: CookieJar):
        self.url: str = url
        self.html: bytes = html
        self.headers: CaseInsensitiveDict = headers
        if "set-cookie" in self.headers:
            self.headers.pop("set-cookie")
        self.cookies: CookieJar = cookies
        self.parsed_html: BeautifulSoup = BeautifulSoup(self.html, 'html.parser')
        self.scripts = [script['src'] for script in self.parsed_html.findAll('script', src=True)]
        self.meta = [{meta['name'].lower(): meta['content']} for meta in self.parsed_html.findAll('meta', attrs=dict(name=True, content=True))]

    @classmethod
    def new_from_response(cls, response: Response):
        return cls(response.url, html=response.content, headers=response.headers, cookies=response.cookies)
