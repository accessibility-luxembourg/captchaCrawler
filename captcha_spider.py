import scrapy, urllib.parse, re, os, itertools, json, requests
from scrapy.http.cookies import CookieJar
from requests import Response
from webappanalyzer.webappanalyzer import WebAppAnalyzer
from webappanalyzer.web_page import WebPage

from scrapy.http import Request

known_captchas = [
  "Friendly Captcha",
  "FunCaptcha",
  "Really Simple CAPTCHA",
  "MTCaptcha",
  "ARCaptcha",
  "AWS WAF Captcha",
  "CoinHive Captcha",
  "Cloudflare Turnstile",
  "Slider Captcha"
  "ReCaptcha v2 for Contact Form 7",
  "reCAPTCHA",
  "hCaptcha",
  "GeeTest",
  "Wordfence Login Security"
]

def response_cookies(response):
    """
    Get cookies from response
    
    @param response scrapy response object
    @return: dict
    """

    obj = CookieJar(policy=None)
    jar = obj.make_cookies(response, response.request)
    cookies = {}
    for cookie in jar:
        cookies[cookie.name] = cookie.value
    return cookies

# based on the quotesSpider from Scrapy Tutorial
# https://docs.scrapy.org/en/latest/intro/tutorial.html

class captcha_a11y(scrapy.Spider):
  name = "captcha_a11y_crawler"
  custom_settings = {
    'DOWNLOAD_DELAY': '1',
    'COOKIES_ENABLED': True
  } 

  def __init__(self, url=None, *args, **kwargs):
    super(captcha_a11y, self).__init__(*args, **kwargs)
    self.url = url
    self.parsed_url = urllib.parse.urlparse(url)
    self.allowed_domains = [self.parsed_url.netloc]
    self.start_urls = [url]

  def parse(self, response):
    base_url = self.parsed_url.scheme+'://'+self.parsed_url.netloc
    if (isinstance(response, scrapy.http.response.html.HtmlResponse)):

      # FIXME: avoid using requests.get here and analyse the existing response.
      
      res: Response = requests.get(response.url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"})
      
      page: WebPage = WebPage.new_from_response(res)
      data = WebAppAnalyzer().analyze(page)
      found = False
      
      for d in data:
         if (d['tech'] in known_captchas):
            found = d
            
      if (found != False):
        payload = {'url': response.url, 'data': found}
        f = open('./captchas.jsonl', 'a')
        f.write(json.dumps(payload)+'\n')
        f.close()

      for a in response.xpath('//a[@href]/@href'):
        link = a.extract().strip()
        parsed_link = urllib.parse.urlparse(link)
        path = parsed_link.path
        scheme = parsed_link.scheme
        path = re.sub(r'\/+$', '' , path)
        link = response.urljoin(link)
        if (scheme == '' or scheme == 'http' or scheme == 'https'):
          if (path.lower().find('recherche') != -1 or path.lower().find('search') != -1):
              self.logger.info('Avoided search page:'+link)
          else:
              yield response.follow(link, self.parse)



