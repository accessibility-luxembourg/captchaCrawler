import scrapy, urllib.parse, re, os, itertools, json, requests, time, sys
from datetime import datetime
from scrapy.http.cookies import CookieJar
from requests import Response
from webappanalyzer.webappanalyzer import WebAppAnalyzer
from webappanalyzer.web_page import WebPage

from scrapy.http import Request

def console_print(message):
    """Print to console and flush immediately for real-time output"""
    print(message)
    sys.stdout.flush()

def console_progress(msg: str):
    # clear and overwrite the current line
    print(f"\r\033[K{msg}", end="", flush=True)

def console_newline():
    """Print a newline to move to next permanent line"""
    print()
    sys.stdout.flush()

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
    console_print(f"🔍 Starting crawl for domain: {self.parsed_url.netloc}")
    self.page_count = 0
    self.start_time = time.time()
    self.captcha_count = 0
    self.skip_count = 0

  def start_requests(self):
    for url in self.start_urls:
        yield scrapy.Request(url=url, callback=self.parse)

  def parse(self, response):
    # Progress indicator - show ALL requests (overwriting)
    self.page_count += 1
    elapsed = time.time() - self.start_time
    rate = self.page_count / elapsed if elapsed > 0 else 0
    status_emoji = "✅" if response.status == 200 else f"⚠️({response.status})"
    
    # Overwriting progress line
    console_progress(
      f"📄 [{self.parsed_url.netloc}] Pages: {self.page_count} | "
      f"Rate: {rate:.1f}/sec | Skipped: {self.skip_count} | "
      f"CAPTCHAs: {self.captcha_count} | Current: {response.url[:60]}..."
    )
    
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
        self.captcha_count += 1
        console_newline()  # Move to new line before permanent message
        console_print(f"🚨 CAPTCHA #{self.captcha_count} FOUND: {found['tech']} on {response.url}")
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
              self.skip_count += 1
              self.logger.info('Avoided search page:'+link)
          else:
              yield response.follow(link, self.parse)

  def closed(self, reason):
    console_newline()  # Move to new line for final summary
    elapsed_time = time.time() - self.start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    rate = self.page_count / elapsed_time if elapsed_time > 0 else 0
    timestamp = datetime.now().strftime("%H:%M:%S")
    console_print(f"✅ [{self.parsed_url.netloc}] Completed at {timestamp}: {self.page_count} pages, {self.skip_count} skipped, {self.captcha_count} CAPTCHAs in {minutes}m {seconds}s ({rate:.1f} pages/sec)")
    if reason != 'finished':
        console_print(f"🏁 [{self.parsed_url.netloc}] Reason: {reason}")
    console_print("="*80)