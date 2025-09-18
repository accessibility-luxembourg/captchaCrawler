# captchaCrawler

Crawls websites to detect the pages using CAPTCHAs.
The goal is to evaluate their impact on accessibility. Not all CAPTCHAs have accessibility issues, this should then be assessed based on the results.

## Installation

```
git clone https://github.com/accessibility-luxembourg/captchaCrawler.git
cd captchaCrawler
python -m venv env # on a Mac, use the python3 command instead of python
source ./env/bin/activate 
pip install -r requirements.txt
chmod a+x *.sh
```

On MacOS, the `timeout` or `gtimeout` commands are not available but they are needed to limit the crawling time per site, you will need to install the coreutils package via brew:
```
brew install coreutils
```

## Usage

To be able to use this tool, you need a list of websites to crawl. Store this list in a file named `list-sites.txt`, one domain per line (without protocol and without path). Example of content for this file: 

```
test.public.lu
etat.public.lu

```

You can then crawl all the files. Launch the following command `crawl.sh`. It will crawl all the sites mentioned in `list-sites.txt`. Each site is crawled during maximum 1 hour (it can be adjusted in crawl.sh). The resulting files will be placed in the `crawled_files`folder. This step can be quite long.

Everytime you come back to the project and start a terminal, you have to load the virtual environment first with the following command:
```
source ./env/bin/activate 
```

# Results

A [json lines](https://jsonlines.org/) file named captchas.jsonl

# Detection

The detection is based on ["Webappanalyzer"](https://github.com/enthec/webappanalyzer/), an open source fork of Wappalyzer.

The following CAPTCHAs are detected:

-   Friendly Captcha,
-   FunCaptcha,
-   Really Simple CAPTCHA,
-   MTCaptcha,
-   ARCaptcha,
-   AWS WAF Captcha,
-   CoinHive Captcha,
-   Cloudflare Turnstile,
-   Slider Captcha
-   ReCaptcha v2 for Contact Form 7,
-   reCAPTCHA,
-   hCaptcha,
-   GeeTest,
-   Wordfence Login Security


## License
This software is developed by the [Information and press service](https://sip.gouvernement.lu/en.html) of the luxembourgish government and licensed under the MIT license.

