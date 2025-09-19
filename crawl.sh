#!/bin/bash
gnutimeout() {
    if hash gtimeout 2>/dev/null; then
        gtimeout "$@"
    else
        timeout "$@"
    fi
}
cat list-sites.txt | while read i; do 
    gnutimeout -s KILL 1h scrapy runspider --logfile=scrapy.log captcha_spider.py -a url=https://$i
done

