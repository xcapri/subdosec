<p align="center">
<b>Subdosec</b>
</p>
<p align="center">
Subdomain takeover scanner & reconnaissance tool.
</p>

---



![Demo](img/final_demo.gif)

<p align="center">
  <a href="#installation">Install</a> •
  <a href="#running-subdosec">Usage</a> •
  <a href="#web-based">Web Based</a> •
  <a href="#contribution">Contribution</a> •
  <a href="#online-scan">Online scan</a> •
  <a href="#acknowledgments">Acknowledgments</a>
</p>

---

> Subdosec is a fast and accurate subdomain takeover scanner with no false positives, featuring a public database of vulnerable subdomains and detailed non-vulnerable metadata (IP, CNAME, title, and status code) for reconnaissance.

# Installation

Install or upgrade subdosec
```
pipx install git+https://github.com/xcapri/subdosec.git
```
```
pipx upgrade subdosec
```


Then run this every time you start a new terminal session (until “server started successfully”).

```
$ subdosec -ins

Starting Node.js server...
Node.js server started successfully.
```

---
# Running subdosec

<b>[WARNING]
_Do not takeover all subdomains in test.txt,_
let everyone use that for demos.
</b>

<b>[INFO]
_Also check the [Release](https://github.com/xcapri/subdosec/releases) section._
You can find interesting info.
</b>

```
$ subdosec -h
```
<details>
  <summary>Expand full help flags</summary>

```yaml
   _____       __        __
  / ___/__  __/ /_  ____/ /___  ________  _____
  \__ \/ / / / __ \/ __  / __ \/ ___/ _ \/ ___/
 ___/ / /_/ / /_/ / /_/ / /_/ (__  )  __/ /__
/____/\__,_/_.___/\__,_/\____/____/\___/\___/



usage: subdosec [-h] [-mode {private,public}] [-initkey INITKEY] [-vo] [-pe] [-ins] [-pf PF] [-subfng SUBFNG] [-lf LF] [-sfid] [-ks] [-o O] [-su] [-lu LU] [-lm] [-uf] [-unai UNAI] [-v] [-t THREADS]

Subdomain takeover scanner.

options:
  -h, --help            show this help message and exit
  -mode {private,public}
                        Mode of operation (private/public)
  -initkey INITKEY      Initialize the API key
  -vo                   VULN Only: Hide UNDETECT messages
  -pe                   Print Error: When there are problems detecting your target
  -ins                  Prepar node & start server
  -pf PF                Private Fingerprint: uses your local fingerprint. Example: -pf /path/to/tko.json
  -subfng SUBFNG        Submit fingerprint: submit local fingerprint to admin. Example: -subfng localfinger.json
  -lf LF                Fingerprint lock: to focus on one or multiple fingerprints. (-lf github.io,surge.sh) and leave this arg to scan all fingerprints
  -sfid                 To view all available fingerprint ids.
  -ks                   To shut down the server node if you want to not use subdosec for a long time.
  -o O                  Save result locally to the specified path. Example: -o /path/to/dir
  -su                   Skip undetect will not stored to server (https://subdosec.vulnshot.com/result/undetected)
  -lu LU                Undetec stored localy to the specified path. Example: -lu /path/to/dir
  -lm                   Local Mode: Save vuln and undetect to default inside tools directory (auto -su)
  -uf                   Update Fingerprint
  -unai UNAI            Analyze undetected subdomains using AI. Example: -unai /path/to/undetect.json
  -v, --verbose         Show progress count (e.g. [1/10])
  -t THREADS, --threads THREADS
                        Number of threads to use for scanning (default: 10)
```
</details>

## Basic Commands

**Prepare list** 
> Support without protocol
```
cat list 

https://careers.rotacloud.com
http://creators.thinkorion.com
https://docs.polygon-nightfall.technology
a.anchorsawaytpt.com
help.oceges.com
```

**CMD 1** 
> Skip stored undetect to server & save localy
```
cat test.txt | subdosec -lm

https://subdosec.vulnshot.com [UNDETECT]
http://feedback.bazoom.com [sleekplan.com] [VULN] [SAVED]
http://demodev.destinojet.co [meteor.com] [VULN] [SAVED]
http://creators.thinkorion.com [UNDETECT]
https://www.www.savillerow.status.lnt.cl [ohdear.app] [VULN] [SAVED]
https://careers.rotacloud.com [gohire.io] [VULN] [SAVED]
https://careers.rotacloud.com [gohire.io] [VULN] [SAVED]
https://ai.yooture.com [UNDETECT]
https://help.oceges.com [UNDETECT]
http://ftp.thiagolima.com [surge.sh] [VULN] [SAVED]


VULN DIRECTORY  : /home/alice/.subdosec/vulns
UNDETECT FILE   : /home/alice/.subdosec/undetect/undetect.json
```
> Read output 
```
~$ ls /home/alice/.subdosec/vulns
gohire.io_tko.txt  meteor.com_tko.txt  ohdear.app_tko.txt  sleekplan.com_tko.txt  surge.sh_tko.txt
~$ cat /home/alice/.subdosec/vulns/gohire.io_tko.txt
careers.rotacloud.com
```
> Read undetect & auto analys new potential vuln with -unai
```
cat /home/alice/.subdosec/undetect/undetect.json
[
    {
        "title": "No title found",
        "status_code": 404,
        "redirect_url": "No redirects",
        "cname_records": [
            "cname.redacted.com"
        ],
        "a_records": [
            "76.76.21.98",
            "76.76.21.241"
        ],
        "subdomain": "try.redacted.com",
        "rootdomain": "redacted.com"
    },
    {
        "title": "No title found",
        "status_code": 200,
        "redirect_url": "No redirects",
        "cname_records": [
            "cname.fermat.shop"
        ],
        "a_records": [
            "216.150.16.129",
            "216.150.1.129"
        ],
        "subdomain": "get.redacted.com",
        "rootdomain": "redacted.com"
    }
]
```
```
subdosec -unai /home/pd/.subdosec/undetect/undetect.json

[INFO] PURE UNDETECTED 0 | Subdomains are not detected as vulnerable even though they have passed the subdosec scan..

[INFO] Analyzing 8 items in 2 batches.

[INFO] Progress: 5/8 data analyzed.

NEW POTENTIAL :


Domain     : try.redacted.com
  CNAME    : cname.redacted-service.com
  A Record : 76.76.21.98, 76.76.21.241
  Takeover : NOT
  Reason   : The redacted-service custom domain setup guide explicitly states the requirement of adding a TXT record (e.g., 'redacted-service-verification=<your_site_id>') for domain ownership verification. The presence of a TXT record verification step makes it not vulnerable.
  Reference: https://www.redacted-service.com/blog/how-to-setup-custom-domain/
================================================================================
Domain     : get.redacted.com
  CNAME    : cname.fermat.shop
  A Record : 216.150.16.129, 216.150.1.129
  Takeover : POSSIBLE
  Reason   : The service uses a static CNAME (cname.fermat.shop) for custom domain setup. Publicly available documentation for Fermat's custom domain setup does not clearly specify a requirement for a TXT record or any dynamic verification method for domain ownership. Without such verification, a static CNAME makes the subdomain potentially vulnerable if the corresponding Fermat account is deleted or becomes unlinked.
  Reference: https://fermat.shop/
================================================================================
```
**CMD 2**
> Using root domain & pipeline subdomain finder tool like (subfinder, assetfinder, amass, etc)

```
cat list
example.com 
```
```
cat list | subfinder -silent | subdosec -lm

https://subdosec.vulnshot.com [UNDETECT]
http://feedback.bazoom.com [sleekplan.com] [VULN] [SAVED]
http://demodev.destinojet.co [meteor.com] [VULN] [SAVED]
http://creators.thinkorion.com [UNDETECT]
https://www.www.savillerow.status.lnt.cl [ohdear.app] [VULN] [SAVED]
https://careers.rotacloud.com [gohire.io] [VULN] [SAVED]
https://careers.rotacloud.com [gohire.io] [VULN] [SAVED]
https://ai.yooture.com [UNDETECT]
https://help.oceges.com [UNDETECT]
http://ftp.thiagolima.com [surge.sh] [VULN] [SAVED]


VULN DIRECTORY  : /home/alice/.subdosec/vulns
UNDETECT FILE   : /home/alice/.subdosec/undetect/undetect.json
```

**CMD 3** 
> (Forward result to notify)
```
cat list | subdosec -lm -vo | notify -silent 

https://careers.rotacloud.com [100.00%] [gohire.io] [VULN] [SAVED]
```

**CMD 4**
> Use private fingerprint, this flag will auto merge public + priv fingerprint
<details>
  <summary>Expand full help flags</summary>

```yaml
cat priv8.json

{
  "fingerprints": [
    {
      "fid": 0,
      "name": "Subdomain takeover - Pagedeck",
      "rules": {
        "cname": "cname.pagedeck.com",
        "status_code": "404",
"in_body":"This page could not be found."
      },
      "status_fingerprint": 0,
      "reference": "https://docs.pagedeck.com/getting-started/connecting-a-subdomain",
      "service": "pagedeck.com",
      "logo_service": "https://i.ytimg.com/vi/DY76Tjf1m-8/maxresdefault.jpg"
    },
    add more
]}
```

```
 echo try.hugsleep.com | subdosec -pf privfinger.json  -o testpriv -lu okgaslu
   _____       __        __
  / ___/__  __/ /_  ____/ /___  ________  _____
  \__ \/ / / / __ \/ __  / __ \/ ___/ _ \/ ___/
 ___/ / /_/ / /_/ / /_/ / /_/ (__  )  __/ /__
/____/\__,_/_.___/\__,_/\____/____/\___/\___/



https://try.hugsleep.com [pagedeck.com] [VULN] [SAVED]


VULN DIRECTORY  : /home/pd/tko/testpriv
UNDETECT FILE   : /home/pd/tko/okgaslu/undetect.json
```
</details>

# Web Based

Knowing the function of the subdosec web, here you can use the https://subdosec.vulnshot.com/result/undetected feature as a reconnaissance, to find out IP, CNAME, TITLE, STATUS CODE, etc. as further information or even to find new takeover subdomains 
> It has the same function as undetect.json, the difference is that you and other people share it with each other.

For example, you search for a site that is not detected as vulnerable by subdosec with the keyword *404*, and there is information on cname.gohire.io and the title GoHire, which if you search on Google, there is no article information about subdomain takeover on the gohire service.


![Undetec](img/undetec_sample.png)

# Contribution

After you find a new subdomain takeover, either manually or automatically (using -unai), you can submit the data to us using the subdosec -subfng command.

Dynamically you can use this element for rules :  
>``title, cname, status_code, in_body, a_record, redirect``

```
cat newvuln.json
{
  "name": "Subdomain takeover - GoHire",
  "rules": {
    "cname": "custom.gohire.io",
    "in_body": "Page not found",
    "status_code": "404"
  },
  "status_fingerprint": 0,
  "reference": "https://help.gohire.io/en/articles/3385288-setting-up-a-custom-domain",
  "service": "gohire.io",
  "logo_service": "https://gohire-website.s3.amazonaws.com/img/logos/gh-logo-main.gif"
}

```
```
subdosec -subfng newvuln.json

[Info] Submitting fingerprint ...

Imported fingerprint data successfully
```


## Online scan

If you are not a person with a security background, maybe a web-dev/programmer and not familiar with cli tools. you can use the web version to scan all your subdomains with a max of 10 subdomains per scan.

![Undetec](img/onlinescan.gif)

## Acknowledgments

The predecessor tools that inspired the creation of subdosec tools.

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns)
- [SubOver](https://github.com/Ice3man543/SubOver)
- [subjack](https://github.com/haccer/subjack)
- [nuclei-templates/http/takeovers](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers)
- The bug bounty community for inspiration and feedback.


--- 
<div align="center">
  
  <sub>**`subdosec`** is distributed under [**MIT License**](https://github.com/xcapri/subdosec/blob/main/LICENSE.md)</sub>

</div>