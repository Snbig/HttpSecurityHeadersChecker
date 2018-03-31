# HttpSecurityHeadersChecker

**Http Security Headers Checker Tool written in PHP Cli + Useful Tips to set Http Security Headers in the most Webservers (Apache,nginx,IIS,...)**

## Response Headers
The following contains a list of HTTP response headers related to security , declared by [OWASP](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).
* **HTTP Strict Transport Security (HSTS)**
* **Public Key Pinning Extension for HTTP (HPKP)**
* **X-Frame-Options**
* **X-XSS-Protection**
* **X-Content-Type-Options**
* **Content-Security-Policy**
* **X-Permitted-Cross-Domain-Policies**
* **Referrer-Policy**
* **Expect-CT**
### Prerequisites :

To use this tool you need to insatll PHP CLI . (_PHP >=5 is OK_)

### Installing PHP CLI :
* **Linux** : PHP CLI Pre-installed Linux.<br><br>
* **Windows** : <br>
Go to : http://windows.php.net/download<br>
Download appropriate released PHP file .<br>
Follow this tutorial : http://www.php-cli.com/php-cli-tutorial.shtml
# How to use :
* **Linux** :
Fire up terminal and enter the below command :

```
php HttpSecurityHeadersChecker.php
```
* **Windows** :
Open CMD (Win + R keys on your keyboard. Then, type cmd or cmd.exe and press Enter).<br>
* Enter the below command :
```
php.exe HttpSecurityHeadersChecker.php
```
* Enter website exact URL :
```
[*] Enter URL (http/https)://[www.]google.com : https://github.com
```
* Enter "Y" for following website redirection or "N" to disable it.
```
[*] Do you want to follow redirection ? (Y/N) : Y
```
* If you want to keep your anonymity , use PROXY.
To set **Socks5/Tor/Http** proxy , enter 1,2 or 3.
```
[*] Do you want to use proxy ? ([0] => No proxy , [1] => Socks5 , [2] => Tor , [3] =>Http) : 2
```
* _Enable Tor on your PC before using Tor as socks5 proxy ._
# Running the test :
![alt text](https://pasteboard.co/images/H5Ww5sR.png/download)

## Tip :
* **Use exact target URL**<br>
www.google.com is not as same as google.com .<br> 
Or<br>
http**s** is not as same as http And gives different results .
## Authors
* **Hamed** - *Initial work* - [Hamed](https://github.com/Snbig)
* **Bitmessage** : 𝘉𝘔-2𝘤𝘝𝘳𝘗𝘈8𝘍𝘻𝘔𝘯𝘠𝘱𝘔𝘛𝘈9𝘸𝘏𝘨𝘔𝘰𝘬𝘨𝘒2𝘬𝘪𝘪𝘹𝘊2𝘍2

## License

This project is licensed under the Apache License 2.0 License - see the [LICENSE.md](LICENSE) file for details
