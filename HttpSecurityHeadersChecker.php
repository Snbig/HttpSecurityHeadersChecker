<?php
/*
 * Author : Snbig (Hamed) https://github.com/Snbig/
 * Source : https://github.com/Snbig/HttpSecurityHeadersChecker/
 * License : This project is licensed under the Apache License 2.0 License .
 * Date : 1/31/2018
 */

//Tips for setting Security Http Headers to the Webservers
$tip0 = <<<_END
[?]Tips

Strict-Transport-Security enforces the use of HTTPS. This is important because it protects against passive eavesdropper and man-in-the-middle (MITM) attacks.

Apache:
Edit your apache configuration file and add the following to your VirtualHost.
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains"

nginx:
Edit your nginx configuration file and add the following snippet.
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";

lighttpd:
Edit your lighttpd configuration file and add the following snippet.
setenv.add-response-header = ("Strict-Transport-Security" => "max-age=63072000; includeSubdomains",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#strict-transport-security
_END;

$tip1 = <<<_END
[?]Tips

The Public Key Pinning Extension for HTML5 (HPKP) is a security feature that tells a web client to associate a specific cryptographic public key with a certain web server to decrease the risk of MITM attacks with forged certificates.

[!] Get your website HPKP hash from : https://report-uri.com/home/pkp_hash

Apache [Example]:
Edit your apache configuration file and add the following to your VirtualHost.
Header set Public-Key-Pins "pin-sha256=\"klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=\"; pin-sha256=\"633lt352PKRXbOwf4xSEa1M517scpD3l5f79xMD9r9Q=\"; max-age=2592000; includeSubDomains"

nginx [Example]:
Edit your nginx configuration file and add the following snippet.
add_header Public-Key-Pins "pin-sha256=\"klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=\"; pin-sha256=\"633lt352PKRXbOwf4xSEa1M517scpD3l5f79xMD9r9Q=\"; max-age=2592000; includeSubDomains";

lighttpd [Example]:
Edit your lighttpd configuration file and add the following snippet.
setenv.add-response-header = ("Public-Key-Pins" => "pin-sha256=\"klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=\"; pin-sha256=\"633lt352PKRXbOwf4xSEa1M517scpD3l5f79xMD9r9Q=\"; max-age=2592000; includeSubDomains",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#public-key-pinning
_END;

$tip2 = <<<_END
[?]Tips

X-Frame-Options prevents clickjacking attacks and helps ensure your content is not embedded into other sites via < frame >, < iframe > or < object >.

Apache:
Add this line below into your site's configuration to configure Apache to send X-Frame-Options header for all pages.
Header set X-Frame-Options DENY

nginx:
Add snippet below into configuration file to send X-Frame-Options header.
add_header X-Frame-Options "DENY";

lighttpd:
Add snippet below into configuration file to send X-Frame-Options header.
setenv.add-response-header = ("X-Frame-Options" => "DENY",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options
_END;

$tip3 = <<<_END
[?]Tips

X-XSS-Protection sets the configuration for the cross-site scripting filters built into most browsers. This is important because it tells the browser to block the response if a malicious script has been inserted from a user input.

Add appropriate snippet into configuration file.

Apache:
Header set X-XSS-Protection: 1; mode=block

nginx:
add_header X-XSS-Protection "1;mode=block";

lighttpd:
setenv.add-response-header = ("X-XSS-Protection" => "1; mode=block",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#x-xss-protection
_END;

$tip4 = <<<_END
[?]Tips

X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. This is important because the browser will only load external resources if their content-type matches what is expected, and not malicious hidden code.

Add appropriate snippet into configuration file.

Apache:
Header set X-Content-Type-Options: nosniff

nginx:
add_header X-Content-Type-Options "nosniff";

lighttpd:
setenv.add-response-header = ("X-Content-Type-Options" => "nosniff",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options
_END;

$tip5 = <<<_END
[?]Tips

Content-Security-Policy tells the browser where resources are allowed to be loaded and if it’s allowed to parse/run inline styles or Javascript. This is important because it prevents content injection attacks, such as Cross Site Scripting (XSS).

Add appropriate snippet into configuration file.

Apache:
Header set Content-Security-Policy "script-src 'self'; object-src 'self'"

nginx:
add_header Content-Security-Policy "script-src 'self'; object-src 'self'";

lighttpd:
setenv.add-response-header = ("Content-Security-Policy" => "script-src 'self'; object-src 'self'",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/#content-security-policy
_END;

$tip6 = <<<_END
[?]Tips

X-Permitted-Cross-Domain-Policies is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily limited to these), permission to handle data across domains.

Add appropriate snippet into configuration file.

Apache:
Header set X-Permitted-Cross-Domain-Policies: none

nginx:
add_header X-Permitted-Cross-Domain-Policies "none";

lighttpd:
setenv.add-response-header = ("X-Permitted-Cross-Domain-Policies" => "none",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/
_END;

$tip7 = <<<_END
[?]Tips :

Referrer-Policy allows control/restriction of the amount of information present in the referral header for links away from your page—the URL path or even if the header is sent at all.

Add appropriate snippet into configuration file.

Apache:
Header set Referrer-Policy: "SAMEORIGIN"

nginx:
add_header Referrer-Policy "SAMEORIGIN";

lighttpd:
setenv.add-response-header = ("Referrer-Policy" => "SAMEORIGIN",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/
_END;

$tip8 = <<<_END
[?]Tips

Certificate Transparency policy means that user-agents, e.g. browsers should block an access to a website with a certificate that is not registered in public CT logs (after October 2017).

Add appropriate snippet into configuration file.

Apache:
Header set Expect-CT: "enforce"

nginx:
add_header Expect-CT "enforce"

lighttpd:
setenv.add-response-header = ("Expect-CT" => "enforce",)

IIS:
Visit https://scotthelme.co.uk/hardening-your-http-response-headers/
_END;

do
{
    //Get Target URL
    echo "[*] Enter URL (http/https)://[www.]google.com : ";
    $url = trim(fgets(STDIN));

    if(!empty($url)) {
        if (filter_var($url, FILTER_VALIDATE_URL)) { //Check the given url is valid or not .
            $host = parse_url($url);
            if (GetServerStatus($host['host'], 80)) { //Check Website availability .
                $ch = curl_init();
                $headers = [];
                curl_setopt($ch, CURLOPT_URL, $host['scheme']."://". $host['host']);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch,CURLOPT_USERAGENT,'Mozilla/4.0 (X11; Linux x86_64) AppleWebKit/434.24 (KHTML, like Gecko) Ubuntu/10.04 Chromium/11.0.696.0 Chrome/11.0.696.0 Safari/434.24.');
                curl_setopt($ch, CURLOPT_HEADERFUNCTION,
                    function($curl, $header) use (&$headers)
                    {
                        $len = strlen($header);
                        $header = explode(':', $header, 2);
                        if (count($header) < 2)
                            return $len;
                        $name = strtolower(trim($header[0]));
                        if (!array_key_exists($name, $headers))
                            $headers[$name] = [trim($header[1])];
                        else
                            $headers[$name][] = trim($header[1]);
                        return $len;
                    }
                );
                curl_exec($ch); //Send HTTP request to the specified target .


                //Check Strict Transport Security (HSTS) header
                if (array_key_exists("strict-transport-security",$headers)) {
                    splitter();
                    echo color("[+] Secure : Strict Transport Security (HSTS) is Enabled .",0);
                    print_array(color("\t\t\tStrict Transport Security (HSTS)",4),$headers["strict-transport-security"]);
                    splitter();
                }
                else {
                    splitter();
                    echo color("[-] InSecure : Strict Transport Security (HSTS) is NOT Enabled .", 1);
                    echo color($tip0, 6);
                    splitter();
                }



                //Check X-Frame-Options header
                if (array_key_exists("x-frame-options",$headers)){
                    $frame = $headers['x-frame-options'][0];
                    if($frame == "deny") {
                        echo color("[+++] Secure : The page cannot be displayed in a frame, regardless of the site attempting to do so .",0);
                        print_array(color("\t\t\t\tX-Frame-Options",4),$headers["x-frame-options"]);
                        splitter();
                    }
                    elseif ($frame == "sameorigin") {
                        echo color("[++] Secure : The page can only be displayed in a frame on the same origin as the page itself .",0);
                        print_array(color("\t\t\t\tX-Frame-Options",4),$headers["x-frame-options"]);
                        splitter();
                    }
                    elseif (preg_match("/allow-from/",$frame)) {
                        $uri = substr($frame,11);
                        echo color("[+] Secure : The page can only be displayed in a frame on the [ $uri ] origin .",0);
                        print_array(color("\t\t\t\tX-Frame-Options",4),$headers["x-frame-options"]);
                        splitter();
                    }
                    else{
                        echo color("[!] Unable to detect X-Frame-Option header value .",5);
                        splitter();
                    }
                }
                else {
                    echo color("[-] InSecure : The website is vulnerable to Clickjacking attack .", 1);
                    echo color($tip2, 6);
                    splitter();
                }


                //Check X-XSS-Protection header
                if (array_key_exists("x-xss-protection",$headers)){
                    $xss = $headers['x-xss-protection'][0];
                    if(preg_match("/\b1; report=\b/",$xss)){
                        echo color("[+++] Secure : If a cross-site scripting attack (XSS) is detected, browsers will sanitize the page and report the violation .",0);
                        print_array(color("\t\t\t\t\tX-XSS-Protection",4),$headers["x-xss-protection"]);
                        splitter();
                    }
                    elseif (preg_match("/\b1; mode=\b/",$xss)){
                        echo color("[++] Secure : Rather than sanitize the page, when a XSS attack is detected, browsers will prevent rendering of the page .",0);
                        print_array(color("\t\t\t\t\tX-XSS-Protection",4),$headers["x-xss-protection"]);
                        splitter();
                    }
                    elseif ($xss == '1'){
                        echo color("[+] Secure : If a cross-site scripting attack is detected, in order to stop the attack, browsers will sanitize the page .",0);
                        print_array(color("\t\t\t\t\tX-XSS-Protection",4),$headers["x-xss-protection"]);
                        splitter();
                    }
                    else {
                        echo color("[!] Unable to detect X-XSS-Protection header value .", 5);
                        splitter();
                    }
                }
                else {
                    echo color("[-] InSecure : If a cross-site scripting attack is detected, there will be NO browser built-in XSS Filter .", 1);
                    echo color($tip3, 6);
                    splitter();
                }


                //Check X-Content-Type-Options header
                if(array_key_exists("x-content-type-options",$headers)){
                    echo color("[+++] Secure : Browsers will refuse to load the styles and scripts in case they have an incorrect MIME-type .",0);
                    print_array(color("\t\t\t\tX-Content-Type-Options",4),$headers["x-content-type-options"]);
                    splitter();
                }
                else {
                    echo color("[-] InSecure : Browsers are vulnerable to the Content sniffing attack (MIME attack) .", 1);
                    echo color($tip4,6);
                    splitter();
                }


                //Check Public Key Pinning Extension for HTTP (HPKP) header
                if(array_key_exists("public-key-pins",$headers)){
                    echo color("[+++] Secure : The website is SECURE against the Man-In-The-Middle attack (MITM attack) .",0);
                    print_array(color("\t\tPublic Key Pinning Extension for HTTP (HPKP)",4),$headers["public-key-pins"]);
                    splitter();
                }
                else {
                    echo color("[-] InSecure : The website is NOT SECURE against the Man-In-The-Middle attack (MITM) .", 1);
                    echo color($tip1, 6);
                    splitter();
                }


                //Check Content-Security-Policy (CSP) header
                if(array_key_exists("content-security-policy",$headers)){
                    echo color("[+++] Secure : CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections .",0);
                    print_array(color("\t\t\tContent-Security-Policy (CSP)",4),$headers["content-security-policy"]);
                    splitter();
                }
                else {
                    echo color("[-] InSecure : Browsers might be vulnerable to a wide range of attacks, including Cross-site scripting and other cross-site injections .", 1);
                    echo color($tip5,6);
                    splitter();
                }


                //Check X-Permitted-Cross-Domain-Policies header
                if(array_key_exists("x-permitted-cross-domain-policies",$headers)) {
                    $xpcdp = $headers["x-permitted-cross-domain-policies"][0];
                    if (preg_match("/all/", $xpcdp)) {
                        echo color("[-] InSecure : All policy files on this domain are allowed .",1); splitter();
                        print_array(color("\t\t\tX-Permitted-Cross-Domain-Policies",4),$headers["x-permitted-cross-domain-policies"]);
                        echo color($tip6,6);
                        splitter();
                    }
                    else {
                        echo color("[+++] Secure : The remote domains are specified to continue the client transactions like ( Adobe Flash Player or Adobe Acrobat ) .", 0);
                        print_array(color("\t\t\tX-Permitted-Cross-Domain-Policies", 4), $headers["x-permitted-cross-domain-policies"]);
                        splitter();
                    }
                }
                else {
                    echo color("[-] InSecure : The remote domains are NOT specified to continue the client transactions like ( Adobe Flash Player or Adobe Acrobat ) .", 1);
                    echo color($tip6,6);
                    splitter();
                }


                //Check Referrer-Policy header
                if(array_key_exists("referrer-policy",$headers)){
                    if(preg_match("/unsafe-url/",$headers["referrer-policy"][0])){
                        echo color("[-] InSecure : The website sends a full URL (stripped from parameters) in Referer header when performing a same-origin or cross-origin request .",1); splitter();
                        print_array(color("\t\t\t\tReferrer-Policy",4),$headers["referrer-policy"]);
                        splitter();
                    }
                    else {
                        echo color("[+++] Secure : The website sanitize Referer header information when performing a same-origin or cross-origin request .",0);
                        print_array(color("\t\t\t\tReferrer-Policy",4),$headers["referrer-policy"]);
                        splitter();
                    }
                }
                else {
                    echo color("[-] InSecure : There is no policy for sending Referer header information when performing a same-origin or cross-origin request .", 1);
                    echo color($tip7, 6);
                    splitter();
                }


                //Check Expect-CT header
                if(array_key_exists("expect-ct",$headers)){
                    echo color("[+++] Secure :  The website indicates that browsers should evaluate connections to the host emitting the header for Certificate Transparency compliance .",0);
                    print_array(color("\t\t\t\t\tExpect-CT",4),$headers["expect-ct"]);
                    splitter();
                }
                else {
                    echo color("[-] InSecure : The website does NOT indicate that browsers should evaluate connections to the host emitting the header for Certificate Transparency compliance .", 1);
                    echo color($tip8,6);
                    splitter();
                }


            } else echo color("[!] Website is not available !\n",5); $url="";
        }
        else echo color("[!] The given URL is not valid .\n",5); $url="";
    }
}while(empty($url));

//Website status checker function
function GetServerStatus($site, $port)
{
    $fp = @fsockopen($site, $port, $errno, $errstr, 2);
    if (!$fp)
        return false;
    else
        return true;
}

//Printing array function
function print_array($title,$array){

    if(is_array($array)){
        foreach ($array as $item) {
            echo "\n" . $title .
                color("||-------------------------------------------------------------||",3) .
                "\r\n";
            echo "\t".$item."\n";
        }
        echo "\r\n".
            color("||-------------------------------------------------------------||",3);

    }else echo "";
}

//Line splitter function
function splitter(){
    echo color("\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n",2);
}

//Line colors function
function color($string,$num){
    switch ($num){
        case 0:
            return "\033[1;32m$string\033[0m\n"; //Light Green
        case 1:
            return "\033[0;31m$string\033[0m\n"; //Red
        case 2:
            return "\033[1;36m$string\033[0m\n"; //Light Cyan
        case 3:
            return "\033[1;33m$string\033[0m\n"; //Yellow
        case 4:
            return "\033[1;35m$string\033[0m\n"; //Light Magenta
        case 5:
            return "\033[1;31m$string\033[0m\n"; //Light Red
        case 6:
            return "\033[0;32m$string\033[0m\n"; //Green
    }
}
