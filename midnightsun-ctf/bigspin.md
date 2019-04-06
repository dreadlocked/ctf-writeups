
## Bigspin (web)

This weekend, my mates of ID-10-T Team and I decided to play the Midnightsun CTF, we had a long time without playing CTFs so it was nice to meet again and solve some challenges.

The Bigspin challenge, from web cathegory, has the following statement:

```
This app got hacked due to admin and uberadmin directories being open. Was just about to wget -r it, but then they fixed it :( Can you help me get the files again?

Service: http://bigspin-01.play.midnightsunctf.se:3123

Author: avlidienbrunn
```

### Intro
First is first, let's see what this application looks like on it's root path:
```
<html>
    What's it gonna be? Are you an 
    <a href="/uberadmin/">uberadmin</a>, 
    an <a href="/admin/">admin</a>, 
    a <a href="/user/">user</a>, 
    or (most likely) just a <a href="/pleb/">pleb</a>?
</html>
```
Ok so we have four kind of "privilege" levels, and probably we need to reach /uberadmin/ path, cool but, How? Trying to just navigate http://bigspin-01.play.midnightsunctf.se:3123/uberadmin/ shows us an Nginx 403 default error, the same occurs with /user, otherwise, /admin shows a 404. How about /pleb?.

/pleb path returns a 200 OK with the HTML body of http://www.example.com/. 

![pleb1](https://raw.githubusercontent.com/dreadlocked/ctf-writeups/master/images/bigspin/bigspin_1.png)

Usually, when I face Nginx servers on CTFs and in some real-world cases, I instantly think about Nginx-alias path traversal vulenerabilities, so I tested /pleb../ and.. the server returns 502 Bad Gateway error. 

![pleb2](https://raw.githubusercontent.com/dreadlocked/ctf-writeups/master/images/bigspin/bigspin_2.png)

Wait, what? If not vulnerable, it should return 404, if vulnerable it should return 404 or 200, as we are asking for an existing file or path.

### 1/3 beating user level.
Now we have an unexpected behaviour, when the /pleb/ string is present on the path, the server returns the HTML body of example.com, this could be an indicative of ```proxy_pass``` Nginx directive acting as a reverse proxy to www.example.com, but if we add any characters to the end of /pleb, like /plebidiot, the server returns 502, this means that the server is trying to reach www.example.comidiot, as it can't reach that domain, it returns 502.

Well, so now we know that some kind of SSRF can be done here, my man @dj.thd told us, what if you use a dynamically resolver dns server based on level1 subdomain, and ignoring  other low-level subdomains? Like this www.example.com.127.0.0.1.idiots.com -> 127.0.0.1. Great idea, fortunately for us, there's a service that does exactly this, nip.io. 

So, let's see what happens, when we try to reach /pleb.127.0.0.1.nip.io/user/,

![pleb3](https://raw.githubusercontent.com/dreadlocked/ctf-writeups/master/images/bigspin/bigspin_3.png)

Ding ding ding!!! Win!!! We reached /users/ folder, with shows us an Index folder where we can see an "nginx.cönf " file. To read it, my man @patatasfritas used double URL encoding, as Nginx is not that friendly when trying to read files with special characters.

### 1/3 beating user level.

The nginx.conf file contained the following directives:
```
 # omited for readability

http {

    # omited for readability

    server {
        listen 80;

        location / {
            root /var/www/html/public;
            try_files $uri $uri/index.html $uri/ =404;
        }

        location /user {
            allow 127.0.0.1;
            deny all;
            autoindex on;
            root /var/www/html/;
        }

        location /admin {
            internal;
            autoindex on;
            alias /var/www/html/admin/;
        }

        location /uberadmin {
            allow 0.13.3.7;
            deny all;
            autoindex on;
            alias /var/www/html/uberadmin/;
        }

        location ~ /pleb([/a-zA-Z0-9.:%]+) {
            proxy_pass   http://example.com$1;
        }

        access_log /dev/stdout;
        error_log /dev/stdout;
    }

}
```

Well, see that? /user path can only be reached on localhost, we aimed that using the location /pleb SSRF, pointing a user controlled domain to 127.0.0.1 using nip.io, a classic SSRF tip.

### 2/3 beating admin level.
Now we need to reach ```/admin```, it's configuration is the same, but this time it has an ```internal``` nginx directive, what means internal? Let's Google a bit:

```
Specifies that a given location can only be used for internal requests. 
For external requests, the client error 404 (Not Found) is returned. Internal requests are the following:

-   requests redirected by the error_page, index, random_index, and try_files directives;
-   requests redirected by the “X-Accel-Redirect” response header field from an upstream server;
-   subrequests formed by the include virtual command of the  ngx_http_ssi_module  module, by the ngx_http_addition_module module directives,
and by auth_request and  mirror directives; requests changed by the rewrite directive.
```

Ok, while reading this snippet of documentation, the ```X-Accel-Redirect``` header shines among so many directives. What if we try to do the same as the previous step, but this time resolving to a user controlled server, which always redirects with ```X-Accel-Redirect```pointing to ```/admin```? We can use nip.io again to do this. 

First, we need to setup a simple python web server and configure it to always redirect, simple. Then, we try to reach /pleb.X.X.X.X.nip.io, if everything works, the admin folder should be returned and...

Ding ding ding!!! Win!!! Another win, now we can reach /admin location.

### 3/3 beating uberadmin level.
This level was easy peasy, as when seeing the Nginx configuration file, it highlights the alias traversal on /admin location, so we just need to configure our python server with ```X-Accel-Redirect: /admin..uberadmin/flag.txt``` and...

![pleb4](https://raw.githubusercontent.com/dreadlocked/ctf-writeups/master/images/bigspin/bigspin_4.png)

Win!!! We got the flag.

### Final thoughts
This challenge was really funny, it's curious how sensitive an Nginx configuration file is. Thanks to @HackingPatatas and @dj.thd for solving this challenge with me.

Feel free to ping me if you see any mistake at @_dreadlocked on twitter.
