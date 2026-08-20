# WHOIS(3)

## NAME
WHOIS - Internet domain name and network number directory service

## SYNOPSIS
import **pnu_whois**

String pnu_whois.**auto_select_server**(
    String query
)

List pnu_whois.**whois**(
    String query,
    String server="whois.iana.org",
    Integer port=43,
    Boolean show_comments=True
)

List pnu_whois.**recursive_whois**(
   String query,
   String server="whois.iana.org",
   Integer port=43,
   Boolean recursive=True,
   Boolean show_intermediates=True,
   Boolean show_redirections=False,
   Boolean show_comments=True
)

List pnu_whois.**cached_whois**(
    String query,
    String database,
    Integer cachedays,
    Boolean force_refresh=False,
    String server="whois.iana.org",
    Integer port=43,
    Boolean recursive=True,
    Boolean show_comments=True,
    Boolean debug=False
)

## DESCRIPTION
The **auto_select_server**() function attempts to determine the authoritative server for the *query* and returns its name.
For IP addresses, it uses the [IPv4 Address Space](https://www.iana.org/assignments/ipv4-address-space) from IANA, in a way similar to RDAP.

The **whois**(), **recursive_whois**() and **cached_whois**() functions all perform a direct *query* to a WHOIS *server*:*port* and return the results as a list of lines.

If you don't want to specify a server:port, or use the default whois.iana.org:43, you can set the server parameter to "auto" and it'll use the **auto_select_server**() function above.

The server results are unaltered with the possible exception of comments (lines starting with "%" or "#") which can be stripped by setting the *show_comments* parameter to False.

The **recursive_whois**() function will follow servers redirections (lines starting with "whois:") unless its *recursive* parameter is set to False.

By default, it will include the intermediate servers results unless its *show_intermediates* parameter is set to False.

It can also print the server redirections to stderr if the *show_redirections* parameter is set to True.

The **cached_whois**() function will attempt to answer from its cache database first if a fresh enough result is available,
or it'll fallback to **recursive_whois**() but with *Show_intermediates*=False.

You must specify the directory to use as a (.xz compressed files) cache database with the *database* parameter, and the number of day a cached result is considered fresh with the *cachedays* parameter.

You can use set the *force_refresh* parameter to True if you want to bypass and update the cache.

It can also print cache hits or misses to stderr if the *debug* parameter is set to True.

## ENVIRONMENT
The WHOIS_DEBUG environment variable can also be set to any value to enable debug mode.

The *FLAVOUR* or *WHOIS_FLAVOUR* environment variables can be set to one of the following values, to implement only the corresponding options and behaviours:
* bsd | bsd:freebsd : FreeBSD [whois(1)](https://www.freebsd.org/cgi/man.cgi?query=whois)

Other classical environment variables:
Variable | Use
------- | ---
WHOIS_SERVER|The primary default whois server. If this is unset, whois uses the RA_SERVER environment variable.
RA_SERVER|The secondary default whois server. If this is unset, whois will use whois.iana.org or auto-select the server for IP addresses.

Version specific environment variables:
Variable | Use
------- | ---
WHOIS_DATABASE|A directory pathname where the compressed query results will be stored
WHOIS_CACHEDAYS|An integer specifying the number of days a cached result can be reused

## SEE ALSO
[whois(1)](https://github.com/HubTou/whois/blob/main/WHOIS.1.md)

## STANDARDS
K.  Harrenstien,  M. Stahl, and E. Feinler, NICNAME/WHOIS, RFC 954, October 1985.

L. Daigle, WHOIS Protocol Specification, RFC 3912, September 2004.
     
The **whois** library is not a standard UNIX one.

It tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
Tested OK under Windows.

## HISTORY
The **whois** command appeared in 4.3BSD (OpenBSD's version mentions 4.1cBSD but a [whois manpage](https://www.tuhs.org/cgi-bin/utree.pl?file=4.3BSD/usr/man/man1/whois.1) only appeared in 4.3BSD),
but there was no companion library.

This implementation was made for the [PNU project](https://github.com/HubTou/PNU).

It was mostly written in December 2022, but I left it unfinished by the end of my winter vacations and forgot to update the related GitHub repository...

This work is dedicated to the memory of my late colleague **Sébastien Richard**, who passed away while I was finalizing it.
I miss you Seb'.

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

## CAVEATS
When serving answers from the database cache, only the main item requested is returned.
For an inetnum record, for example, the contacts, organisation and routes are not returned, though you can request their cached version on their own.
If you want an answer similar to the original one, use the *force_refresh* option to bypass the database cache.
Note that for the ARIN registry, there is no obvious relationship with original contacts when you use a cached answer...

The database cache is never purged.

## SECURITY CONSIDERATIONS
Be careful not to send too many requests to WHOIS servers or use the caching version to avoid unnecessary ones!
