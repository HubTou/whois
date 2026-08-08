# WHOIS(1)

## NAME
WHOIS - Internet domain name and network number directory service

## SYNOPSIS
**COMMAND**
\[--debug\]
\[--help|-?\]
\[--version\]
\[--\]

## DESCRIPTION
The **COMMAND** utility

### OPTIONS
Options | Use
------- | ---
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator

## ENVIRONMENT
The COMMAND_DEBUG environment variable can also be set to any value to enable debug mode.

The *FLAVOUR* or *COMMAND_FLAVOUR* environment variables can be set to one of the following values, to implement only the corresponding options and behaviours:
* posix : POSIX [COMMAND](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/COMMAND.html)
* unix | unix:v10 : Unix v10 [COMMAND(1)](http://man.cat-v.org/unix_10th/1/COMMAND)
* bsd | bsd:freebsd : FreeBSD [COMMAND(1)](https://www.freebsd.org/cgi/man.cgi?query=COMMAND)
* gnu | gnu:linux | linux : GNU/Linux [COMMAND(1)](https://man7.org/linux/man-pages/man1/COMMAND.1.html)
* plan9 : Plan 9 [COMMAND(1)](http://man.cat-v.org/plan_9/1/COMMAND)
* inferno : Inferno [COMMAND(1)](http://man.cat-v.org/inferno/1/COMMAND)

However, if the *POSIXLY_CORRECT* environment variable is set to any value, then the POSIX flavour will be selected.

## EXIT STATUS
The **whois** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES


## SEE ALSO
[wis(1)](https://github.com/HubTou/wis)

## STANDARDS
K.  Harrenstien,  M. Stahl, and E. Feinler, NICNAME/WHOIS, RFC 954, October 1985.

L. Daigle, WHOIS Protocol Specification, RFC 3912, September 2004.
     
The **whois** utility is a standard UNIX command, though not a POSIX one.

This re-implementation tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
To be tested under Windows.

## HISTORY
The whois command appeared in 4.3BSD.

This re-implementation was made for the [PNU project](https://github.com/HubTou/PNU).

It was mostly written in December 2022, but I left it unfinished by the end of my winter vacations and forgot to update the related GitHub repository...

This work is dedicated to the memory of my late colleague **Sébastien Richard**, who passed away while I was finalizing it.
I miss you Seb'.

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

This manual page is mainly based on the one written for [FreeBSD](https://www.freebsd.org/).

## CAVEATS
When serving answers from the database cache, only the main item requested is shown.
For an inetnum record, for example, the contacts, organisation and routes are not displayed, though you can request their cached version on their own.
If you want the answer similar to the original one, use the *-D* option to bypass the database cache.
Note that for the ARIN registry, there is no obvious relationship with original contacts when you use a cached answer...

The database cache is never purged. 

## SECURITY CONSIDERATIONS
Be careful not to send too many requests to WHOIS servers or use the caching options to avoid unnecessary ones!
