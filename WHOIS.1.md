# WHOIS(1)

## NAME
WHOIS - Internet domain name and network number directory service

## SYNOPSIS
**whois**
\[--debug\]
\[--help|-?\]
\[--version\]
\[-@|--auto\]
\[-a|--arin\]
\[-A|--apnic\]
\[-b|--abuse\]
\[-c|--tld|--country TLD\]
\[-d|--db|--database DIR\]
\[-D|--nodb\]
\[-f|--afrinic\]
\[-F|--force\]
\[-g|--gov\]
\[-h|--host HOST\]
\[-i|--internic\]
\[-I|--iana\]
\[-k|--kisa|--krnic\]
\[-l|--lacnic\]
\[-m|--ra|--radb\]
\[-p|--port PORT\]
\[-q|--quiet\]
\[-P|--peering\]
\[-Q|--quick\]
\[-r|--ripe\]
\[-R|--recursive\]
\[-S|--verbatim\]	   
\[--\]
simple_query|"complex_query" ...

## DESCRIPTION
The **whois** utility looks up records in the databases maintained by several Network Information Centers (NICs).

By default whois starts by querying the Internet Assigned Numbers Authority (IANA) whois server, and follows referrals to whois servers that have more specific details about the query. 
The IANA whois server knows about IP address and AS numbers as well as domain names.

However, when the query is about an IP address, this **whois** version version will directly goes to the appropriate registry server,
as well as automatically following to the relevant registry server when the ARIN registry points to another registry without issuing a redirection.

### OPTIONS
Options | Use
------- | ---
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator

## ENVIRONMENT
The WHOIS_DEBUG environment variable can also be set to any value to enable debug mode.

The *FLAVOUR* or *WHOIS_FLAVOUR* environment variables can be set to one of the following values, to implement only the corresponding options and behaviours:
* bsd | bsd:freebsd : FreeBSD [whois(1)](https://www.freebsd.org/cgi/man.cgi?query=whois)

Other classical environment variables:
Variable | Use
------- | ---
WHOIS_SERVER|The primary default whois server. If this is unset, whois uses the RA_SERVER environment variable.
RA_SERVER|The secondary default whois server. If this is unset, whois will use whois.iana.org.

## EXIT STATUS
The **whois** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES
To obtain contact information about an administrator located in the Russian TLD domain "RU", use the *-c* option as shown in the following example, where *CONTACT‐ID* is substituted with the actual contact identifier.

```
whois ‐c RU CONTACT‐ID
```

(Note: This example is specific to the TLD "RU", but other TLDs can be queried by using a similar syntax.)

The following example demonstrates how to query a whois server using a non‐standard  port, where “query‐data” is the query to be sent to “whois.example.com” on port “rwhois” (written numerically as 4321).

```
whois ‐h whois.example.com ‐p rwhois query‐data
```
Some whois servers support complex queries with dash‐letter options.
You can use the -- option to separate whois command options from whois server query options.
A query containing spaces must be quoted as one argument to the whois command.
The following example asks the RIPE whois server to return a brief description of its “domain” object type:

```
whois ‐r ‐‐ ’‐t domain’
```

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
The **whois** command appeared in 4.3BSD.

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
If you want an answer similar to the original one, use the *-D* option to bypass the database cache.
Note that for the ARIN registry, there is no obvious relationship with original contacts when you use a cached answer...

The database cache is never purged. 

## SECURITY CONSIDERATIONS
Be careful not to send too many requests to WHOIS servers or use the caching options to avoid unnecessary ones!
