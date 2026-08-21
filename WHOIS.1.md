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
simple_query|'complex query' ...

## DESCRIPTION
The **whois** utility looks up records in the databases maintained by several Network Information Centers (NICs).

By default **whois** starts by querying the Internet Assigned Numbers Authority (IANA) whois server, and follows referrals to whois servers that have more specific details about the query. 
The IANA whois server knows about IP address and AS numbers as well as domain names.

However, when the query is about an IP address, this **whois** version will directly goes to the appropriate registry server,
as well as automatically following to the relevant registry server when the ARIN registry points to another registry without issuing a redirection.

### OPTIONS
Options | Use
------- | ---
-h\|--host HOST|Use the specified HOST instead of the default. Either a host name or an IP address may be specified.
-p\|--port PORT|Connect to the whois server on PORT. If this option is not specified, whois defaults to port 43.
-Q\|--quick|Do a quick lookup; whois will not attempt to follow referrals to other whois servers. This is the default if a server is explicitly specified using one of the other options or in an environment variable. See also the -R option.
-R\|--recursive|Do a recursive lookup; whois will attempt to follow referrals to other whois servers. This is the default if no server is explicitly specified. See also the -Q option.
-S\|--verbatim|By default whois adjusts simple queries (without spaces) to produce more useful output from certain whois servers, and it suppresses some uninformative output. With the -S option, whois sends the query and prints the output verbatim.
-q\|--quiet|Hide comments
-@\|--auto|Tell which server would be selected and abort the query
-a\|--arin|Use the American Registry for Internet Numbers (ARIN) database. It contains network numbers used in those parts of the world covered neither by APNIC, AfriNIC, LACNIC, nor by RIPE. The query syntax is documented at [https://www.arin.net/resources/registry/whois/rws/cli/](https://www.arin.net/resources/registry/whois/rws/cli/)
-A\|--apnic|Use the Asia/Pacific Network Information Center (APNIC) database. It contains network numbers used in East Asia, Australia, New Zealand, and the Pacific islands. The query syntax is documented at [https://www.apnic.net/manage-ip/using-whois/searching/query-options/](https://www.apnic.net/manage-ip/using-whois/searching/query-options/) or you can get it using whois -A help
-b\|--abuse|Use the Network Abuse Clearinghouse database. It contains addresses to which network abuse should be reported, indexed by domain name.
-c\|--tld\|--country TLD|This is the equivalent of using the -h option with an argument of "TLD.whois‐servers.net". This can be helpful for locating country‐class TLD whois servers.
-f\|--afrinic|Use the African Network Information Centre (AfriNIC) database. It contains network numbers used in Africa and the islands of the western Indian Ocean. The query syntax was documented at [https://www.afrinic.net/support/whois/manual](https://web.archive.org/web/20201022084312/https://www.afrinic.net/support/whois/manual) or you can get it using whois ‐f help
-g\|--gov|Use the US non‐military federal government database, which contains points of contact for subdomains of .GOV.
-i\|--internic|Use the traditional Network Information Center (InterNIC) (whois.internic.net) database. This now contains only registrations for domain names under .COM, .NET, .EDU. You can specify the type of object to search for like whois ‐i ’type name’ where type can be domain, nameserver, registrar. The name can contain * wildcards. Get query syntax documentation using whois -i help
-I\|--iana|Use the Internet Assigned Numbers Authority (IANA) database. The query syntax is documented at [https://www.iana.org/help/whois](https://www.iana.org/help/whois)
-k\|--kisa\|--krnic|Use the National Internet Development Agency of Korea’s (KRNIC) database. It contains network numbers and domain contact information for Korea.
-l\|--lacnic|Use the Latin American and Caribbean IP address Regional Registry (LACNIC) database. This server accepts only direct match queries (POCs, ownerid, CIDR blocks, IP and AS numbers).
-m\|--ra\|--radb|Use the Route Arbiter Database (RADB) database. It contains route policy specifications for a large number of operators’ networks.
-P\|--peering|Use the PeeringDB database of AS numbers. It contains details about presence at internet peering points for many network operators.
-r\|--ripe|Use the Réseaux IP Européens (RIPE) database. It contains network numbers and domain contact information for Europe. The query syntax is documented at [https://docs.db.ripe.net/Tables-of-Query-Types-Supported-by-the-RIPE-Database](https://docs.db.ripe.net/Tables-of-Query-Types-Supported-by-the-RIPE-Database#tables-of-query-types-supported-by-the-ripe-database) or you can get it using whois ‐r help
-d\|--db\|--database DIR|Use the DIR directory as WHOIS cache database
-D\|--nodb|Don't use the environment defined cache database
-F\|--force|Force a refresh of the WHOIS cache for the queries
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator. Specific WHOIS server options can be used after

## ENVIRONMENT
The WHOIS_DEBUG environment variable can be set to any value to enable debug mode.

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
[wis(1)](https://github.com/HubTou/wis),
[whois(3)](https://github.com/HubTou/whois/blob/main/WHOIS.3.md)

## STANDARDS
K.  Harrenstien,  M. Stahl, and E. Feinler, NICNAME/WHOIS, RFC 954, October 1985.

L. Daigle, WHOIS Protocol Specification, RFC 3912, September 2004.
     
The **whois** utility is a standard UNIX command, though not a POSIX one.

This re-implementation tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
Tested OK under Windows.

## HISTORY
The **whois** command appeared in 4.3BSD (OpenBSD's version mentions 4.1cBSD but a [whois manpage](https://www.tuhs.org/cgi-bin/utree.pl?file=4.3BSD/usr/man/man1/whois.1) only appeared in 4.3BSD).

This re-implementation was made for the [PNU project](https://github.com/HubTou/PNU).

It was mostly written in December 2022, but I left it unfinished by the end of my winter vacations and forgot to update the related GitHub repository...

This work is dedicated to the memory of my late colleague **Sébastien Richard**, who passed away while I was finalizing it.
I miss you Seb'.

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

This manual page is based on the one written for [FreeBSD](https://www.freebsd.org/).

## CAVEATS
When serving answers from the database cache, only the main item requested is shown.
For an inetnum record, for example, the contacts, organisation and routes are not displayed, though you can request their cached version on their own.
If you want an answer similar to the original one, use the *-D* option to bypass the database cache.
Note that for the ARIN registry, there is no obvious relationship with original contacts when you use a cached answer...

The database cache is never purged.

I didn't made extensive tests to ensure 100% similar behaviour for the FreeBSD flavour.

## SECURITY CONSIDERATIONS
Be careful not to send too many requests to WHOIS servers or use the caching options to avoid unnecessary ones!
