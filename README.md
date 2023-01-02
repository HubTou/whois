# Installation
Depending on if you want only this tool, the full set of PNU tools, or PNU plus a selection of additional third-parties tools, use one of these commands:

pip install [pnu-whois](https://pypi.org/project/pnu-whois/)
<br>
pip install [PNU](https://pypi.org/project/PNU/)
<br>
pip install [pytnix](https://pypi.org/project/pytnix/)

# WHOIS(1), WHOIS(3)
This repository includes a command-line utility (**a portable BSD whois command clone, with enhancements**):
* [whois(1)](https://github.com/HubTou/whois/blob/main/WHOIS.1.md) - Internet domain name and network number directory service

And a Python library:
* [whois(3)](https://github.com/HubTou/whois/blob/main/WHOIS.3.md) - Internet domain name and network number directory service

Both provide access to classical WHOIS servers (not HTTP servers with RDAP queries), with optional **local caching of results**.
