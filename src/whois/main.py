#!/usr/bin/env python
""" whois - Internet domain name and network number directory service
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import getopt
import logging
import os
import sys

import libpnu

from .library import _get_port_by_name, auto_select_server, cached_whois, recursive_whois, whois


# Version string used by the what(1) and ident(1) commands:
ID = "@(#) $Id: whois - Internet domain name and network number directory service v1.0.0 (August 21, 2026) by Hubert Tournier $"

# Default parameters. Can be overcome by environment variables, then command line options
parameters = {
    "Server": "auto",
    "Port": 43,
    "Recursive": True,
    "Verbatim": False,
    "Show comments": True,
    "Show server": False,

    "Database": "",
    "Force refresh": False,
    "Days before refresh": 180,
    "Debug": False,

    "Command flavour": "PNU"
}


####################################################################################################
def _display_help():
    """ Display usage and help """
    #pylint: disable=C0301
    if parameters["Command flavour"] in ("bsd", "bsd:freebsd"):
        print("usage: whois [-aAbfgiIklmPQrRS] [-c country-code | -h hostname] [-p port] name ...", file=sys.stderr)
    else: # PNU
        print("usage: whois [--debug] [--help|-?] [--version]", file=sys.stderr)
        print("       [-@|--auto] [-a|--arin] [-A|--apnic] [-b|--abuse]", file=sys.stderr)
        print("       [-c|--tld|--country TLD] [-d|--db|--database DIR] [-D|--nodb]", file=sys.stderr)
        print("       [-f|--afrinic] [-F|--force] [-g|--gov] [-h|--host HOST] [-i|--internic]", file=sys.stderr)
        print("       [-I|--iana] [-k|--kisa|--krnic] [-l|--lacnic] [-m|--ra|--radb]", file=sys.stderr)
        print("       [-p|--port PORT] [-q|--quiet] [-P|--peering] [-Q|--quick] [-r|--ripe]", file=sys.stderr)
        print("       [-R|--recursive] [-S|--verbatim]", file=sys.stderr)
        print("       [--] simple_query|'complex query' ...", file=sys.stderr)
        print("  ----------------------  -----------------------------------------------------", file=sys.stderr)
        print("  -h|--host HOST          Use the specified HOST instead of the default", file=sys.stderr)
        print("  -p|--port PORT          Connect to the whois server on PORT", file=sys.stderr)
        print("  -Q|--quick              Do a quick lookup", file=sys.stderr)
        print("  -R|--recursive          Do a recursive lookup", file=sys.stderr)
        print("  -S|--verbatim           Prints the output verbatim", file=sys.stderr)
        print("  -q|--quiet              Hide comments", file=sys.stderr)
        print("  ----------------------  -----------------------------------------------------", file=sys.stderr)
        print("  -@|--auto               Tell which server would be selected and abort query", file=sys.stderr)
        print("                          Use the specified server:", file=sys.stderr)
        print("  -a|--arin               * ARIN (American Registry for Internet Numbers)", file=sys.stderr)
        print("  -A|--apnic              * APNIC (Asia/Pacific Network Information Center)", file=sys.stderr)
        print("  -b|--abuse              * Network Abuse Clearinghouse", file=sys.stderr)
        print("  -c|--tld|--country TLD  * Country-class TLD whois server", file=sys.stderr)
        print("  -f|--afrinic            * AfriNIC (African Network Information Center)", file=sys.stderr)
        print("  -g|--gov                * US non-military federal government (.gov)", file=sys.stderr)
        print("  -i|--internic           * InterNIC (Network Information Center .com/net/edu)", file=sys.stderr)
        print("  -I|--iana               * IANA (Internet Assigned Numbers Authority)", file=sys.stderr)
        print("  -k|--kisa|--krnic       * KRNIC (Korea National Internet Development Agency)", file=sys.stderr)
        print("  -l|--lacnic             * LACNIC (Latin American and Caribbean IP address", file=sys.stderr)
        print("                            Regional Registry)", file=sys.stderr)
        print("  -m|--ra|--radb          * RADB (Router Arbiter DataBase)", file=sys.stderr)
        print("  -P|--peering            * Peering DB database of AS numbers", file=sys.stderr)
        print("  -r|--ripe               * RIPE (Réseaux IP Européens)", file=sys.stderr)
        print("  ----------------------  -----------------------------------------------------", file=sys.stderr)
        print("  -d|--db|--database DIR  Use the DIR directory as WHOIS cache database", file=sys.stderr)
        print("  -D|--nodb               Don't use the environment defined cache database", file=sys.stderr)
        print("  -F|--force              Force a refresh of the WHOIS cache for the queries", file=sys.stderr)
        print("  ----------------------  -----------------------------------------------------", file=sys.stderr)
        print("  --debug                 Enable debug mode", file=sys.stderr)
        print("  --help|-?               Print usage and this help message and exit", file=sys.stderr)
        print("  --version               Print version and exit", file=sys.stderr)
        print("  --                      Options processing terminator", file=sys.stderr)
        print("                          Specific WHOIS server options can be used after", file=sys.stderr)
        print(file=sys.stderr)
    #pylint: enable=C0301


####################################################################################################
def _process_environment_variables():
    """ Process environment variables """
    #pylint: disable=C0103, W0602
    global parameters
    #pylint: enable=C0103, W0602

    if "WHOIS_DEBUG" in os.environ:
        parameters["Debug"] = True
        logging.disable(logging.NOTSET)

    if "FLAVOUR" in os.environ:
        parameters["Command flavour"] = os.environ["FLAVOUR"].lower()
    if "WHOIS_FLAVOUR" in os.environ:
        parameters["Command flavour"] = os.environ["WHOIS_FLAVOUR"].lower()

    # Command variants supported:
    if parameters["Command flavour"] in ("bsd", "bsd:freebsd"):
        if "WHOIS_SERVER" in os.environ:
            parameters["Server"] = os.environ["WHOIS_SERVER"]
        elif "RA_SERVER" in os.environ:
            parameters["Server"] = os.environ["RA_SERVER"]
        else:
            parameters["Server"] = "whois.iana.org"

    elif parameters["Command flavour"] == "PNU":
        if "WHOIS_SERVER" in os.environ:
            parameters["Server"] = os.environ["WHOIS_SERVER"]
        elif "RA_SERVER" in os.environ:
            parameters["Server"] = os.environ["RA_SERVER"]
        else:
            parameters["Server"] = "auto"

        if "WHOIS_DATABASE" in os.environ:
            if not os.path.exists(os.environ["WHOIS_DATABASE"]):
                os.makedirs(os.environ["WHOIS_DATABASE"])
            elif not os.path.isdir(os.environ["WHOIS_DATABASE"]):
                logging.critical("Environment variable WHOIS_DATABASE must be a directory name")
                sys.exit(1)
            parameters["Database"] = os.environ["WHOIS_DATABASE"]

        if "WHOIS_CACHEDAYS" in os.environ:
            try:
                parameters["Days before refresh"] = int(os.environ["WHOIS_CACHEDAYS"])
            except ValueError:
                logging.critical("Environment variable WHOIS_CACHEDAYS must be an integer")
                sys.exit(1)
            if parameters["Days before refresh"] < 1:
                logging.critical("Environment variable WHOIS_CACHEDAYS must be more than 1 day")
                sys.exit(1)
    else:
        logging.critical("Unimplemented command FLAVOUR: %s", parameters["Command flavour"])
        sys.exit(1)


####################################################################################################
def _process_command_line():
    """ Process command line options """
    # pylint: disable=C0103, W0602
    global parameters
    # pylint: enable=C0103, W0602

    # option letters followed by : expect an argument
    # same for option strings followed by =
    if parameters["Command flavour"] in ("bsd", "bsd:freebsd"):
        character_options = "aAbc:fgh:iIklmp:PQrRS"
        string_options = []
    else: # PNU
        character_options = "@aAbc:d:DfFgh:iIklmp:PqQrRS?"
        string_options = [
            "abuse",
            "afrinic",
            "apnic",
            "arin",
            "auto",
            "country="
            "db=",
            "debug",
            "database=",
            "force",
            "gov",
            "help",
            "host=",
            "iana",
            "internic",
            "kisa",
            "krnic",
            "lacnic",
            "nodb",
            "peering",
            "port=",
            "quick",
            "quiet",
            "ra",
            "radb",
            "recursive",
            "ripe",
            "tld=",
            "verbatim",
            "version"
        ]

    try:
        options, remaining_arguments = getopt.getopt(
            sys.argv[1:], character_options, string_options
        )
    except getopt.GetoptError as error:
        logging.critical("Syntax error: %s", error)
        _display_help()
        sys.exit(1)

    for option, argument in options:

        if option == "--debug":
            parameters["Debug"] = True
            logging.disable(logging.NOTSET)

        elif option in ("--abuse", "-b"):
            parameters["Server"] = "whois.abuse.net"
            parameters["Recursive"] = False

        elif option in ("--afrinic", "-f"):
            parameters["Server"] = "whois.afrinic.net"
            parameters["Recursive"] = False

        elif option in ("--apnic", "-A"):
            parameters["Server"] = "whois.apnic.net"
            parameters["Recursive"] = False

        elif option in ("--arin", "-a"):
            parameters["Server"] = "whois.arin.net"
            parameters["Recursive"] = False

        elif option in ("--auto", "-@"):
            parameters["Show server"] = True

        elif option in ("--country", "--tld", "-c"):
            parameters["Server"] = argument.lower() + ".whois-servers.net"
            parameters["Recursive"] = False

        elif option in ("--database", "--db", "-d"):
            if not os.path.exists(argument):
                os.makedirs(argument)
            elif not os.path.isdir(argument):
                logging.critical(
                    "Syntax error: %s",
                    "Option -d|--db|--database parameter must be a directory name"
                    )
                sys.exit(1)
            parameters["Database"] = argument

        elif option in ("--force", "-F"):
            parameters["Force refresh"] = True

        elif option in ("--gov", "-g"):
            parameters["Server"] = "whois.nic.gov"
            parameters["Recursive"] = False

        elif option in ("--help", "-?"):
            _display_help()
            sys.exit(0)

        elif option in ("--host", "-h"):
            parameters["Server"] = argument
            parameters["Recursive"] = False

        elif option in ("--iana", "-I"):
            parameters["Server"] = "whois.iana.org"
            parameters["Recursive"] = False

        elif option in ("--internic", "-i"):
            parameters["Server"] = "whois.internic.net"
            parameters["Recursive"] = False

        elif option in ("--kisa", "--krnic", "-k"):
            parameters["Server"] = "whois.krnic.net"
            parameters["Recursive"] = False

        elif option in ("--lacnic", "-l"):
            parameters["Server"] = "whois.lacnic.net"
            parameters["Recursive"] = False

        elif option in ("--nodb", "-D"):
            parameters["Database"] = ""

        elif option in ("--peering", "-P"):
            parameters["Server"] = "whois.peeringdb.com"
            parameters["Recursive"] = False

        elif option in ("--port", "-p"):
            try:
                parameters["Port"] = int(argument)
            except ValueError:
                parameters["Port"] = _get_port_by_name(argument, "tcp")

            if parameters["Port"] < 1 or parameters["Port"] > 65535:
                logging.critical(
                    "Syntax error: %s",
                    "Option -p|--port parameter must be an integer between 1 and 65535"
                    )
                sys.exit(1)

        elif option in ("--quick", "-Q"):
            parameters["Recursive"] = False

        elif option in ("--quiet", "-q"):
            parameters["Show comments"] = False

        elif option in ("--ra", "--radb", "-m"):
            parameters["Server"] = "whois.ra.net" # "whois.radb.net"
            parameters["Recursive"] = False

        elif option in ("--recursive", "-R"):
            parameters["Recursive"] = True

        elif option in ("--ripe", "-r"):
            parameters["Server"] = "whois.ripe.net"
            parameters["Recursive"] = False

        elif option in ("--verbatim", "-S"):
            # Note: the default behavior differs from the one of the original BSD whois command
            parameters["Verbatim"] = True
            parameters["Show comments"] = True

        elif option == "--version":
            print(ID.replace("@(" + "#)" + " $" + "Id" + ": ", "").replace(" $", ""))
            sys.exit(0)

    return remaining_arguments


####################################################################################################
def main():
    """ The program's main entry point """
    program_name = os.path.basename(sys.argv[0])
    libpnu.initialize_debugging(program_name)
    libpnu.handle_interrupt_signals(libpnu.interrupt_handler_function)
    _process_environment_variables()
    arguments = _process_command_line()

    if not arguments:
        _display_help()
        if parameters["Command flavour"] in ("bsd", "bsd:freebsd"):
            sys.exit(64)
        # elif parameters["Command flavour"] == "PNU":
        sys.exit(1)

    for query in arguments:
        if parameters["Show server"]:
            server = auto_select_server(query)
            print(f"query: {query}")
            print(f"WHOIS server: {server}")
        else:
            if parameters["Database"]:
                results = cached_whois(
                    query,
                    database=parameters["Database"],
                    cachedays=parameters["Days before refresh"],
                    force_refresh=parameters["Force refresh"],
                    server=parameters["Server"],
                    port=parameters["Port"],
                    recursive=parameters["Recursive"],
                    show_comments=parameters["Show comments"],
                    debug=parameters["Debug"]
                )
            else:
                results = recursive_whois(
                    query,
                    server=parameters["Server"],
                    port=parameters["Port"],
                    recursive=parameters["Recursive"],
                    show_intermediates=True,
                    show_redirections=parameters["Debug"],
                    show_comments=parameters["Show comments"]
                )

            for line in results:
                print(line)
            print()

    sys.exit(0)


if __name__ == "__main__":
    main()
