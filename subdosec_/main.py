#!/usr/bin/python3

import sys
import os
import argparse
import pyfiglet

from .app_config import init_key, load_env_vars, get_user_dir
from .node_manager import run_node_server, kill_server
from .api import submit_fingerprint, check_fingerprint, fetch_fingerprints
from .gemini_analyzer import analyze_with_gemini
from .scanner import scan_by_web

def main():
    
    print(f"{pyfiglet.figlet_format('Subdosec', font='slant')}\n")
    parser = argparse.ArgumentParser(description='Subdomain takeover scanner.')
    parser.add_argument('-mode', choices=['private', 'public'], default='public', help='Mode of operation (private/public)')
    parser.add_argument('-initkey', help='Initialize the API key')
    parser.add_argument('-vo', action='store_true', help='VULN Only: Hide UNDETECT messages')
    parser.add_argument('-pe', action='store_true', help='Print Error: When there are problems detecting your target')
    parser.add_argument('-ins', action='store_true', help='Prepar node & start server')
    parser.add_argument('-pf', type=str,  help='Private Fingerprint: uses your local fingerprint. Example: -pf /path/to/tko.json')
    parser.add_argument('-subfng', type=str, help='Submit fingerprint: submit local fingerprint to admin. Example: -subfng localfinger.json')
    parser.add_argument('-lf', default='all',  help='Fingerprint lock: to focus on one or multiple fingerprints. (-lf github.io,surge.sh) and leave this arg to scan all fingerprints')
    parser.add_argument('-sfid', action='store_true',  help='To view all available fingerprint ids.')
    parser.add_argument('-ks', action='store_true',  help='To shut down the server node if you want to not use subdosec for a long time.')
    parser.add_argument('-o', type=str, help='Save result locally to the specified path. Example: -o /path/to/dir')
    parser.add_argument('-su', action='store_true', help='Skip undetect will not stored to server (https://subdosec.vulnshot.com/result/undetected)')
    parser.add_argument('-lu', type=str, help='Undetec stored localy to the specified path. Example: -lu /path/to/dir')
    parser.add_argument('-lm', action='store_true', help='Local Mode: Save vuln and undetect to default inside tools directory')
    parser.add_argument('-uf', action='store_true', help='Update Fingerprint')
    parser.add_argument('-unai', type=str, help='Analyze undetected subdomains using AI. Example: -unai /path/to/undetect.json')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show progress count (e.g. [1/10])')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use for scanning (default: 10)')

    
    args = parser.parse_args()

    if args.lm:
        user_dir = get_user_dir()
        if not args.o:
             args.o = os.path.join(user_dir, 'vulns')
        if not args.lu:
             args.lu = os.path.join(user_dir, 'undetect')

    if args.subfng:
        submit_fingerprint(args.subfng)
        sys.exit(0)

    if args.initkey:
        init_key(args.initkey)
    elif args.uf:
        _, _, _, host_scan_prod, _ = load_env_vars('public')
        fetch_fingerprints(host_scan_prod, True)
    elif args.ins:
        run_node_server()
    elif args.pf and not args.o:
        print("Error: If you use -pf, you must save the scan to local with -o /path/to/save")
        sys.exit(1)
    elif args.sfid:
        check_fingerprint(1)
    elif args.ks:
        kill_server()
    elif args.unai:
        analyze_with_gemini(args.unai)
    else:
        scan_by_web(args.mode, args.vo, args.pe, args.lf,  args.o,  args.pf, args.su, args.lu, args.verbose, args.threads)

if __name__ == "__main__":
    main()
