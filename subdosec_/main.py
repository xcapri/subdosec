#!/usr/bin/python3

import sys
import os
import argparse
import pyfiglet

from .app_config import init_key, load_env_vars, get_user_dir
from .node_manager import kill_server, ensure_server_running
from .api import submit_fingerprint, check_fingerprint, fetch_fingerprints
from .gemini_analyzer import analyze_with_gemini
from .scanner import scan_by_web
from .utils import is_port_in_use
from . import colors


def print_status():
    """Print live status of services."""
    try:
        _, _, _, host_scan_prod, node_port = load_env_vars('public')
        
        # Local API server status
        api_on = is_port_in_use(int(node_port))
        api_status = f"{colors.GREEN}ON{colors.RESET} {colors.DIM}(port {node_port}){colors.RESET}" if api_on else f"{colors.RED}OFF{colors.RESET}"
        
        # Gemini API key status
        user_dir = get_user_dir()
        env_file = os.path.join(user_dir, '.env')
        gemini_key = ""
        if os.path.exists(env_file):
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=env_file)
            gemini_key = os.getenv('GEMINI_API_KEY', '')
        gemini_status = f"{colors.GREEN}SET{colors.RESET}" if gemini_key else f"{colors.YELLOW}NOT SET{colors.RESET}"
        
        # Fingerprint cache status
        offinger = os.path.join(user_dir, 'offinger.json')
        finger_status = f"{colors.GREEN}CACHED{colors.RESET}" if os.path.exists(offinger) else f"{colors.YELLOW}NOT CACHED{colors.RESET}"
        
        print(f"  {colors.GRAY}Local API{colors.RESET}    : {api_status}")
        print(f"  {colors.GRAY}Gemini Key{colors.RESET}   : {gemini_status}")
        print(f"  {colors.GRAY}Fingerprints{colors.RESET} : {finger_status}")
    except Exception:
        pass


def print_usage():
    """Print a clean usage guide when no args and no stdin."""
    ensure_server_running()
    print_status()
    print(f"""
  {colors.WHITE}{colors.BOLD}Usage:{colors.RESET}
    {colors.GRAY}cat targets.txt |{colors.RESET} {colors.CYAN}subdosec{colors.RESET}                  {colors.DIM}Scan subdomains (public mode){colors.RESET}
    {colors.GRAY}cat targets.txt |{colors.RESET} {colors.CYAN}subdosec -lm{colors.RESET}              {colors.DIM}Scan & save results locally{colors.RESET}
    {colors.CYAN}subdosec -sfid{colors.RESET}                              {colors.DIM}List available fingerprints{colors.RESET}
    {colors.CYAN}subdosec -unai{colors.RESET} {colors.WHITE}undetect.json{colors.RESET}               {colors.DIM}AI analysis of undetected subs{colors.RESET}
    {colors.CYAN}subdosec -uf{colors.RESET}                                {colors.DIM}Update fingerprints{colors.RESET}

  {colors.WHITE}{colors.BOLD}Scan Options:{colors.RESET}
    {colors.GREEN}-mode{colors.RESET} {colors.WHITE}private|public{colors.RESET}  {colors.DIM}Mode of operation (default: public){colors.RESET}
    {colors.GREEN}-vo{colors.RESET}                 {colors.DIM}VULN only: hide UNDETECT messages{colors.RESET}
    {colors.GREEN}-pe{colors.RESET}                 {colors.DIM}Print errors during scan{colors.RESET}
    {colors.GREEN}-lf{colors.RESET} {colors.WHITE}github.io{colors.RESET}       {colors.DIM}Lock to specific fingerprints (-lf surge.sh,github.io){colors.RESET}
    {colors.GREEN}-pf{colors.RESET} {colors.WHITE}/path/to.json{colors.RESET}   {colors.DIM}Use private/local fingerprint file{colors.RESET}
    {colors.GREEN}-t{colors.RESET} {colors.WHITE}20{colors.RESET}               {colors.DIM}Set thread count (default: 10){colors.RESET}
    {colors.GREEN}-v{colors.RESET}                  {colors.DIM}Show scan progress counter{colors.RESET}
    {colors.GREEN}-unai{colors.RESET} {colors.WHITE}/path/to/undetect.json{colors.RESET}  {colors.DIM}AI analysis of undetected subdomains{colors.RESET}

  {colors.WHITE}{colors.BOLD}Output Options:{colors.RESET}
    {colors.GREEN}-lm{colors.RESET}                 {colors.DIM}Local mode: save vulns & undetect locally{colors.RESET}
    {colors.GREEN}-o{colors.RESET} {colors.WHITE}/path/to/dir{colors.RESET}     {colors.DIM}Save vuln results to custom path{colors.RESET}
    {colors.GREEN}-lu{colors.RESET} {colors.WHITE}/path/to/dir{colors.RESET}    {colors.DIM}Save undetect results to custom path{colors.RESET}
    {colors.GREEN}-su{colors.RESET}                 {colors.DIM}Skip sending undetect to server{colors.RESET}

  {colors.WHITE}{colors.BOLD}Config & Tools:{colors.RESET}
    {colors.GREEN}-initkey{colors.RESET} {colors.WHITE}YOUR_KEY{colors.RESET}    {colors.DIM}Initialize private API key{colors.RESET}
    {colors.GREEN}-subfng{colors.RESET} {colors.WHITE}finger.json{colors.RESET}  {colors.DIM}Submit fingerprint to admin{colors.RESET}
    {colors.GREEN}-uf{colors.RESET}                 {colors.DIM}Update fingerprints from server{colors.RESET}
    {colors.GREEN}-sfid{colors.RESET}               {colors.DIM}View all available fingerprint IDs{colors.RESET}
    {colors.GREEN}-ks{colors.RESET}                 {colors.DIM}Kill background server{colors.RESET}
""")


def main():
    
    print(f"{colors.banner_color(pyfiglet.figlet_format('Subdosec', font='slant'))}\n")
    parser = argparse.ArgumentParser(description='Subdomain takeover scanner.', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show usage guide')
    parser.add_argument('-mode', choices=['private', 'public'], default='public', help='Mode of operation (private/public)')
    parser.add_argument('-initkey', help='Initialize the API key')
    parser.add_argument('-vo', action='store_true', help='VULN Only: Hide UNDETECT messages')
    parser.add_argument('-pe', action='store_true', help='Print Error: When there are problems detecting your target')
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

    # No args and no piped stdin → show usage
    has_action = any([args.help, args.initkey, args.uf, args.pf, args.sfid, args.ks, args.unai, args.subfng])
    has_stdin = not sys.stdin.isatty()

    if args.help or (not has_action and not has_stdin):
        print_usage()
        sys.exit(0)

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
    elif args.pf and not args.o:
        print(colors.error("If you use -pf, you must save the scan to local with -o /path/to/save"))
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
