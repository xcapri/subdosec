import sys
import os
import argparse
import pyfiglet

from ..shared import colors
from ..shared.utils import is_port_in_use

from ..core.entities import ScanConfig
from ..core.use_cases.scan_use_case import ScanUseCase
from ..core.use_cases.gemini_use_case import GeminiUseCase
from ..core.use_cases.fingerprint_use_case import FingerprintUseCase

from ..infrastructure.file_storage import FileStorage
from ..infrastructure.node_server import NodeServerManager
from ..infrastructure.api_client import ApiClient
from ..infrastructure.gemini_client import GeminiClient


class CliApp:
    def __init__(self):
        self.storage = FileStorage()
        self.server_mgr = NodeServerManager(self.storage)
        self.api_client = ApiClient(self.storage)
        self.ai_analyzer = GeminiClient(self.storage)

        self.scan_use_case = ScanUseCase(
            self.api_client, self.server_mgr, self.api_client, self.storage
        )
        self.gemini_use_case = GeminiUseCase(self.api_client, self.ai_analyzer)
        self.fp_use_case = FingerprintUseCase(self.api_client)

    def print_status(self) -> None:
        """Print live status of services."""
        try:
            _, _, _, _, node_port = self.storage.load_env_vars('public')
            
            # Local API server status
            api_on = is_port_in_use(int(node_port))
            api_status = f"{colors.GREEN}ON{colors.RESET} {colors.DIM}(port {node_port}){colors.RESET}" if api_on else f"{colors.RED}OFF{colors.RESET}"
            
            # Gemini API key status
            user_dir = self.storage.get_user_dir()
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

    def print_usage(self) -> None:
        """Print a clean usage guide when no args and no stdin."""
        self.server_mgr.ensure_server_running()
        self.print_status()
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

    def run(self) -> None:
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
        parser.add_argument('-su', action='store_true', help='Skip undetect will not stored to server')
        parser.add_argument('-lu', type=str, help='Undetec stored localy to the specified path. Example: -lu /path/to/dir')
        parser.add_argument('-lm', action='store_true', help='Local Mode: Save vuln and undetect to default inside tools directory')
        parser.add_argument('-uf', action='store_true', help='Update Fingerprint')
        parser.add_argument('-unai', type=str, help='Analyze undetected subdomains using AI. Example: -unai /path/to/undetect.json')
        parser.add_argument('-v', '--verbose', action='store_true', help='Show progress count (e.g. [1/10])')
        parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use for scanning (default: 10)')

        args = parser.parse_args()

        has_action = any([args.help, args.initkey, args.uf, args.pf, args.sfid, args.ks, args.unai, args.subfng])
        has_stdin = not sys.stdin.isatty()

        if args.help or (not has_action and not has_stdin):
            self.print_usage()
            sys.exit(0)

        # Build ScanConfig
        config = ScanConfig(
            mode=args.mode,
            vuln_only=args.vo,
            print_errors=args.pe,
            thread_count=args.threads,
            verbose=args.verbose,
            local_mode=args.lm,
            output_dir=args.o,
            local_undetect_dir=args.lu,
            skip_undetect_server=args.su,
            private_fingerprint_path=args.pf
        )
        # Lock target service filter
        config.lock_fingerprints = args.lf

        if args.lm:
            user_dir = self.storage.get_user_dir()
            if not config.output_dir:
                 config.output_dir = os.path.join(user_dir, 'vulns')
            if not config.local_undetect_dir:
                 config.local_undetect_dir = os.path.join(user_dir, 'undetect')

        # Execute appropriate action
        if args.subfng:
            self.fp_use_case.submit_fingerprint(args.subfng)
            sys.exit(0)

        if args.initkey:
            self.storage.init_key(args.initkey)
        elif args.uf:
            _, _, _, host_scan_prod, _ = self.storage.load_env_vars('public')
            self.fp_use_case.update_fingerprints(host_scan_prod)
        elif args.pf and not config.output_dir:
            print(colors.error("If you use -pf, you must save the scan to local with -o /path/to/save"))
            sys.exit(1)
        elif args.sfid:
            _, _, _, host_scan_prod, _ = self.storage.load_env_vars('public')
            self.fp_use_case.list_fingerprints(host_scan_prod)
        elif args.ks:
            self.server_mgr.kill_server()
        elif args.unai:
            _, _, _, host_scan_prod, _ = self.storage.load_env_vars('public')
            self.gemini_use_case.execute(args.unai, host_scan_prod)
        else:
            targets = [line.strip() for line in sys.stdin if line.strip()]
            self.scan_use_case.execute(config, targets)


def main():
    app = CliApp()
    app.run()


if __name__ == "__main__":
    main()
