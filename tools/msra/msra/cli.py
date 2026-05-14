"""Command-line interface for MSRA."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple

from .report import generate_html_report, render_pdf_from_html
from .scanner import Scanner
from .patterns import PatternManager, PatternConfig
from .utils import iter_source_files
from .dynamic import GenymotionController, DynamicTestExecutor, AppMonitor, generate_dynamic_report
from .dynamic.executor import EnhancedDynamicExecutor, create_executor
from .crawler import ThreatIntelUpdater, UpdateConfig
from .visualizer import AppStructureAnalyzer, VisualizationRenderer, VisualizationConfig


# ============================================================================
# Interactive Mode Helpers
# ============================================================================

# Configure readline for file path completion
_readline_available = False
try:
    import readline
    import glob
    _readline_available = True

    def _path_completer(text, state):
        """Complete file paths."""
        # Expand ~ to home directory
        if text.startswith('~'):
            text = os.path.expanduser(text)

        # Add wildcard for glob matching
        pattern = text + '*'
        matches = glob.glob(pattern)

        # Add trailing slash to directories
        matches = [m + '/' if os.path.isdir(m) else m for m in matches]

        # Return match at index 'state'
        if state < len(matches):
            return matches[state]
        return None

    # Configure readline
    readline.set_completer(_path_completer)
    readline.set_completer_delims(' \t\n;')

    # Check if libedit (macOS) or GNU readline
    if 'libedit' in readline.__doc__:
        # macOS libedit
        readline.parse_and_bind('bind ^I rl_complete')
    else:
        # GNU readline
        readline.parse_and_bind('tab: complete')

except (ImportError, Exception):
    pass


# Unicode icons for CLI
class Icons:
    """Unicode icons for terminal output."""
    SHIELD = "🛡️ "
    CHECK = "✓"
    CROSS = "✗"
    ARROW = "→"
    BULLET = "●"
    SEARCH = "🔍"
    FOLDER = "📁"
    FILE = "📄"
    GEAR = "⚙️ "
    ROCKET = "🚀"
    WARNING = "⚠️ "
    INFO = "ℹ️ "
    LOCK = "🔒"
    BUG = "🐛"
    CHART = "📊"
    PACKAGE = "📦"
    PROGRESS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def print_banner():
    """Print the MSRA banner."""
    # Get actual pattern count
    try:
        manager = PatternManager()
        manager.load_all()
        pattern_count = manager.stats.get('enabled', 77)
    except Exception:
        pattern_count = 77

    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🛡️  MSRA — Mobile Security Review Assistant                  ║
║                                                              ║
║   Identify vulnerabilities before attackers do               ║
║   ──────────────────────────────────────────────             ║
║   {Icons.BULLET} {pattern_count}+ Security Patterns                              ║
║   {Icons.BULLET} Deep Analysis Engine                               ║
║   {Icons.BULLET} Dynamic Verification                               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_step(step: int, total: int, message: str):
    """Print a step indicator."""
    # Create progress bar
    filled = "█" * step
    empty = "░" * (total - step)
    print(f"\n┌─ Step {step}/{total} {'─' * 40}")
    print(f"│  {Icons.ARROW} {message}")
    print(f"└─ [{filled}{empty}]")


def print_success(message: str):
    """Print a success message."""
    print(f"   {Icons.CHECK} {message}")


def print_error(message: str):
    """Print an error message."""
    print(f"   {Icons.CROSS} {message}")


def print_info(message: str):
    """Print an info message."""
    print(f"   {Icons.INFO} {message}")


def prompt_input(prompt: str, default: str = None, icon: str = None) -> str:
    """Prompt for input with optional default."""
    icon_str = f"{icon} " if icon else ""
    if default:
        display = f"   {icon_str}{prompt} [{default}]: "
    else:
        display = f"   {icon_str}{prompt}: "

    try:
        value = input(display).strip()
        return value if value else default
    except (KeyboardInterrupt, EOFError):
        print("")
        sys.exit(0)


def prompt_choice(prompt: str, choices: List[Tuple[str, str]], default: int = 1) -> str:
    """Prompt for a choice from a list."""
    # Icons for different menu options
    menu_icons = {
        "scan": Icons.SEARCH,
        "visualize": Icons.CHART,
        "both": Icons.ROCKET,
        "patterns": Icons.GEAR,
        "update": Icons.PACKAGE,
        "list": Icons.FILE,
        "stats": Icons.CHART,
        "validate": Icons.CHECK,
        "search": Icons.SEARCH,
        "force": Icons.ROCKET,
        "auto": Icons.GEAR,
        "skip": Icons.ARROW,
        "cancel": Icons.CROSS,
    }

    print(f"\n{prompt}")
    print("─" * 50)
    for i, (key, description) in enumerate(choices, 1):
        icon = menu_icons.get(key, Icons.BULLET)
        if i == default:
            print(f"  ▸ {i}. {icon} {description}")
        else:
            print(f"    {i}. {icon} {description}")

    while True:
        try:
            choice = input(f"\nEnter choice [{default}]: ").strip()
            if not choice:
                return choices[default - 1][0]
            idx = int(choice)
            if 1 <= idx <= len(choices):
                return choices[idx - 1][0]
            print(f"Please enter a number between 1 and {len(choices)}")
        except ValueError:
            print("Please enter a valid number")
        except (KeyboardInterrupt, EOFError):
            print("")
            sys.exit(0)


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    """Prompt for yes/no with default."""
    default_str = "Y/n" if default else "y/N"
    try:
        response = input(f"   {prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        return response in ('y', 'yes', 'true', '1')
    except (KeyboardInterrupt, EOFError):
        print("")
        sys.exit(0)


def prompt_file(prompt: str, must_exist: bool = True, extensions: list = None) -> str:
    """Prompt for a file path with validation.

    Args:
        prompt: The prompt text to display
        must_exist: Whether the file must exist
        extensions: List of valid extensions (e.g., ['.apk', '.apkm'])
    """
    print(f"   {Icons.FOLDER} Tab completion enabled for paths")
    while True:
        path = prompt_input(prompt, icon=Icons.FILE)
        if not path:
            print_error("Please enter a path")
            continue

        path = os.path.expanduser(path)
        path = os.path.abspath(path)

        if must_exist and not os.path.exists(path):
            print_error(f"File not found: {path}")
            continue

        if extensions:
            if not any(path.lower().endswith(ext.lower()) for ext in extensions):
                ext_list = ', '.join(extensions)
                print_error(f"File must have one of these extensions: {ext_list}")
                continue

        return path


def interactive_mode() -> int:
    """Run interactive mode for APK analysis."""
    print_banner()

    # Step 1: Select operation mode
    print(f"""
┌──────────────────────────────────────────────────────────────┐
│  {Icons.GEAR} Select Operation                                      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Analysis Pipeline (Recommended Order):                      │
│  ─────────────────────────────────────                       │
│  1. Threat Intel  →  2. Static  →  3. Dynamic                │
│                                                              │
│  Standalone:                                                 │
│  ───────────                                                 │
│  4. Visualization (App structure diagrams)                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
""")

    operation = prompt_choice("Select operation:", [
        ("pipeline", "Full Pipeline - Threat Intel → Static → Dynamic (Recommended)"),
        ("threat_intel", "Threat Intelligence - Update vulnerability patterns"),
        ("static", "Static Analysis - Scan APK for vulnerabilities"),
        ("dynamic", "Dynamic Analysis - Test vulnerabilities on device"),
        ("visualize", "Visualization - Generate app structure diagrams"),
        ("patterns", "Pattern Management - List/validate patterns"),
    ])

    if operation == "patterns":
        return cmd_patterns_interactive()

    if operation == "threat_intel":
        return cmd_update_interactive()

    if operation == "visualize":
        return interactive_visualize()

    if operation == "dynamic":
        return interactive_dynamic()

    if operation == "static":
        return interactive_static()

    if operation == "pipeline":
        return interactive_full_pipeline()

    return 0


def interactive_static() -> int:
    """Interactive static analysis."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {Icons.SEARCH} Static Analysis                                      ║
║  ────────────────────────────────────────────────────────    ║
║  Scan APK for vulnerabilities using 77+ security patterns    ║
╚══════════════════════════════════════════════════════════════╝
""")

    # APK file
    print(f"   {Icons.FILE} APK Selection")
    apk_path = prompt_file("Enter path to APK file", must_exist=True, extensions=[".apk", ".apkm", ".xapk"])
    print_success(f"APK: {os.path.basename(apk_path)}")

    # Threat intel update
    print(f"\n   {Icons.PACKAGE} Threat Intelligence")
    update_mode = prompt_choice("Update patterns before scan?", [
        ("auto", "Auto - Update if older than 24 hours (Recommended)"),
        ("skip", "Skip - Use existing patterns"),
        ("force", "Force - Always fetch latest"),
    ])

    # Options
    keep_decompiled = prompt_yes_no("Keep decompiled sources?", default=False)

    # Build args
    class Args:
        pass

    args = Args()
    args.apk = apk_path
    args.out = None
    args.jadx_path = None
    args.adb_path = "adb"
    args.patterns_dir = None
    args.keep_decompiled = keep_decompiled
    args.no_update = (update_mode == "skip")
    args.force_update = (update_mode == "force")
    args.quiet_update = False

    print(f"\n{Icons.ROCKET} Starting static analysis...")
    return cmd_scan(args)


def interactive_dynamic() -> int:
    """Interactive dynamic analysis."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {Icons.BUG} Dynamic Analysis                                        ║
║  ────────────────────────────────────────────────────────    ║
║  Test vulnerabilities on a real device/emulator              ║
╚══════════════════════════════════════════════════════════════╝
""")

    # Check for devices first
    controller = GenymotionController()
    devices = controller.list_devices()

    if not devices:
        print_error("No devices found!")
        print_info("Start Genymotion or connect an Android device via ADB")
        return 1

    print(f"\n   {Icons.CHECK} Found {len(devices)} device(s):")
    for d in devices:
        dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
        print(f"      • {d.model} ({d.serial}) - {dtype}")

    # Ask for input method
    print(f"\n   {Icons.GEAR} Test Configuration")
    input_mode = prompt_choice("What do you want to test?", [
        ("package", "Installed app - Test app already on device"),
        ("apk", "APK file - Install and test APK"),
        ("findings", "Static findings - Load findings from previous scan"),
    ])

    package_name = None
    apk_path = None
    static_findings = None

    if input_mode == "package":
        package_name = prompt_input("Enter package name (e.g., com.example.app)")
        if not package_name:
            print_error("Package name is required")
            return 1

    elif input_mode == "apk":
        apk_path = prompt_file("Enter path to APK file", must_exist=True, extensions=[".apk", ".apkm", ".xapk"])

    elif input_mode == "findings":
        # Look for recent scan reports
        reports_base = Path(__file__).parent.parent / "reports"
        if reports_base.exists():
            subdirs = sorted([d for d in reports_base.iterdir() if d.is_dir()],
                           key=lambda d: d.stat().st_mtime, reverse=True)
            if subdirs:
                print(f"\n   Recent scans:")
                choices = []
                for i, d in enumerate(subdirs[:5]):
                    report_file = d / "report.html"
                    if report_file.exists():
                        choices.append((str(d), d.name))
                        print(f"      {i+1}. {d.name}")

                if choices:
                    report_dir = prompt_input("Enter package name from above (or path to report dir)")
                    # Find matching directory
                    for path, name in choices:
                        if name == report_dir or path == report_dir:
                            # Load findings from JSON if available
                            json_report = Path(path) / "findings.json"
                            if json_report.exists():
                                with open(json_report) as f:
                                    static_findings = json.load(f)
                            package_name = name
                            break

        if not package_name:
            print_error("No previous scan found. Run static analysis first.")
            return 1

    # Select device if multiple
    device_serial = None
    if len(devices) > 1:
        print(f"\n   {Icons.GEAR} Select device:")
        device_choices = [(d.serial, f"{d.model} ({d.serial})") for d in devices]
        device_serial = prompt_choice("Choose device:", device_choices)

    # Output directory
    out_dir = _get_reports_dir(package_name) if package_name else "dynamic_report"

    # Build args
    class Args:
        pass

    args = Args()
    args.apk = apk_path
    args.package = package_name
    args.out = out_dir
    args.device = device_serial
    args.adb_path = "adb"
    args.jadx_path = None
    args.skip_static = (input_mode == "package" or input_mode == "findings")
    args.timeout = 300
    args.list_devices = False

    print(f"\n{Icons.ROCKET} Starting dynamic analysis...")
    return cmd_dynamic(args)


def interactive_visualize() -> int:
    """Interactive visualization."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {Icons.CHART} Visualization                                         ║
║  ────────────────────────────────────────────────────────    ║
║  Generate interactive diagrams of app structure              ║
╚══════════════════════════════════════════════════════════════╝
""")

    # APK file
    apk_path = prompt_file("Enter path to APK file", must_exist=True, extensions=[".apk", ".apkm", ".xapk"])
    print_success(f"APK: {os.path.basename(apk_path)}")

    keep_decompiled = prompt_yes_no("Keep decompiled sources?", default=False)

    # Build args
    class Args:
        pass

    args = Args()
    args.apk = apk_path
    args.out = None
    args.jadx_path = None
    args.keep_decompiled = keep_decompiled
    args.no_components = False
    args.no_calls = False
    args.no_dataflow = False
    args.no_hierarchy = False

    print(f"\n{Icons.ROCKET} Generating visualization...")
    result = cmd_visualize(args)

    if result == 0:
        # Offer to open
        reports_base = Path(__file__).parent.parent / "reports"
        if reports_base.exists():
            subdirs = sorted([d for d in reports_base.iterdir() if d.is_dir()],
                           key=lambda d: d.stat().st_mtime, reverse=True)
            if subdirs:
                viz_file = subdirs[0] / "visualization.html"
                if viz_file.exists() and prompt_yes_no("Open visualization in browser?", default=True):
                    _open_file(str(viz_file))

    return result


def interactive_full_pipeline() -> int:
    """Run full analysis pipeline: Threat Intel → Static → Dynamic."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {Icons.ROCKET} Full Analysis Pipeline                               ║
║  ────────────────────────────────────────────────────────    ║
║                                                              ║
║  Step 1: Update Threat Intelligence                          ║
║       ↓                                                      ║
║  Step 2: Static Analysis (Scan APK)                          ║
║       ↓                                                      ║
║  Step 3: Dynamic Analysis (Test on Device)                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

    # APK file
    print(f"   {Icons.FILE} APK Selection")
    apk_path = prompt_file("Enter path to APK file", must_exist=True, extensions=[".apk", ".apkm", ".xapk"])
    print_success(f"APK: {os.path.basename(apk_path)}")

    # Check for devices
    print(f"\n   {Icons.GEAR} Checking for devices...")
    controller = GenymotionController()
    devices = controller.list_devices()

    has_device = len(devices) > 0
    if has_device:
        print_success(f"Found {len(devices)} device(s) for dynamic analysis")
        for d in devices:
            dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
            print(f"      • {d.model} ({d.serial}) - {dtype}")
    else:
        print_info("No devices found - will skip dynamic analysis")
        print_info("Start Genymotion or connect a device to enable dynamic testing")

    # Confirm
    print(f"""
   ┌──────────────────────────────────────────────────────────┐
   │  {Icons.GEAR} Pipeline Configuration                            │
   ├──────────────────────────────────────────────────────────┤
   │  {Icons.FILE} APK:             {os.path.basename(apk_path):<35} │
   │  {Icons.PACKAGE} Threat Intel:    Will update                         │
   │  {Icons.SEARCH} Static Analysis: Enabled                             │
   │  {Icons.BUG} Dynamic Analysis: {'Enabled' if has_device else 'Skipped (no device)':<30} │
   └──────────────────────────────────────────────────────────┘
""")

    if not prompt_yes_no(f"{Icons.ROCKET} Start full pipeline?", default=True):
        print_info("Pipeline cancelled")
        return 0

    # ═══════════════════════════════════════════════════════════
    # STEP 1: Threat Intelligence
    # ═══════════════════════════════════════════════════════════
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  STEP 1/3: Threat Intelligence Update                        ║
╚══════════════════════════════════════════════════════════════╝
""")

    # Ask about custom sources
    from .crawler.sources import SourcesManager
    sources_mgr = SourcesManager()
    custom_sources = sources_mgr.get_custom_sources()

    print(f"   {Icons.PACKAGE} Current sources: 14 built-in blogs + HackerOne")
    if custom_sources:
        print(f"   {Icons.CHECK} Custom sources: {len(custom_sources)}")
        for src in custom_sources:
            print(f"      • {src.name}")

    if prompt_yes_no(f"Add custom threat intelligence source?", default=False):
        print(f"\n   {Icons.INFO} Enter a security blog URL to add as a source")
        print(f"   {Icons.INFO} Example: https://blog.example.com/security")
        source_url = prompt_input("Source URL (or press Enter to skip)")

        if source_url:
            source_name = prompt_input("Source name (optional, will auto-detect)")
            try:
                if source_name:
                    new_source = sources_mgr.add_source(name=source_name, url=source_url)
                else:
                    # Auto-detect name from URL
                    from urllib.parse import urlparse
                    parsed = urlparse(source_url)
                    auto_name = parsed.netloc.replace('www.', '').split('.')[0].title()
                    new_source = sources_mgr.add_source(name=auto_name, url=source_url)

                print_success(f"Added source: {new_source.name}")
                print(f"      URL: {new_source.url}")
            except ValueError as e:
                print_error(f"Could not add source: {e}")

    config = UpdateConfig()
    updater = ThreatIntelUpdater(config)
    updater.update(force=False, quiet=False)

    # ═══════════════════════════════════════════════════════════
    # STEP 2: Static Analysis
    # ═══════════════════════════════════════════════════════════
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  STEP 2/3: Static Analysis                                   ║
╚══════════════════════════════════════════════════════════════╝
""")

    class Args:
        pass

    args = Args()
    args.apk = apk_path
    args.out = None
    args.jadx_path = None
    args.adb_path = "adb"
    args.patterns_dir = None
    args.keep_decompiled = True  # Keep for dynamic analysis
    args.no_update = True  # Already updated
    args.force_update = False
    args.quiet_update = True

    result = cmd_scan(args)
    if result != 0:
        print_error("Static analysis failed")
        return result

    # Find the report directory
    reports_base = Path(__file__).parent.parent / "reports"
    report_dir = None
    package_name = None
    if reports_base.exists():
        subdirs = sorted([d for d in reports_base.iterdir() if d.is_dir()],
                        key=lambda d: d.stat().st_mtime, reverse=True)
        if subdirs:
            report_dir = subdirs[0]
            package_name = report_dir.name

    # ═══════════════════════════════════════════════════════════
    # STEP 3: Dynamic Analysis
    # ═══════════════════════════════════════════════════════════
    if has_device and package_name:
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  STEP 3/3: Dynamic Analysis                                  ║
╚══════════════════════════════════════════════════════════════╝
""")

        # Select device if multiple
        device_serial = None
        if len(devices) > 1:
            device_choices = [(d.serial, f"{d.model} ({d.serial})") for d in devices]
            device_serial = prompt_choice("Choose device:", device_choices)

        args = Args()
        args.apk = apk_path
        args.package = package_name
        args.out = str(report_dir)
        args.device = device_serial
        args.adb_path = "adb"
        args.jadx_path = None
        args.skip_static = True  # Already did static analysis
        args.timeout = 300
        args.list_devices = False

        result = cmd_dynamic(args)
        if result != 0:
            print_info("Dynamic analysis encountered issues (results may be partial)")

    # ═══════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {Icons.CHECK} Pipeline Complete!                                    ║
╚══════════════════════════════════════════════════════════════╝
""")

    if report_dir:
        print(f"   {Icons.FOLDER} Reports saved to: {report_dir}")
        print(f"   ───────────────────────────────────────────")

        report_html = report_dir / "report.html"
        dynamic_html = report_dir / "dynamic_report.html"

        if report_html.exists():
            print(f"   {Icons.FILE} Static Analysis:  report.html")
        if dynamic_html.exists():
            print(f"   {Icons.FILE} Dynamic Analysis: dynamic_report.html")

        # Offer to open
        print()
        if prompt_yes_no("Open reports in browser?", default=True):
            if report_html.exists():
                _open_file(str(report_html))
            if dynamic_html.exists():
                _open_file(str(dynamic_html))

    return 0


def cmd_patterns_interactive() -> int:
    """Interactive pattern management."""
    print_step(1, 1, "Pattern Management")

    action = prompt_choice("Select action:", [
        ("list", "List all patterns"),
        ("stats", "Show pattern statistics"),
        ("validate", "Validate all patterns"),
        ("search", "Search patterns"),
    ])

    manager = PatternManager()
    manager.load_all()

    if action == "list":
        print(f"\nLoaded Patterns:\n")
        print(f"{'ID':<35} {'Title':<40} {'Severity':<10}")
        print("-" * 90)
        for p in manager.get_patterns(enabled_only=True):
            title = p.title[:38] + ".." if len(p.title) > 40 else p.title
            print(f"{p.id:<35} {title:<40} {p.severity.value:<10}")

        stats = manager.stats
        print(f"\nTotal: {stats['total']} | Enabled: {stats['enabled']}")

    elif action == "stats":
        stats = manager.stats
        print(f"\nPattern Statistics")
        print("=" * 40)
        print(f"Total patterns: {stats['total']}")
        print(f"Enabled: {stats['enabled']}")
        print(f"\nBy Severity:")
        for sev, count in sorted(stats['by_severity'].items()):
            print(f"  {sev}: {count}")
        print(f"\nBy Category:")
        for cat, count in sorted(stats['by_category'].items()):
            print(f"  {cat}: {count}")

    elif action == "validate":
        issues = manager.validate_all()
        if not issues:
            print_success("All patterns are valid!")
        else:
            print_error(f"Found issues in {len(issues)} patterns:")
            for pattern_id, pattern_issues in issues.items():
                print(f"\n  {pattern_id}:")
                for issue in pattern_issues:
                    print(f"    - {issue}")

    elif action == "search":
        query = prompt_input("Search query")
        results = manager.search_patterns(query)
        if results:
            print(f"\nFound {len(results)} patterns:\n")
            for p in results:
                print(f"  {p.id}: {p.title}")
        else:
            print_info("No patterns found matching query")

    return 0


def cmd_update_interactive() -> int:
    """Interactive threat intel update."""
    print_step(1, 1, "Threat Intelligence Update")

    config = UpdateConfig()
    updater = ThreatIntelUpdater(config)

    # Show current status
    stats = updater.get_stats()
    print(f"\nCurrent Status:")
    print(f"  Last update: {stats['last_update'] or 'Never'}")
    print(f"  Patterns pending review: {stats['pending_patterns']}")

    action = prompt_choice("\nSelect action:", [
        ("update", "Update now (skip if recent)"),
        ("force", "Force update"),
        ("cancel", "Cancel"),
    ])

    if action == "cancel":
        return 0

    print(f"\nUpdating threat intelligence...\n")
    result = updater.update(force=(action == "force"))

    if result.success:
        print_success("Update completed successfully")
    else:
        print_error("Update completed with errors")
        for error in result.errors:
            print(f"  - {error}")

    return 0


def _open_file(path: str):
    """Open a file with the default application."""
    import platform
    try:
        if platform.system() == "Darwin":
            subprocess.run(["open", path], check=False)
        elif platform.system() == "Windows":
            os.startfile(path)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        pass


def _find_jadx(jadx_path: Optional[str]) -> str:
    """Locate jadx executable."""
    if jadx_path:
        return jadx_path
    for candidate in ("jadx", "jadx-cli"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    # Common macOS Jadx GUI install path
    mac_gui = "/Applications/jadx-gui.app/Contents/Resources/jadx/bin/jadx"
    if os.path.exists(mac_gui):
        return mac_gui
    return ""


def _ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def _get_reports_dir(package_name: str = None) -> str:
    """
    Get the reports directory under the project root.
    Structure: APKAnalyzer/reports/<package_name>/
    """
    # Get the project root (parent of apk_analyzer package)
    project_root = Path(__file__).parent.parent
    reports_dir = project_root / "reports"

    if package_name:
        # Sanitize package name for filesystem
        safe_name = package_name.replace("/", "_").replace("\\", "_")
        reports_dir = reports_dir / safe_name

    _ensure_dir(str(reports_dir))
    return str(reports_dir)


def _extract_split_apk_bundle(bundle_path: str, out_dir: str) -> Optional[str]:
    """
    Extract split APK bundles (APKM, XAPK, or similar formats).

    Supports:
    - APKM: APKMirror format (contains base.apk + split_config.*.apk)
    - XAPK: APKPure format (contains manifest.json + APKs in various layouts)
    - Generic split bundles: Any ZIP containing base.apk or *.apk files

    Returns path to merged/extracted APK, or None if not a split bundle.
    """
    import zipfile
    import json

    try:
        with zipfile.ZipFile(bundle_path, 'r') as zf:
            names = zf.namelist()
            apk_files = [n for n in names if n.endswith('.apk')]

            if not apk_files:
                return None

            # Detect bundle type
            bundle_type = None
            base_apk = None

            # Check for XAPK format (has manifest.json)
            if 'manifest.json' in names:
                bundle_type = "XAPK"
                try:
                    manifest_data = json.loads(zf.read('manifest.json'))
                    print(f"[+] {Icons.PACKAGE} Detected XAPK bundle")
                    if 'package_name' in manifest_data:
                        print(f"    Package: {manifest_data['package_name']}")
                    if 'version_name' in manifest_data:
                        print(f"    Version: {manifest_data['version_name']}")
                except:
                    pass

            # Check for APKM format (base.apk + split_config.*.apk)
            elif 'base.apk' in apk_files:
                if any('split_config.' in n or 'split_' in n for n in apk_files):
                    bundle_type = "APKM"
                    print(f"[+] {Icons.PACKAGE} Detected APKM bundle (split APKs)")
                else:
                    bundle_type = "APKM"
                    print(f"[+] {Icons.PACKAGE} Detected APK bundle")

            if not bundle_type:
                # Check if it's just a ZIP with APKs
                if len(apk_files) >= 1:
                    bundle_type = "Generic"
                    print(f"[+] {Icons.PACKAGE} Detected APK archive ({len(apk_files)} APK files)")
                else:
                    return None

            # List split APKs
            split_apks = [n for n in apk_files if n != 'base.apk' and 'split' in n.lower()]
            if split_apks:
                print(f"[+] {Icons.ARROW} Split APKs found:")
                for split in split_apks[:5]:  # Show first 5
                    print(f"    - {split}")
                if len(split_apks) > 5:
                    print(f"    ... and {len(split_apks) - 5} more")

            # Find the base APK to extract
            if 'base.apk' in apk_files:
                base_apk = 'base.apk'
            else:
                # Look for main APK in common locations
                for candidate in apk_files:
                    # Skip split configs
                    if 'split_config' not in candidate and 'split_' not in candidate.lower():
                        base_apk = candidate
                        break
                # If no suitable APK found, use the first one
                if not base_apk:
                    base_apk = apk_files[0]

            print(f"[+] {Icons.ARROW} Extracting {base_apk}...")

            # Extract base APK
            extracted_path = os.path.join(out_dir, 'base.apk')
            with zf.open(base_apk) as src, open(extracted_path, 'wb') as dst:
                dst.write(src.read())

            print(f"[+] {Icons.CHECK} Extracted: {extracted_path}")

            # Also extract all APKs for comprehensive analysis
            apks_dir = os.path.join(out_dir, 'split_apks')
            os.makedirs(apks_dir, exist_ok=True)

            for apk in apk_files:
                if apk != base_apk:
                    apk_out = os.path.join(apks_dir, os.path.basename(apk))
                    with zf.open(apk) as src, open(apk_out, 'wb') as dst:
                        dst.write(src.read())

            if len(apk_files) > 1:
                print(f"[+] {Icons.FOLDER} All APKs extracted to: {apks_dir}")

            return extracted_path

    except zipfile.BadZipFile:
        print(f"[!] {Icons.WARNING} File is not a valid ZIP archive")
    except Exception as e:
        print(f"[!] {Icons.WARNING} Error extracting bundle: {e}")

    return None


# Alias for backward compatibility
_extract_apkm_bundle = _extract_split_apk_bundle


def _decompile(apk_path: str, out_dir: str, jadx_path: str) -> None:
    """Decompile APK using jadx."""
    cmd = [jadx_path, "-d", out_dir, apk_path]
    subprocess.run(cmd, check=False)


def _update_threat_intel(force: bool = False, quiet: bool = False) -> None:
    """Update threat intelligence feeds by crawling security sources."""
    config = UpdateConfig()
    updater = ThreatIntelUpdater(config)
    updater.update(force=force, quiet=quiet)


def cmd_scan(args) -> int:
    """Scan APK for vulnerabilities."""
    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}", file=sys.stderr)
        return 2

    jadx_path = _find_jadx(args.jadx_path)
    if not jadx_path:
        print("jadx not found. Install jadx-cli or pass --jadx-path.", file=sys.stderr)
        return 2

    # Update threat intelligence before scanning
    if not args.no_update:
        _update_threat_intel(force=args.force_update, quiet=args.quiet_update)

    # Use temp directory for initial decompilation
    import tempfile
    temp_dir = tempfile.mkdtemp(prefix="apk_analyzer_")

    # Check if this is an APKM bundle and extract base.apk if so
    extracted_apk = _extract_apkm_bundle(apk_path, temp_dir)
    if extracted_apk:
        apk_path = extracted_apk

    decompiled_dir = os.path.join(temp_dir, "decompiled")
    _ensure_dir(decompiled_dir)

    print("[+] Decompiling APK with jadx...")
    _decompile(apk_path, decompiled_dir, jadx_path)

    manifest_guess = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    sources_guess = os.path.join(decompiled_dir, "sources")
    if not os.path.exists(manifest_guess) and not os.path.exists(sources_guess):
        print("[!] Decompiled output appears empty. Jadx may have failed.", file=sys.stderr)

    # Configure pattern loading
    pattern_config = PatternConfig()
    if args.patterns_dir:
        pattern_config.custom_patterns_dir = Path(args.patterns_dir)

    print("[+] Scanning decompiled sources...")
    scanner = Scanner(decompiled_dir, adb_path=args.adb_path, pattern_config=pattern_config)
    findings = scanner.scan()
    source_file_count = sum(1 for _ in iter_source_files(decompiled_dir))

    # Get package name and create reports directory
    package_name = scanner.package_name or "unknown"
    out_dir = _get_reports_dir(package_name)

    print(f"[+] Pattern stats: {scanner.pattern_stats.get('total', 0)} patterns loaded")
    print(f"[+] Source files scanned: {source_file_count}")
    print(f"[+] Vulnerabilities found: {len(findings)}")

    # Generate reports in the package-specific reports directory
    # Build findings data for JSON export
    findings_json_path = os.path.join(out_dir, "findings.json")
    findings_data = []
    for f in findings:
        # Extract category from fid (e.g., "webview-js-interface" -> "webview")
        category = f.fid.split('-')[0] if f.fid and '-' in f.fid else 'other'
        # Also check extra dict for category
        if hasattr(f, 'extra') and f.extra and 'category' in f.extra:
            category = f.extra['category']

        # Get extra data including reachability info
        extra_data = f.extra if hasattr(f, 'extra') and f.extra else {}

        finding_dict = {
            'fid': f.fid,
            'title': f.title,
            'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            'category': category,
            'description': f.description,
            'attack_path': f.attack_path if hasattr(f, 'attack_path') else '',
            'evidence': {
                'file_path': f.evidence.file_path if f.evidence else None,
                'line_number': f.evidence.line_number if f.evidence else None,
                'matched_text': getattr(f.evidence, 'matched_text', None) if f.evidence else None,
                'snippet': getattr(f.evidence, 'snippet', None) if f.evidence else None,
            } if f.evidence else None,
            'adb_commands': f.adb_commands if hasattr(f, 'adb_commands') else [],
            'deep_links': extra_data.get('deep_links', []),
            'attack_scenarios': extra_data.get('attack_scenarios', []),
            'entry_points': extra_data.get('entry_points', []),
            # Attack vector details (how attackers can exploit this)
            'attack_vector': extra_data.get('attack_vector'),
            'attack_description': extra_data.get('attack_description'),
            'attack_prerequisites': extra_data.get('attack_prerequisites', []),
            'attack_steps': extra_data.get('attack_steps', []),
            'attack_impact': extra_data.get('attack_impact', []),
            'malicious_apk_code': extra_data.get('malicious_apk_code'),
            'deep_link_exploit': extra_data.get('deep_link_exploit'),
            'mitigation': extra_data.get('mitigation'),
            'extra': extra_data,
        }
        findings_data.append(finding_dict)

    scan_time = datetime.now().isoformat()

    # Build JSON data (used for both report embedding and dynamic analysis)
    json_data = {
        'package': package_name,
        'apk': os.path.basename(apk_path),
        'scan_time': scan_time,
        'total_findings': len(findings),
        'findings': findings_data
    }

    # Save JSON for dynamic analysis pipeline
    with open(findings_json_path, 'w') as jf:
        json.dump(json_data, jf, indent=2)

    # Generate HTML report with embedded JSON
    html_path = os.path.join(out_dir, "report.html")
    metadata = {
        "title": "MSRA Security Report",
        "package": package_name,
        "apk": os.path.basename(apk_path),
        "scan_time": scan_time,
        "patterns_loaded": scanner.pattern_stats.get('total', 0),
    }
    generate_html_report(findings, html_path, metadata, json_data=json_data)
    print(f"[+] {Icons.FILE} Report: {html_path}")

    pdf_path = os.path.join(out_dir, "report.pdf")
    pdf_rendered = render_pdf_from_html(html_path, pdf_path)
    if pdf_rendered:
        print(f"[+] {Icons.FILE} PDF report: {pdf_path}")
    else:
        print("[!] PDF renderer not available. Install wkhtmltopdf or weasyprint.")

    # Copy decompiled sources to reports dir if requested
    if args.keep_decompiled:
        dest_decompiled = os.path.join(out_dir, "decompiled")
        if os.path.exists(dest_decompiled):
            shutil.rmtree(dest_decompiled)
        shutil.copytree(decompiled_dir, dest_decompiled)
        print(f"[+] {Icons.FOLDER} Decompiled sources: {dest_decompiled}")

    # Cleanup temp directory
    shutil.rmtree(temp_dir, ignore_errors=True)

    return 0


def cmd_patterns_list(args) -> int:
    """List loaded patterns."""
    manager = PatternManager()
    manager.load_all()

    if args.format == "json":
        patterns = []
        for p in manager.get_patterns(enabled_only=not args.all):
            patterns.append({
                "id": p.id,
                "title": p.title,
                "severity": p.severity.value,
                "category": p.category.value,
                "enabled": p.enabled,
            })
        print(json.dumps(patterns, indent=2))
    else:
        print(f"\n{'ID':<35} {'Title':<40} {'Severity':<10} {'Category':<25}")
        print("-" * 115)
        for p in manager.get_patterns(enabled_only=not args.all):
            title = p.title[:38] + ".." if len(p.title) > 40 else p.title
            print(f"{p.id:<35} {title:<40} {p.severity.value:<10} {p.category.value:<25}")

    stats = manager.stats
    print(f"\nTotal: {stats['total']} | Enabled: {stats['enabled']}")
    print(f"By severity: {stats['by_severity']}")

    return 0


def cmd_patterns_show(args) -> int:
    """Show pattern details."""
    manager = PatternManager()
    manager.load_all()

    pattern = manager.get_pattern(args.pattern_id)
    if not pattern:
        print(f"Pattern not found: {args.pattern_id}", file=sys.stderr)
        return 1

    print(f"\nPattern: {pattern.id}")
    print(f"Title: {pattern.title}")
    print(f"Severity: {pattern.severity.value}")
    print(f"Category: {pattern.category.value}")
    print(f"Enabled: {pattern.enabled}")
    print(f"\nDescription:\n{pattern.description}")
    print(f"\nAttack Path:\n{pattern.attack_path}")
    if pattern.remediation:
        print(f"\nRemediation:\n{pattern.remediation}")
    if pattern.metadata.cwe:
        print(f"\nCWE: {', '.join(pattern.metadata.cwe)}")
    if pattern.metadata.cve:
        print(f"CVE: {', '.join(pattern.metadata.cve)}")
    if pattern.metadata.references:
        print(f"\nReferences:")
        for ref in pattern.metadata.references:
            print(f"  - {ref}")

    return 0


def cmd_patterns_validate(args) -> int:
    """Validate all patterns."""
    manager = PatternManager()
    manager.load_all()

    issues = manager.validate_all()
    if not issues:
        print("All patterns valid.")
        return 0

    print(f"Found issues in {len(issues)} patterns:\n")
    for pattern_id, pattern_issues in issues.items():
        print(f"{pattern_id}:")
        for issue in pattern_issues:
            print(f"  - {issue}")

    return 1


def cmd_patterns_stats(args) -> int:
    """Show pattern statistics."""
    manager = PatternManager()
    manager.load_all()

    stats = manager.stats
    print("\nPattern Statistics")
    print("=" * 40)
    print(f"Total patterns: {stats['total']}")
    print(f"Enabled: {stats['enabled']}")
    print(f"\nBy severity:")
    for sev, count in sorted(stats['by_severity'].items()):
        print(f"  {sev}: {count}")
    print(f"\nBy category:")
    for cat, count in sorted(stats['by_category'].items()):
        print(f"  {cat}: {count}")
    print(f"\nSources loaded: {stats['sources_loaded']}")

    return 0


def cmd_crawl_hackerone(args) -> int:
    """Crawl HackerOne for Android vulnerability reports."""
    from .crawler import HackerOneCrawler, HackerOneConfig, PatternExtractor

    config = HackerOneConfig(
        api_username=os.environ.get("HACKERONE_USERNAME"),
        api_token=os.environ.get("HACKERONE_TOKEN"),
        min_severity=args.min_severity,
    )

    crawler = HackerOneCrawler(config)

    since = None
    if args.since:
        since = datetime.fromisoformat(args.since)

    print(f"[+] Fetching HackerOne disclosed reports (max: {args.max})...")
    reports = list(crawler.fetch_reports(since=since, max_reports=args.max))
    print(f"[+] Found {len(reports)} Android-related reports")

    if args.extract:
        extractor = PatternExtractor()
        extracted_count = 0

        for report in reports:
            result = extractor.extract_from_hackerone(report)
            if result.success:
                for pattern in result.patterns:
                    extractor.save_pattern(pattern, pending_review=True)
                    extracted_count += 1
                print(f"  Extracted {len(result.patterns)} patterns from: {report.title[:50]}")

        print(f"\n[+] Total patterns extracted: {extracted_count}")
        print(f"[+] Patterns saved to pending_review folder for approval")
    else:
        for report in reports[:10]:  # Show first 10
            print(f"  [{report.severity.upper()}] {report.title[:60]}")
            print(f"    URL: {report.report_url}")

    return 0


def cmd_crawl_blogs(args) -> int:
    """Crawl security blogs for Android vulnerability writeups."""
    from .crawler import BlogCrawler, PatternExtractor

    crawler = BlogCrawler()

    if args.sources:
        print(f"[+] Crawling specified sources: {args.sources}")
    else:
        print(f"[+] Crawling all configured sources: {crawler.list_sources()}")

    articles = []
    if args.sources:
        for source in args.sources:
            articles.extend(crawler.crawl_source(source, max_articles=args.max))
    else:
        articles = list(crawler.crawl_all_sources(max_articles_per_source=args.max))

    print(f"[+] Found {len(articles)} Android-related articles")

    if args.extract:
        extractor = PatternExtractor()
        extracted_count = 0

        for article in articles:
            result = extractor.extract_from_blog(article)
            if result.success:
                for pattern in result.patterns:
                    extractor.save_pattern(pattern, pending_review=True)
                    extracted_count += 1
                print(f"  Extracted {len(result.patterns)} patterns from: {article.title[:50]}")

        print(f"\n[+] Total patterns extracted: {extracted_count}")
        print(f"[+] Patterns saved to pending_review folder for approval")
    else:
        for article in articles[:10]:
            print(f"  {article.title[:60]}")
            print(f"    Source: {article.source} | URL: {article.url}")

    return 0


def cmd_crawl_review(args) -> int:
    """Review and approve/reject extracted patterns."""
    from .crawler import PatternExtractor

    extractor = PatternExtractor()

    if args.list:
        pending = extractor.list_pending()
        if not pending:
            print("No patterns pending review.")
            return 0

        print(f"\nPatterns pending review ({len(pending)}):\n")
        print(f"{'ID':<40} {'Severity':<10} {'Title':<40}")
        print("-" * 95)
        for p in pending:
            title = p['title'][:38] + ".." if len(p['title']) > 40 else p['title']
            print(f"{p['id']:<40} {p['severity']:<10} {title:<40}")
        return 0

    if args.approve:
        for pattern_id in args.approve:
            if extractor.approve_pattern(pattern_id):
                print(f"Approved: {pattern_id}")
            else:
                print(f"Failed to approve: {pattern_id}", file=sys.stderr)

    if args.reject:
        for pattern_id in args.reject:
            if extractor.reject_pattern(pattern_id):
                print(f"Rejected: {pattern_id}")
            else:
                print(f"Failed to reject: {pattern_id}", file=sys.stderr)

    return 0


def cmd_dynamic(args) -> int:
    """Run dynamic analysis on APK using Genymotion/emulator."""
    # Check if enhanced mode is requested
    if getattr(args, 'enhanced', False):
        return cmd_dynamic_enhanced(args)

    # Initialize controller
    controller = GenymotionController(adb_path=args.adb_path)

    # Handle list-devices first (doesn't need APK)
    if args.list_devices:
        devices = controller.list_devices()
        if not devices:
            print("No devices found. Start Genymotion or connect a device.")
            return 1
        print(f"\nAvailable devices ({len(devices)}):\n")
        print(f"{'Serial':<25} {'Model':<20} {'State':<10} {'Type':<15} {'API':<5}")
        print("-" * 80)
        for d in devices:
            dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
            api = str(d.api_level) if d.api_level else "?"
            print(f"{d.serial:<25} {d.model:<20} {d.state:<10} {dtype:<15} {api:<5}")
        return 0

    # APK or package name is required
    if not args.apk and not args.package:
        print("APK path or --package name is required for dynamic analysis.", file=sys.stderr)
        print("Use --list-devices to see available devices.", file=sys.stderr)
        print("\nExamples:", file=sys.stderr)
        print("  apk-analyzer dynamic app.apk --out report", file=sys.stderr)
        print("  apk-analyzer dynamic --package com.example.app --out report", file=sys.stderr)
        return 2

    apk_path = None
    original_apk_path = None  # Keep track of original for display
    temp_extract_dir = None   # Track temp dir for cleanup

    if args.apk:
        apk_path = os.path.abspath(args.apk)
        original_apk_path = apk_path
        if not os.path.exists(apk_path):
            print(f"APK not found: {apk_path}", file=sys.stderr)
            return 2

        # Handle split APK bundles (.apkm, .xapk)
        if apk_path.lower().endswith(('.apkm', '.xapk')):
            temp_extract_dir = tempfile.mkdtemp(prefix="apk_dynamic_")
            extracted_apk = _extract_split_apk_bundle(apk_path, temp_extract_dir)
            if extracted_apk:
                # For installation, we'll use the original bundle path
                # The install_apk method in genymotion.py handles extraction
                print(f"[+] Bundle will be installed with all split APKs")
            else:
                print(f"[!] Failed to process APK bundle", file=sys.stderr)
                if temp_extract_dir:
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                return 2

    out_dir = os.path.abspath(args.out)
    _ensure_dir(out_dir)

    # Connect to device
    print("[+] Connecting to device/emulator...")
    if not controller.connect(serial=args.device):
        return 1

    # Run static scan first if not skipped and we have an APK
    findings = []
    static_findings_loaded = False

    # Try to load existing static findings if skipping static analysis
    if args.skip_static:
        findings_json_path = os.path.join(out_dir, "findings.json")
        if os.path.exists(findings_json_path):
            print("\n[+] Loading static analysis findings...")
            try:
                with open(findings_json_path, 'r') as f:
                    findings_data = json.load(f)
                findings = findings_data.get('findings', [])
                print(f"[+] Loaded {len(findings)} findings from static analysis")

                # Filter to testable findings
                testable_categories = ['webview', 'intent', 'provider', 'component', 'network', 'crypto', 'storage']
                testable_findings = [
                    f for f in findings
                    if any(cat in str(f.get('category', '')).lower() for cat in testable_categories)
                    or str(f.get('severity', '')).lower() in ['critical', 'high']
                ]
                print(f"[+] {len(testable_findings)} findings are testable dynamically")
                findings = testable_findings
                static_findings_loaded = True
            except Exception as e:
                print(f"[!] Could not load findings: {e}")
        else:
            print(f"\n[+] No findings.json found at {findings_json_path}")
            print("[+] Will discover attack surface from installed app")

    if apk_path and not args.skip_static:
        jadx_path = _find_jadx(args.jadx_path)
        if not jadx_path:
            print("[!] jadx not found. Skipping static analysis.")
        else:
            print("\n[+] Running static analysis first...")
            decompiled_dir = os.path.join(out_dir, "decompiled")
            _ensure_dir(decompiled_dir)

            # For APKM/XAPK bundles, extract base.apk for decompilation
            decompile_apk_path = apk_path
            if apk_path.lower().endswith(('.apkm', '.xapk')):
                if temp_extract_dir:
                    base_apk = os.path.join(temp_extract_dir, 'base.apk')
                    if os.path.exists(base_apk):
                        decompile_apk_path = base_apk
                        print(f"[+] Using extracted base.apk for decompilation")

            print("[+] Decompiling APK with jadx...")
            _decompile(decompile_apk_path, decompiled_dir, jadx_path)

            pattern_config = PatternConfig()
            scanner = Scanner(decompiled_dir, adb_path=args.adb_path, pattern_config=pattern_config)
            findings = scanner.scan()
            print(f"[+] Static analysis found {len(findings)} vulnerabilities")

            # Filter to testable findings
            testable_categories = ['webview', 'intent', 'provider', 'component', 'network']
            testable_findings = [
                f for f in findings
                if any(cat in f.get('category', '').lower() for cat in testable_categories)
                or f.get('severity') in ['critical', 'high']
            ]
            print(f"[+] {len(testable_findings)} findings are testable dynamically")
            findings = testable_findings
            static_findings_loaded = True
    elif not apk_path and not static_findings_loaded:
        print("\n[+] No APK provided - testing already installed app")
        print("[+] Will discover attack surface from installed app")

    # Get package name
    package_name = args.package
    if not package_name and apk_path:
        print("\n[+] Extracting package name from APK...")
        try:
            # For APKM/XAPK bundles, use extracted base.apk
            aapt_apk_path = apk_path
            if apk_path.lower().endswith(('.apkm', '.xapk')) and temp_extract_dir:
                base_apk = os.path.join(temp_extract_dir, 'base.apk')
                if os.path.exists(base_apk):
                    aapt_apk_path = base_apk

            # Use aapt if available for accurate parsing
            result = subprocess.run(
                ["aapt", "dump", "badging", aapt_apk_path],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                if line.startswith("package:"):
                    # Parse: package: name='com.example' versionCode='1' ...
                    for part in line.split():
                        if part.startswith("name='"):
                            package_name = part.split("'")[1]
                            break
                    break
            if not package_name:
                print("[!] Could not extract package name. Specify with --package.")
                return 1
        except Exception as e:
            print(f"[!] Could not extract package name: {e}")
            print("[!] Specify with --package.")
            return 1

    if not package_name:
        print("[!] Package name is required. Use --package.")
        return 1

    print(f"[+] Package: {package_name}")

    # Initialize dynamic test executor
    executor = DynamicTestExecutor(
        controller=controller,
        package_name=package_name,
        apk_path=apk_path,
        findings=findings,
        output_dir=out_dir
    )

    # Setup (install app, start monitoring)
    print("\n[+] Setting up dynamic analysis...")
    if apk_path:
        display_name = os.path.basename(original_apk_path or apk_path)
        print(f"[+] Will install APK: {display_name}")
    if not executor.setup():
        print("[!] Setup failed")
        return 1

    # Discover attack surface if no static findings
    if not findings:
        print("\n[+] No static findings - discovering attack surface from installed app...")
        findings = executor.discover_attack_surface()
        if not findings:
            print("[!] No testable components found. App may not be installed.")
            return 1
        print(f"[+] Found {len(findings)} testable components")
    else:
        # We have static findings - show what we're testing
        print(f"\n[+] Using {len(findings)} findings from static analysis")
        print("[+] Static findings will guide dynamic testing:")
        categories = {}
        for f in findings:
            cat = str(f.get('category', 'other')).lower()
            categories[cat] = categories.get(cat, 0) + 1
        for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:5]:
            print(f"    • {cat}: {count} findings")

    # Run tests
    print("\n[+] Running dynamic tests...")
    print("-" * 60)
    results = executor.run_tests(findings=findings, timeout=args.timeout)

    # Print results summary
    print("\n" + "=" * 60)
    print("DYNAMIC ANALYSIS RESULTS")
    print("=" * 60)

    confirmed = [r for r in results if r.test_status == 'confirmed']
    likely = [r for r in results if r.test_status == 'likely_vulnerable']
    inconclusive = [r for r in results if r.test_status == 'inconclusive']
    not_vuln = [r for r in results if r.test_status == 'not_vulnerable']

    print(f"\nConfirmed vulnerabilities: {len(confirmed)}")
    for r in confirmed:
        print(f"  [{r.severity.upper()}] {r.finding_title}")
        if r.evidence and r.evidence.get('command'):
            print(f"    PoC: {r.evidence.get('command', '')[:80]}")

    print(f"\nLikely vulnerable: {len(likely)}")
    for r in likely:
        print(f"  [{r.severity.upper()}] {r.finding_title}")

    print(f"\nInconclusive: {len(inconclusive)}")
    print(f"Not vulnerable: {len(not_vuln)}")

    # Check for crashes/sensitive data leaks
    report = executor.get_report()
    if report.crashes_detected:
        print(f"\n[!] CRASHES DETECTED: {report.crashes_detected}")
    if report.sensitive_data_leaks:
        print(f"\n[!] SENSITIVE DATA LEAKS: {report.sensitive_data_leaks}")

    # Export JSON report
    report_path = os.path.join(out_dir, "dynamic_report.json")
    executor.export_report(report_path)
    print(f"\n[+] JSON report saved: {report_path}")

    # Generate HTML report with PoC evidence
    with open(report_path, 'r') as f:
        report_data = json.load(f)
    html_report_path = os.path.join(out_dir, "dynamic_report.html")
    generate_dynamic_report(report_data, html_report_path)
    print(f"[+] HTML report saved: {html_report_path}")

    # Cleanup
    executor.cleanup()

    # Generate combined HTML report if we have static findings
    if findings and apk_path:
        html_path = os.path.join(out_dir, "combined_report.html")
        metadata = {
            "title": "MSRA - Combined Security Report",
            "package": package_name,
            "apk": os.path.basename(original_apk_path or apk_path) if apk_path else "N/A",
            "scan_time": datetime.now().isoformat(),
            "dynamic_results": {
                "confirmed": len(confirmed),
                "likely": len(likely),
                "inconclusive": len(inconclusive),
                "not_vulnerable": len(not_vuln),
                "crashes": report.crashes_detected,
                "leaks": report.sensitive_data_leaks,
            }
        }
        generate_html_report(findings, html_path, metadata)
        print(f"[+] Combined HTML report: {html_path}")

    # Cleanup temp extraction directory
    if temp_extract_dir and os.path.exists(temp_extract_dir):
        shutil.rmtree(temp_extract_dir, ignore_errors=True)

    return 0


def cmd_dynamic_enhanced(args) -> int:
    """Run enhanced dynamic analysis with Frida, traffic capture, and verification."""
    from .dynamic import (
        DynamicConfig, AnalysisMode, FridaConfig, ProxyConfig,
        create_device, EnhancedDynamicExecutor,
        is_frida_available, is_mitmproxy_available
    )

    # Handle list-devices first
    if getattr(args, 'list_devices', False):
        controller = GenymotionController(adb_path=args.adb_path)
        devices = controller.list_devices()
        if not devices:
            print("No devices found. Start Genymotion or connect a device.")
            return 1
        print(f"\nAvailable devices ({len(devices)}):\n")
        print(f"{'Serial':<25} {'Model':<20} {'State':<10} {'Type':<15} {'API':<5}")
        print("-" * 80)
        for d in devices:
            dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
            api = str(d.api_level) if d.api_level else "?"
            print(f"{d.serial:<25} {d.model:<20} {d.state:<10} {dtype:<15} {api:<5}")
        return 0

    # Validate args
    if not args.apk and not args.package:
        print("APK path or --package name is required for dynamic analysis.", file=sys.stderr)
        return 2

    apk_path = None
    if args.apk:
        apk_path = os.path.abspath(args.apk)
        if not os.path.exists(apk_path):
            print(f"APK not found: {apk_path}", file=sys.stderr)
            return 2

    out_dir = os.path.abspath(args.out)
    _ensure_dir(out_dir)

    # Parse analysis mode
    mode_map = {
        "passive": AnalysisMode.PASSIVE,
        "active": AnalysisMode.ACTIVE,
        "aggressive": AnalysisMode.AGGRESSIVE,
    }
    mode = mode_map.get(args.mode, AnalysisMode.ACTIVE)

    # Create configuration
    config = DynamicConfig(
        mode=mode,
        use_frida=not getattr(args, 'no_frida', False),
        use_proxy=not getattr(args, 'no_traffic', False),
        proxy=ProxyConfig(port=getattr(args, 'proxy_port', 8080)),
    )

    # Show capabilities
    print(f"\n{Icons.GEAR} Enhanced Dynamic Analysis Configuration")
    print("=" * 50)
    print(f"Mode: {mode.value}")
    print(f"Frida: {'Enabled' if config.use_frida and is_frida_available() else 'Disabled'}")
    print(f"Traffic Capture: {'Enabled' if config.use_proxy and is_mitmproxy_available() else 'Disabled'}")
    print(f"Proxy Port: {config.proxy.port}")
    print("=" * 50)

    # Create device
    print(f"\n[+] Connecting to device...")
    from .dynamic import DeviceType
    use_uiautomator = not getattr(args, 'no_ui_automation', False)
    device_type = DeviceType.AUTO if use_uiautomator else DeviceType.ADB
    device = create_device(
        serial=args.device,
        device_type=device_type
    )

    if not device or not device.connect(args.device):
        print("[!] Failed to connect to device")
        return 1

    device_info = device.get_device_info()
    if device_info:
        print(f"[+] Connected: {device_info.model} (API {device_info.api_level})")

    # Create enhanced executor
    print(f"\n[+] Initializing enhanced executor...")
    executor = EnhancedDynamicExecutor(
        device=device,
        config=config,
        output_dir=out_dir,
    )

    # Show capabilities
    caps = executor.get_capabilities()
    print(f"[+] Capabilities:")
    print(f"    Device: {'Connected' if caps['device_connected'] else 'Not connected'}")
    print(f"    Frida: {'Available' if caps['frida_available'] else 'Not available'}")
    print(f"    Traffic Capture: {'Available' if caps['proxy_available'] else 'Not available'}")
    print(f"    UI Automation: {'Available' if caps['ui_automation'] else 'Basic ADB only'}")

    # Check if Frida server is running on device
    if config.use_frida and is_frida_available() and not caps['frida_available']:
        print(f"\n{Icons.WARNING}Frida server not detected on device. To enable Frida:")
        print(f"    1. Download frida-server for your device architecture")
        print(f"    2. Push to device: adb push frida-server /data/local/tmp/")
        print(f"    3. Make executable: adb shell chmod 755 /data/local/tmp/frida-server")
        print(f"    4. Start server: adb shell /data/local/tmp/frida-server &")
        print(f"    Continuing without Frida instrumentation...\n")

    # Get package name
    package_name = args.package
    if not package_name and apk_path:
        # Extract from APK
        try:
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                if line.startswith("package:"):
                    for part in line.split():
                        if part.startswith("name='"):
                            package_name = part.split("'")[1]
                            break
                    break
        except Exception as e:
            print(f"[!] Could not extract package name: {e}")

    if not package_name:
        print("[!] Package name is required. Use --package.")
        return 1

    print(f"[+] Package: {package_name}")

    # Setup - this will launch app and attach Frida
    print(f"\n[+] Setting up for {package_name}...")
    print(f"    Launching app and attaching instrumentation...")
    if not executor.setup(package_name, apk_path):
        print("[!] Setup failed")
        executor.cleanup()
        return 1
    print(f"[+] Setup complete")

    # Load findings
    findings = []
    findings_json_path = os.path.join(out_dir, "findings.json")
    if os.path.exists(findings_json_path):
        print(f"\n[+] Loading static analysis findings...")
        try:
            with open(findings_json_path, 'r') as f:
                findings_data = json.load(f)
            findings = findings_data.get('findings', [])
            print(f"[+] Loaded {len(findings)} findings")
        except Exception as e:
            print(f"[!] Could not load findings: {e}")

    # Run verification
    if findings:
        print(f"\n[+] Verifying {len(findings)} findings...")
        results = executor.verify_findings(findings, timeout=args.timeout)
    else:
        print(f"\n[+] No static findings - running basic analysis...")
        # Create some basic findings from app exploration
        results = []

    # Print summary
    summary = executor.get_summary()
    print("\n" + "=" * 60)
    print(f"{Icons.CHART} ENHANCED DYNAMIC ANALYSIS RESULTS")
    print("=" * 60)
    print(f"Package: {summary['package']}")
    print(f"\nFindings Verified: {summary['total_findings']}")
    print(f"  Confirmed: {summary['verified']} {Icons.CHECK}")
    print(f"  Likely: {summary['likely']}")
    print(f"  Not Vulnerable: {summary['not_vulnerable']}")
    print(f"  Inconclusive: {summary['inconclusive']}")
    print(f"  Errors: {summary['errors']}")

    # Show traffic analysis if available
    if summary.get('traffic'):
        traffic = summary['traffic']
        print(f"\n{Icons.SEARCH} Traffic Analysis:")
        print(f"  Total Flows: {traffic['total_flows']}")
        print(f"  Data Leak Alerts: {len(traffic['leak_alerts'])}")
        if traffic['leak_alerts']:
            print(f"  Leak Types:")
            leak_types = {}
            for alert in traffic['leak_alerts']:
                cat = alert.get('category', 'unknown')
                leak_types[cat] = leak_types.get(cat, 0) + 1
            for lt, count in sorted(leak_types.items(), key=lambda x: -x[1]):
                print(f"    - {lt}: {count}")

    print("=" * 60)

    # Export results
    results_path = os.path.join(out_dir, "enhanced_results.json")
    executor.export_results(results_path)
    print(f"\n[+] Results saved: {results_path}")

    # Generate HTML report
    html_report_path = os.path.join(out_dir, "enhanced_report.html")
    with open(results_path, 'r') as f:
        report_data = json.load(f)
    generate_dynamic_report(report_data, html_report_path)
    print(f"[+] HTML report: {html_report_path}")

    # Cleanup
    executor.cleanup()

    return 0


def cmd_dynamic_list_devices(args) -> int:
    """List available devices/emulators."""
    controller = GenymotionController(adb_path=args.adb_path)
    devices = controller.list_devices()

    if not devices:
        print("No devices found. Start Genymotion or connect a device.")
        return 1

    print(f"\nAvailable devices ({len(devices)}):\n")
    print(f"{'Serial':<25} {'Model':<20} {'State':<10} {'Type':<15} {'API':<5}")
    print("-" * 80)
    for d in devices:
        dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
        api = str(d.api_level) if d.api_level else "?"
        print(f"{d.serial:<25} {d.model:<20} {d.state:<10} {dtype:<15} {api:<5}")

    return 0


def cmd_update(args) -> int:
    """Update threat intelligence feeds by crawling security sources."""
    from .crawler.blogs import BLOG_SOURCES

    # List sources option
    if args.list_sources:
        print("\n" + "=" * 60)
        print("THREAT INTELLIGENCE SOURCES")
        print("=" * 60)

        print("\n[HackerOne]")
        print("  Bug bounty reports with Android vulnerabilities")
        print("  URL: https://hackerone.com/hacktivity")

        print(f"\n[Security Blogs] ({len(BLOG_SOURCES)} sources)")
        for source in BLOG_SOURCES:
            print(f"  • {source.name}")
            print(f"    {source.base_url}")

        print("\n" + "=" * 60)
        print(f"Total: {len(BLOG_SOURCES) + 1} sources configured")
        print("=" * 60)
        return 0

    config = UpdateConfig(
        max_hackerone_reports=args.max_reports,
        max_blog_articles_per_source=args.max_articles,
        enable_hackerone=not args.no_hackerone,
        enable_blogs=not args.no_blogs,
    )

    updater = ThreatIntelUpdater(config)

    if args.stats:
        stats = updater.get_stats()
        print("\nThreat Intelligence Status")
        print("=" * 40)
        print(f"Last update: {stats['last_update'] or 'Never'}")
        print(f"Total updates: {stats['update_count']}")
        print(f"Patterns pending review: {stats['pending_patterns']}")
        print(f"\nConfigured sources: {len(BLOG_SOURCES) + 1}")
        print("  Run 'apk-analyzer update --list-sources' to see all sources")
        return 0

    result = updater.update(force=args.force)

    if result.errors:
        print(f"\n[!] Errors encountered: {len(result.errors)}")
        for error in result.errors:
            print(f"    - {error}")

    return 0 if result.success else 1


def cmd_sources(args) -> int:
    """Manage threat intelligence sources."""
    from .crawler.sources import SourcesManager, PatternApprovalManager
    from .crawler.blogs import BLOG_SOURCES

    sources_mgr = SourcesManager()
    approval_mgr = PatternApprovalManager()

    # Add source
    if args.add:
        try:
            # Parse name and URL from add argument
            if '=' in args.add:
                name, url = args.add.split('=', 1)
            else:
                url = args.add
                # Extract name from URL
                from urllib.parse import urlparse
                parsed = urlparse(url)
                name = parsed.netloc.replace('www.', '').split('.')[0].title()

            # Get optional keywords
            keywords = args.keywords.split(',') if args.keywords else None

            source = sources_mgr.add_source(
                name=name,
                url=url,
                feed_url=args.feed_url,
                keywords=keywords
            )
            print(f"[+] Added source: {source.name}")
            print(f"    URL: {source.url}")
            print(f"    Feed: {source.feed_url or 'Auto-detect'}")
            print(f"    Keywords: {', '.join(source.keywords)}")
            return 0
        except ValueError as e:
            print(f"[!] Error: {e}")
            return 1

    # Remove source
    if args.remove:
        if sources_mgr.remove_source(args.remove):
            print(f"[+] Removed source: {args.remove}")
            return 0
        else:
            print(f"[!] Source not found: {args.remove}")
            return 1

    # List sources
    if args.list or (not args.pending and not args.approve and not args.approve_all):
        print("\n" + "=" * 60)
        print("THREAT INTELLIGENCE SOURCES")
        print("=" * 60)

        print(f"\n[Built-in Sources] ({len(BLOG_SOURCES)} sources)")
        for source in BLOG_SOURCES:
            print(f"  • {source.name}")
            print(f"    {source.base_url}")

        custom = sources_mgr.get_custom_sources()
        if custom:
            print(f"\n[Custom Sources] ({len(custom)} sources)")
            for source in custom:
                status = "✓" if source.enabled else "○"
                print(f"  {status} {source.name}")
                print(f"    {source.url}")
                if source.patterns_extracted > 0:
                    print(f"    Patterns extracted: {source.patterns_extracted}")

        print("\n" + "-" * 60)
        stats = approval_mgr.get_stats()
        print(f"Patterns: {stats['approved']} approved, {stats['pending']} pending review")
        print("=" * 60)
        return 0

    # Show pending patterns
    if args.pending:
        pending = approval_mgr.get_pending_patterns()
        if not pending:
            print("[+] No patterns pending review")
            return 0

        print("\n" + "=" * 60)
        print(f"PATTERNS PENDING REVIEW ({len(pending)})")
        print("=" * 60)

        for i, pattern in enumerate(pending, 1):
            severity = pattern.get('severity', 'unknown')
            title = pattern.get('title', 'Unknown')
            source_url = pattern.get('metadata', {}).get('source', {}).get('url', 'Unknown')
            pattern_id = pattern.get('id', 'unknown')

            print(f"\n[{i}] {title}")
            print(f"    ID: {pattern_id}")
            print(f"    Severity: {severity}")
            print(f"    Source: {source_url}")
            if pattern.get('description'):
                desc = pattern['description'][:100] + '...' if len(pattern.get('description', '')) > 100 else pattern.get('description', '')
                print(f"    Description: {desc}")

        print("\n" + "-" * 60)
        print("To approve: apk-analyzer sources --approve <pattern-id>")
        print("To approve all: apk-analyzer sources --approve-all")
        print("=" * 60)
        return 0

    # Approve pattern
    if args.approve:
        if approval_mgr.approve_pattern(args.approve):
            print(f"[+] Approved pattern: {args.approve}")
            print("[+] Pattern will be used in future scans")
            return 0
        else:
            print(f"[!] Pattern not found: {args.approve}")
            return 1

    # Approve all patterns
    if args.approve_all:
        count = approval_mgr.approve_all()
        print(f"[+] Approved {count} patterns")
        print("[+] Patterns will be used in future scans")
        return 0

    return 0


def cmd_visualize(args) -> int:
    """Visualize application structure and functionality."""
    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}", file=sys.stderr)
        return 2

    jadx_path = _find_jadx(args.jadx_path)
    if not jadx_path:
        print("jadx not found. Install jadx-cli or pass --jadx-path.", file=sys.stderr)
        return 2

    # Use temp directory for decompilation
    import tempfile
    temp_dir = tempfile.mkdtemp(prefix="apk_analyzer_viz_")

    # Check if this is an APKM bundle and extract base.apk if so
    extracted_apk = _extract_apkm_bundle(apk_path, temp_dir)
    if extracted_apk:
        apk_path = extracted_apk

    decompiled_dir = os.path.join(temp_dir, "decompiled")
    _ensure_dir(decompiled_dir)

    # Decompile
    print("[+] Decompiling APK with jadx...")
    _decompile(apk_path, decompiled_dir, jadx_path)

    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print("[!] Decompilation failed - manifest not found", file=sys.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return 1

    # Analyze application structure
    print("[+] Analyzing application structure...")
    analyzer = AppStructureAnalyzer(decompiled_dir)
    structure = analyzer.analyze()

    # Get package name and create reports directory
    package_name = structure.package_name or "unknown"
    out_dir = _get_reports_dir(package_name)

    print(f"[+] Found {len(structure.classes)} classes")
    print(f"[+] Found {len(structure.components)} components")
    print(f"[+] Found {len(structure.entry_points)} entry points")

    # Configure visualization
    viz_config = VisualizationConfig(
        include_component_graph=not args.no_components,
        include_call_graph=not args.no_calls,
        include_data_flow=not args.no_dataflow,
        include_class_hierarchy=not args.no_hierarchy,
        include_entry_points=True,
        include_statistics=True,
    )

    # Render visualization
    print("[+] Generating visualization...")
    renderer = VisualizationRenderer(structure, viz_config)

    html_path = os.path.join(out_dir, "visualization.html")
    renderer.render_html(html_path)
    print(f"[+] {Icons.CHART} Visualization saved: {html_path}")

    # Print summary
    print("\n" + "=" * 50)
    print("APPLICATION STRUCTURE SUMMARY")
    print("=" * 50)
    print(f"Package: {structure.package_name}")
    print(f"Classes: {len(structure.classes)}")
    print(f"  - Activities: {sum(1 for c in structure.classes.values() if c.is_activity)}")
    print(f"  - Services: {sum(1 for c in structure.classes.values() if c.is_service)}")
    print(f"  - Receivers: {sum(1 for c in structure.classes.values() if c.is_receiver)}")
    print(f"  - Providers: {sum(1 for c in structure.classes.values() if c.is_provider)}")
    print(f"  - Fragments: {sum(1 for c in structure.classes.values() if c.is_fragment)}")
    print(f"Components (manifest): {len(structure.components)}")
    print(f"  - Exported: {sum(1 for c in structure.components.values() if c.exported)}")
    print(f"Entry Points: {len(structure.entry_points)}")
    print(f"Permissions: {len(structure.permissions)}")
    print(f"Data Flows: {len(structure.data_flows)}")

    # List entry points
    if structure.entry_points:
        print("\nEntry Points:")
        for entry in structure.entry_points[:10]:
            print(f"  - {entry}")
        if len(structure.entry_points) > 10:
            print(f"  ... and {len(structure.entry_points) - 10} more")

    # Copy decompiled sources to reports dir if requested
    if args.keep_decompiled:
        dest_decompiled = os.path.join(out_dir, "decompiled")
        if os.path.exists(dest_decompiled):
            shutil.rmtree(dest_decompiled)
        shutil.copytree(decompiled_dir, dest_decompiled)
        print(f"[+] {Icons.FOLDER} Decompiled sources: {dest_decompiled}")

    # Cleanup temp directory
    shutil.rmtree(temp_dir, ignore_errors=True)

    return 0


def main() -> int:
    """Main CLI entry point."""
    # If no arguments, run interactive mode
    if len(sys.argv) == 1:
        return interactive_mode()

    # Check for explicit interactive flag
    if len(sys.argv) == 2 and sys.argv[1] in ('-i', '--interactive'):
        return interactive_mode()

    parser = argparse.ArgumentParser(
        description="MSRA - Mobile Security Review Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode (recommended for first-time users):
    apk-analyzer                          # Launch interactive wizard
    apk-analyzer --interactive            # Same as above

  Scan an APK (auto-updates threat intel):
    apk-analyzer scan app.apk --out report
    apk-analyzer scan app.apk --no-update      # Skip update
    apk-analyzer scan app.apk --force-update   # Force fresh update

  Visualize application structure:
    apk-analyzer visualize app.apk             # Generate visualization
    apk-analyzer visualize app.apk --out viz   # Custom output dir

  Update threat intelligence:
    apk-analyzer update                        # Update if needed
    apk-analyzer update --force                # Force update
    apk-analyzer update --stats                # Show update status

  List patterns:
    apk-analyzer patterns list

  Dynamic analysis:
    apk-analyzer dynamic --list-devices
    apk-analyzer dynamic app.apk --out dynamic_report
    apk-analyzer dynamic app.apk --device emulator-5554 --timeout 600
    apk-analyzer dynamic --package com.example.app --out report  # Test installed app

  Crawl HackerOne:
    apk-analyzer crawl hackerone --max 50 --extract

  Review extracted patterns:
    apk-analyzer crawl review --list
    apk-analyzer crawl review --approve h1-123-webview
        """
    )

    # Add interactive flag
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Launch interactive wizard')

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan APK for vulnerabilities")
    scan_parser.add_argument("apk", help="Path to APK file")
    scan_parser.add_argument("--out", default="report", help="Output directory")
    scan_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    scan_parser.add_argument("--adb-path", default="adb", help="Path to adb")
    scan_parser.add_argument("--patterns-dir", help="Custom patterns directory")
    scan_parser.add_argument("--keep-decompiled", action="store_true", help="Keep decompiled output")
    scan_parser.add_argument("--no-update", action="store_true", help="Skip threat intel update")
    scan_parser.add_argument("--force-update", action="store_true", help="Force threat intel update even if recent")
    scan_parser.add_argument("--quiet-update", action="store_true", help="Suppress threat intel update output")
    scan_parser.set_defaults(func=cmd_scan)

    # Patterns commands
    patterns_parser = subparsers.add_parser("patterns", help="Pattern management")
    patterns_sub = patterns_parser.add_subparsers(dest="patterns_cmd")

    list_parser = patterns_sub.add_parser("list", help="List patterns")
    list_parser.add_argument("--format", choices=["table", "json"], default="table")
    list_parser.add_argument("--all", action="store_true", help="Include disabled patterns")
    list_parser.set_defaults(func=cmd_patterns_list)

    show_parser = patterns_sub.add_parser("show", help="Show pattern details")
    show_parser.add_argument("pattern_id", help="Pattern ID")
    show_parser.set_defaults(func=cmd_patterns_show)

    validate_parser = patterns_sub.add_parser("validate", help="Validate patterns")
    validate_parser.set_defaults(func=cmd_patterns_validate)

    stats_parser = patterns_sub.add_parser("stats", help="Show pattern statistics")
    stats_parser.set_defaults(func=cmd_patterns_stats)

    # Crawl commands
    crawl_parser = subparsers.add_parser("crawl", help="Crawl security sources")
    crawl_sub = crawl_parser.add_subparsers(dest="crawl_cmd")

    h1_parser = crawl_sub.add_parser("hackerone", help="Crawl HackerOne")
    h1_parser.add_argument("--since", help="Fetch reports since date (YYYY-MM-DD)")
    h1_parser.add_argument("--max", type=int, default=50, help="Max reports")
    h1_parser.add_argument("--min-severity", default="low", choices=["none", "low", "medium", "high", "critical"])
    h1_parser.add_argument("--extract", action="store_true", help="Extract patterns")
    h1_parser.set_defaults(func=cmd_crawl_hackerone)

    blog_parser = crawl_sub.add_parser("blogs", help="Crawl security blogs")
    blog_parser.add_argument("--sources", nargs="+", help="Specific sources")
    blog_parser.add_argument("--max", type=int, default=20, help="Max articles per source")
    blog_parser.add_argument("--extract", action="store_true", help="Extract patterns")
    blog_parser.set_defaults(func=cmd_crawl_blogs)

    review_parser = crawl_sub.add_parser("review", help="Review extracted patterns")
    review_parser.add_argument("--list", action="store_true", help="List pending")
    review_parser.add_argument("--approve", nargs="+", help="Approve pattern IDs")
    review_parser.add_argument("--reject", nargs="+", help="Reject pattern IDs")
    review_parser.set_defaults(func=cmd_crawl_review)

    # Dynamic analysis command
    dynamic_parser = subparsers.add_parser("dynamic", help="Dynamic analysis with Genymotion/emulator")
    dynamic_parser.add_argument("apk", nargs="?", help="Path to APK file")
    dynamic_parser.add_argument("--out", default="dynamic_report", help="Output directory")
    dynamic_parser.add_argument("--device", help="Device serial (auto-selects if not specified)")
    dynamic_parser.add_argument("--adb-path", default="adb", help="Path to adb")
    dynamic_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    dynamic_parser.add_argument("--package", help="Package name (auto-detected from APK)")
    dynamic_parser.add_argument("--skip-static", action="store_true", help="Skip static analysis")
    dynamic_parser.add_argument("--timeout", type=int, default=300, help="Test timeout in seconds")
    dynamic_parser.add_argument("--list-devices", action="store_true", help="List available devices")
    # Enhanced dynamic analysis options
    dynamic_parser.add_argument("--enhanced", action="store_true",
                                help="Use enhanced executor with Frida, traffic capture, and verification")
    dynamic_parser.add_argument("--mode", choices=["passive", "active", "aggressive"], default="active",
                                help="Analysis mode: passive (observe), active (test), aggressive (bypass)")
    dynamic_parser.add_argument("--no-frida", action="store_true",
                                help="Disable Frida instrumentation")
    dynamic_parser.add_argument("--no-traffic", action="store_true",
                                help="Disable traffic interception")
    dynamic_parser.add_argument("--no-ui-automation", action="store_true",
                                help="Use basic ADB only (no uiautomator2)")
    dynamic_parser.add_argument("--proxy-port", type=int, default=8080,
                                help="Proxy port for traffic interception")
    dynamic_parser.add_argument("--explore-depth", type=int, default=5,
                                help="UI exploration depth for discovering attack surfaces")
    dynamic_parser.set_defaults(func=cmd_dynamic)

    # Update command
    update_parser = subparsers.add_parser("update", help="Update threat intelligence feeds")
    update_parser.add_argument("--force", action="store_true", help="Force update even if recently updated")
    update_parser.add_argument("--stats", action="store_true", help="Show update statistics")
    update_parser.add_argument("--list-sources", action="store_true", help="List all threat intelligence sources")
    update_parser.add_argument("--max-reports", type=int, default=30, help="Max HackerOne reports to fetch")
    update_parser.add_argument("--max-articles", type=int, default=10, help="Max blog articles per source")
    update_parser.add_argument("--no-hackerone", action="store_true", help="Skip HackerOne feed")
    update_parser.add_argument("--no-blogs", action="store_true", help="Skip security blog feeds")
    update_parser.set_defaults(func=cmd_update)

    # Sources management command
    sources_parser = subparsers.add_parser("sources", help="Manage threat intelligence sources and patterns")
    sources_parser.add_argument("--list", action="store_true", help="List all sources (default)")
    sources_parser.add_argument("--add", metavar="NAME=URL", help="Add custom source (e.g., 'MyBlog=https://blog.example.com')")
    sources_parser.add_argument("--remove", metavar="NAME", help="Remove a custom source")
    sources_parser.add_argument("--feed-url", help="RSS/Atom feed URL for custom source")
    sources_parser.add_argument("--keywords", help="Comma-separated keywords for filtering (default: android,mobile,apk)")
    sources_parser.add_argument("--pending", action="store_true", help="Show patterns pending review")
    sources_parser.add_argument("--approve", metavar="PATTERN_ID", help="Approve a pending pattern")
    sources_parser.add_argument("--approve-all", action="store_true", help="Approve all pending patterns")
    sources_parser.set_defaults(func=cmd_sources)

    # Visualize command
    viz_parser = subparsers.add_parser("visualize", help="Visualize application structure")
    viz_parser.add_argument("apk", help="Path to APK file")
    viz_parser.add_argument("--out", default="visualization", help="Output directory")
    viz_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    viz_parser.add_argument("--keep-decompiled", action="store_true", help="Keep decompiled output")
    viz_parser.add_argument("--no-components", action="store_true", help="Skip component graph")
    viz_parser.add_argument("--no-calls", action="store_true", help="Skip call graph")
    viz_parser.add_argument("--no-dataflow", action="store_true", help="Skip data flow graph")
    viz_parser.add_argument("--no-hierarchy", action="store_true", help="Skip class hierarchy")
    viz_parser.set_defaults(func=cmd_visualize)

    args = parser.parse_args()

    # Handle interactive flag
    if hasattr(args, 'interactive') and args.interactive:
        return interactive_mode()

    # Handle legacy usage (no subcommand, just APK path)
    if args.command is None:
        if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
            # Legacy mode: treat first arg as APK path
            args.apk = sys.argv[1]
            args.out = "report"
            args.jadx_path = None
            args.adb_path = "adb"
            args.patterns_dir = None
            args.keep_decompiled = False
            args.no_update = False
            args.force_update = False
            args.quiet_update = False
            return cmd_scan(args)
        parser.print_help()
        return 1

    if hasattr(args, 'func'):
        return args.func(args)

    # Handle subcommand without action
    if args.command == "patterns" and not args.patterns_cmd:
        patterns_parser.print_help()
        return 1
    if args.command == "crawl" and not args.crawl_cmd:
        crawl_parser.print_help()
        return 1
    if args.command == "dynamic" and not args.apk and not args.list_devices:
        dynamic_parser.print_help()
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
