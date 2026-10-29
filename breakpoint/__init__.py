"""BREAKPOINT: executed ground truth for detection engineering."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "ext"
DATA = ROOT / "data"
STP_DCC = EXT / "stp" / "DCC"
SIGMA_RULES = EXT / "sigma" / "rules" / "windows"
CATALOG = STP_DCC / "implementation_catalog_with_attack_components.xlsx"

PILOT_TECHNIQUES = ["T1018", "T1016", "T1057", "T1082", "T1053.005", "T1543.003"]
