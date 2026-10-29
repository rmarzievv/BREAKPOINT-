"""The submodule evaluator works on rules loaded from outside detection-as-code."""
from pathlib import Path

from breakpoint.evaluate import fires_on_any, load_rule

DAC_RULES = Path(__file__).resolve().parent.parent / "vendor" / "detection-as-code" / "rules"


def test_arp_rule_fires_on_arp_but_not_get_netneighbor():
    rule = load_rule(next(DAC_RULES.rglob("win_proc_arp_cache_discovery.yml")))
    arp = {"EventID": 1, "Image": r"C:\Windows\System32\ARP.EXE", "CommandLine": "arp -a",
           "ParentImage": r"C:\Windows\System32\cmd.exe"}
    # Get-NetNeighbor creates no new process: the only events are inside powershell.exe
    get_netneighbor = {"EventID": 4104, "ScriptBlockText": "Get-NetNeighbor"}
    assert fires_on_any(rule, [arp])
    assert not fires_on_any(rule, [get_netneighbor])
