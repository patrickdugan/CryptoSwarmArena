"""CLI for the sealed Mulder/Scully CASE-764-SYNTH-01 benchmark."""
import argparse
import json
from pathlib import Path
from .forensic_casebook import evaluate


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    report=evaluate()
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print(json.dumps({k:report[k] for k in ('suite','cases','contract_passes','totals')},indent=2))
    return 0 if report['contract_passes']==report['cases'] else 1

if __name__=='__main__':
    raise SystemExit(main())
