#!/usr/bin/env python3
"""Freeze explicitly selected DEVELOPMENT-only few-shot exemplars."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import HERE,read_csv,write_csv
OUT=HERE/'rescue'
IDS=['paper:Alishahryar1/free-claude-code:34','paper:Donchitos/Claude-Code-Game-Studios:3','paper:abhigyanpatwari/GitNexus:4','paper:AlexsJones/llmfit:18','paper:chenhg5/cc-connect:3','paper:Alishahryar1/free-claude-code:10','paper:AlexsJones/llmfit:4','paper:AlexsJones/llmfit:17','paper:AlexsJones/llmfit:32','paper:czlonkowski/n8n-mcp:2','paper:Donchitos/Claude-Code-Game-Studios:11','paper:AlexsJones/llmfit:27','paper:Donchitos/Claude-Code-Game-Studios:10','paper:Alishahryar1/free-claude-code:31','paper:gastownhall/beads:26','paper:chenhg5/cc-connect:27','paper:ChromeDevTools/chrome-devtools-mcp:4','paper:Alishahryar1/free-claude-code:2']
def main():
 dev={r['statement_id'] for r in read_csv(OUT/'dev_inputs.csv')}
 gold={r['statement_id']:r for r in read_csv(HERE/'paper_labels.csv')}
 assert set(IDS)<=dev
 write_csv(OUT/'examples-r1.csv',[{k:gold[s][k] for k in ['statement_id','repo','text','enforceability','context_required']} for s in IDS])
if __name__=='__main__':main()
