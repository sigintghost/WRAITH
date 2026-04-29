# modules/wishlist_agent.py
# WRAITH wishlist intelligence agent
# reads WISHLIST.md, generates implementation workflows
# sig.int.ghost — the system builds itself

import os, json

WISHLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    'WISHLIST.md'
)

def load_wishlist():
    if not os.path.exists(WISHLIST_PATH):
        return "WISHLIST.md not found"
    with open(WISHLIST_PATH) as f:
        return f.read()

def parse_items(content):
    items = []
    current = None
    for line in content.split('\n'):
        if line.startswith('### '):
            if current:
                items.append(current)
            current = {'name': line[4:], 'desc': [], 'status': 'wishlist'}
        elif line.startswith('Status:') and current:
            current['status'] = line.replace('Status:','').strip()
        elif current and line.strip():
            current['desc'].append(line.strip())
    if current:
        items.append(current)
    return items

def run_wishlist_agent():
    print("\n  [WISHLIST] loading backlog...")
    content = load_wishlist()
    items = parse_items(content)
    wishlist = [i for i in items if 'wishlist' in i['status']]
    print(f"  {len(wishlist)} wishlist items found\n")
    for i, item in enumerate(wishlist):
        print(f"  [{i+1}] {item['name']}")
        print(f"      {item['status']}")
    print()
    choice = input("  select item to generate workflow > ").strip()
    try:
        selected = wishlist[int(choice)-1]
        generate_workflow(selected)
    except:
        print("  invalid selection")

def generate_workflow(item):
    try:
        from modules.doxa import load_doxa_key, ask_doxa
        api_key = load_doxa_key()
        prompt = (
            f"You are a Python developer working on WRAITH, "
            f"a passive OT/BAS network intelligence tool. "
            f"Generate a step by step implementation workflow "
            f"for this feature:\n\n"
            f"Feature: {item['name']}\n"
            f"Description: {chr(10).join(item['desc'])}\n\n"
            f"Include: file to create or modify, "
            f"functions needed, integration points, "
            f"testing approach. Be specific and technical."
        )
        print(f"\n  [WISHLIST] generating workflow for: {item['name']}")
        print("  thinking...\n")
        reply, _ = ask_doxa(prompt, api_key, [])
        print(reply)
    except Exception as e:
        print(f"  workflow generation failed: {e}")
