"""Static UX regression checks for the current local prototype; no dependencies."""
from pathlib import Path
from html.parser import HTMLParser
import sys

class Audit(HTMLParser):
    def __init__(self):
        super().__init__(); self.errors=[]; self.ids=set(); self.autofocus=[]
    def handle_starttag(self, tag, attrs):
        values=dict(attrs); name=values.get('id',tag)
        if 'id' in values:
            if name in self.ids: self.errors.append(f'Duplicate id: {name}')
            self.ids.add(name)
        if tag in ('h1','h2','h3','p') or values.get('role')=='heading':
            if 'autofocus' in values or 'tabindex' in values: self.errors.append(f'Static text receives focus: {name}')
        if 'autofocus' in values:
            if tag not in ('button','input','textarea','select'): self.errors.append(f'Autofocus on non-control: {name}')
            self.autofocus.append(name)

root=Path(__file__).resolve().parents[1]
prototype=root/'research/prototype-next/app/index.html'
if not prototype.exists():
    print('Local prototype is absent; browser UX checks remain required.');sys.exit(0)
audit=Audit();audit.feed(prototype.read_text())
focus_file=prototype.parent/'focus.css'
if not focus_file.exists() or 'focus.css' not in prototype.read_text(): audit.errors.append('Shared focus stylesheet is missing or not loaded.')
for stylesheet in prototype.parent.glob('*.css'):
    if stylesheet.name!='focus.css' and ':focus' in stylesheet.read_text(): audit.errors.append(f'Focus rules outside the shared owner: {stylesheet.name}')

expected={'connect-close','pair-reject','unlock-code','delete-cancel'}
if set(audit.autofocus)!=expected: audit.errors.append('Dialog autofocus policy changed; review all dialogs and update the documented policy.')
if audit.errors:
    print('\n'.join(audit.errors));sys.exit(1)
print('Static UX checks passed. Browser scenarios in docs/ux-checks.md are still required.')
