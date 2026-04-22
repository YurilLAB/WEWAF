import sys

with open('internal/web/assets/index-BEJ7suss.css', 'r', encoding='utf-8') as f:
    css = f.read()

remaining = ['3b82f6', '2563eb', '217 91%', '59 130 246']
for b in remaining:
    count = css.lower().count(b)
    if count:
        print(f'Remaining blue: {b} -> {count} occurrences')

orange = ['f97316', 'ea580c', '249 115 22', '25 95% 53%']
for o in orange:
    count = css.lower().count(o)
    if count:
        print(f'Orange: {o} -> {count} occurrences')

print('Check complete.')
