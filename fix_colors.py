import sys

with open('internal/web/assets/index-BEJ7suss.css', 'r', encoding='utf-8') as f:
    css = f.read()

replacements = [
    ('#3b82f6', '#f97316'),
    ('#2563eb', '#ea580c'),
    ('rgb(59 130 246', 'rgb(249 115 22'),
    ('rgb(37 99 235', 'rgb(234 88 12'),
    ('217 91% 60%', '25 95% 53%'),
]

for old, new in replacements:
    before = css.count(old)
    css = css.replace(old, new)
    after = css.count(old)
    print(f'Replaced {old}: {before} -> {after} remaining', file=sys.stderr)

with open('internal/web/assets/index-BEJ7suss.css', 'w', encoding='utf-8') as f:
    f.write(css)

print('Done.', file=sys.stderr)
