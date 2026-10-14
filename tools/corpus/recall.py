import json, re, subprocess, os, collections, sys

# image-shaped only: a Bitnami namespace not preceded by '/', '.' or a word char (excludes /opt/bitnami/..., github.com/bitnami/...)
pat = r'((?<![/\w.])bitnami(legacy|secure)?/[a-z0-9][a-z0-9._-]+|charts\.bitnami\.com/bitnami|bitnamicharts|allowInsecureImages:\s*true)'
show = sys.argv[1] if len(sys.argv) > 1 else 'other'
tot = collections.Counter(); hit = collections.Counter(); misses = []
for d in sorted(x for x in os.listdir('.') if os.path.isdir(x)):
    out = subprocess.run(['rg', '-P', '-n', '-o', '-i', '--no-heading', pat, '-g', '*.y*ml', '-g', 'Dockerfile*',
                          '-g', '!*.md', '-g', '!**/README*', d], capture_output=True, text=True).stdout
    r = json.load(open(d + '.json'))
    found = {(f['location']['path'].replace(chr(92), '/'), f['location']['line']) for f in r['findings']}
    for line in out.splitlines():
        m = re.match(r'(.+?):(\d+):(.*)', line)
        p, ln = m.group(1).replace(chr(92), '/'), int(m.group(2))
        rel = p[len(d) + 1:]
        src = open(p, encoding='utf-8', errors='replace').read().splitlines()[ln - 1].strip()
        if src.startswith('#'):
            continue
        kind = 'templates' if '/templates/' in rel else 'other'
        tot[kind] += 1
        if (rel, ln) in found:
            hit[kind] += 1
        else:
            misses.append((kind, d, rel, ln, src[:110]))
for k in tot:
    print(k, hit[k], '/', tot[k])
for m in [x for x in misses if x[0] == show][:45]:
    print(*m[1:])
