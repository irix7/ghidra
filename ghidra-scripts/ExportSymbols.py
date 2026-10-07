# @category SGI
# Export symbol table + functions to CSV for the SGI IRIX RE effort.
import csv

out_path = getScriptArgs()[0]
st = currentProgram.getSymbolTable()
fm = currentProgram.getFunctionManager()

with open(out_path, 'w') as f:
    w = csv.writer(f)
    w.writerow(['kind', 'name', 'addr', 'size'])
    seen = set()
    for s in st.getAllSymbols(True):
        if s.isDynamic():
            continue
        addr = s.getAddress().getOffset()
        key = (s.getName(), addr)
        if key in seen:
            continue
        seen.add(key)
        w.writerow(['sym', s.getName(), '0x%x' % addr, ''])
    for fn in fm.getFunctions(True):
        w.writerow(['func', fn.getName(), '0x%x' % fn.getEntryPoint().getOffset(), fn.getBody().getNumAddresses()])

print('exported to', out_path)
