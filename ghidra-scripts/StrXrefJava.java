import ghidra.app.script.GhidraScript;

public class StrXrefJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        byte[] nb = "does not contain all".getBytes();
        var mem = currentProgram.getMemory();
        for (var block : mem.getBlocks()) {
            long size = block.getSize();
            byte[] buf = new byte[(int) Math.min(size, 1 << 20)];
            int read = block.getBytes(block.getStart(), buf);
            for (int i = 0; i <= read - nb.length; i++) {
                boolean ok = true;
                for (int j = 0; j < nb.length; j++) if (buf[i+j] != nb[j]) { ok = false; break; }
                if (ok) {
                    var va = block.getStart().add(i);
                    println("STRING at " + va);
                    var refs = currentProgram.getReferenceManager().getReferencesTo(va);
                    int n = 0;
                    for (var r : refs) { println("  xref from " + r.getFromAddress()); n++; }
                    println("  xrefs: " + n);
                }
            }
        }
    }
}
