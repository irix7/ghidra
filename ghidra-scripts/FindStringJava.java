import ghidra.app.script.GhidraScript;

public class FindStringJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String needle = getScriptArgs()[0];
        byte[] nb = needle.getBytes();
        byte[] all = new byte[(int) currentProgram.getMemory().getSize()];
        currentProgram.getMemory().getBytes(currentProgram.getMemory().getMinAddress(), all);
        int found = 0;
        for (int i = 0; i <= all.length - nb.length && found < 10; i++) {
            boolean ok = true;
            for (int j = 0; j < nb.length; j++) {
                if (all[i + j] != nb[j]) { ok = false; break; }
            }
            if (ok) {
                long va = currentProgram.getImageBase().getOffset() + i;
                println("string at 0x" + Long.toHexString(va));
                found++;
            }
        }
        println("done found=" + found);
    }
}
