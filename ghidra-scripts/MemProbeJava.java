import ghidra.app.script.GhidraScript;

public class MemProbeJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        var mem = currentProgram.getMemory();
        var a = toAddr("0x10071878");
        byte[] b = new byte[24];
        if (mem.contains(a) && mem.getBytes(a, b) == 24) {
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            println("bytes: " + sb.toString());
        }
    }
}
