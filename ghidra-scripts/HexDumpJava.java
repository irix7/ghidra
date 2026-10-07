import ghidra.app.script.GhidraScript;

public class HexDumpJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long addr = Long.parseLong(args[0], 16);
        int len = Integer.parseInt(args[1]);
        byte[] b = new byte[len];
        if (currentProgram.getMemory().getBytes(toAddr(addr), b) != len) {
            println("read failed");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02x ", b[i]));
            if (i % 16 == 15) sb.append("\n");
        }
        println(sb.toString());
    }
}
