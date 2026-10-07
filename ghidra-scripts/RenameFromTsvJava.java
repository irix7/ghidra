import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import java.io.BufferedReader;
import java.io.FileReader;

public class RenameFromTsvJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String path = getScriptArgs()[0];
        int renamed = 0, notfound = 0;
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String[] parts = line.split("\t");
            long addr = Long.parseLong(parts[0].substring(2), 16);
            String name = parts[1];
            Address a = toAddr(addr);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(a);
            if (fn == null) {
                notfound++;
                continue;
            }
            if (!fn.getName().equals(name)) {
                fn.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED);
                renamed++;
            }
        }
        br.close();
        println("renamed " + renamed + ", not found " + notfound);
    }
}
