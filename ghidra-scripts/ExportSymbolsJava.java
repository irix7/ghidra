import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;

public class ExportSymbolsJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String path = args[0];
        SymbolTable st = currentProgram.getSymbolTable();
        FileWriter w = new FileWriter(path);
        w.write("kind,name,addr,size\n");
        for (Symbol s : st.getAllSymbols(true)) {
            if (s.isDynamic()) continue;
            w.write("sym," + s.getName() + ",0x" + Long.toHexString(s.getAddress().getOffset()) + ",\n");
        }
        for (Function fn : currentProgram.getFunctionManager().getFunctions(true)) {
            w.write("func," + fn.getName() + ",0x" + Long.toHexString(fn.getEntryPoint().getOffset()) + "," + fn.getBody().getNumAddresses() + "\n");
        }
        w.close();
        println("exported to " + path);
    }
}
