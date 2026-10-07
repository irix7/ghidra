import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.FileWriter;

public class DumpFunctionsJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args[0];
        new File(outDir).mkdirs();
        DecompInterface di = new DecompInterface();
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) {
            println("open failed");
            return;
        }
        for (int i = 1; i < args.length; i++) {
            String name = args[i];
            Function fn = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) { fn = f; break; }
            }
            if (fn == null) { println("not found: " + name); continue; }
            DecompileResults dr = di.decompileFunction(fn, 60, monitor);
            if (dr == null || !dr.decompileCompleted()) {
                println("decompile failed: " + name);
                continue;
            }
            FileWriter w = new FileWriter(outDir + "/" + name + ".c");
            w.write(dr.getDecompiledFunction().getC());
            w.close();
            println("wrote " + name);
        }
        di.dispose();
    }
}
