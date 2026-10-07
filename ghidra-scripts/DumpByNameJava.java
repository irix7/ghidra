import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.FileWriter;

public class DumpByNameJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = getScriptArgs()[0];
        new File(outDir).mkdirs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (int i = 1; i < getScriptArgs().length; i++) {
            String name = getScriptArgs()[i];
            Function fn = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) { fn = f; break; }
            }
            if (fn == null) { println("not found: " + name); continue; }
            DecompileResults dr = di.decompileFunction(fn, 60, monitor);
            if (dr == null || !dr.decompileCompleted()) { println("failed: " + name); continue; }
            FileWriter w = new FileWriter(outDir + "/" + name + ".c");
            w.write(dr.getDecompiledFunction().getC());
            w.close();
            println("wrote " + name);
        }
        di.dispose();
    }
}
