import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.io.FileWriter;

public class DumpAtAddrsJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args[0];
        new File(outDir).mkdirs();
        DecompInterface di = new DecompInterface();
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) { println("open failed"); return; }
        for (int i = 1; i < args.length; i++) {
            long addr = Long.parseLong(args[i].startsWith("0x") ? args[i].substring(2) : args[i], 16);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(toAddr(addr));
            if (fn == null) { println("no func at " + args[i]); continue; }
            DecompileResults dr = di.decompileFunction(fn, 60, monitor);
            if (dr == null || !dr.decompileCompleted()) { println("failed " + args[i]); continue; }
            FileWriter w = new FileWriter(outDir + "/at_" + args[i].substring(2) + "_" + fn.getName() + ".c");
            w.write(dr.getDecompiledFunction().getC());
            w.close();
            println("wrote " + args[i] + " -> " + fn.getName());
        }
        di.dispose();
    }
}
