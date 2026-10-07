import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class ForceFuncsJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        for (String a : args) {
            long addr = Long.parseLong(a.startsWith("0x") ? a.substring(2) : a, 16);
            Address ad = toAddr(addr);
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(ad);
            if (fn == null) {
                createFunction(ad, null);
                println("created at " + a);
            } else {
                println("already there " + a);
            }
        }
    }
}
