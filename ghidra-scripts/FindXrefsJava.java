import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class FindXrefsJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        long addr = Long.parseLong(args[0].startsWith("0x") ? args[0].substring(2) : args[0], 16);
        Address a = toAddr(addr);
        var refs = currentProgram.getReferenceManager().getReferencesTo(a);
        int n = 0;
        for (var ref : refs) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("xref from " + from + " in func " +
                    (fn != null ? fn.getEntryPoint() + " (" + fn.getName() + ")" : "NO-FUNC"));
            n++;
        }
        println("total xrefs: " + n);
    }
}
