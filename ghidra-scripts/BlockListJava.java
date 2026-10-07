import ghidra.app.script.GhidraScript;

public class BlockListJava extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (var block : currentProgram.getMemory().getBlocks()) {
            println(block.getStart() + " - " + block.getEnd() + " (" + block.getSize() + ")");
        }
    }
}
