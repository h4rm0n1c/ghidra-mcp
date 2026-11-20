// Configure only the controlled integration fixture's memory permissions.
// @category OldMac.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
public class PreparePointerFixture extends GhidraScript {
    public void run() throws Exception {
        if (!currentProgram.getName().equals("pointer-tables-68k.bin")) {
            throw new IllegalStateException("Only the integration fixture may be changed");
        }
        var memory = currentProgram.getMemory();
        var boundary = toAddr(0x1010);
        MemoryBlock code = memory.getBlock(toAddr(0x1000));
        if (memory.getBlock(boundary).getStart().getOffset() != 0x1010) {
            memory.split(code, boundary);
        }
        code.setExecute(true);
        memory.getBlock(boundary).setExecute(false);
        memory.setBytes(toAddr(0x100c), new byte[]{0x70, 0x2d, 0x4e, 0x75});
        memory.setBytes(toAddr(0x103c), new byte[]{0, 0, 0x10, 0x0c});
        memory.setBytes(toAddr(0x104c), new byte[]{0, 0, 0x10, 0x22});
        println("Fixture code executable, table data non-executable");
    }
}
