// Decode explicitly selected 68k relative dispatch targets; no ABI inference.
// @category OldMac
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
public class InspectRelativeDispatch extends GhidraScript {
    public void run() throws Exception {
        if (!currentProgram.getLanguage().isBigEndian()) throw new Exception("Requires big endian program");
        for (String arg : getScriptArgs()) {
            Address a = toAddr(arg);
            disassemble(a);
            println("TARGET " + a);
            Instruction i = getInstructionAt(a);
            for (int n = 0; i != null && n < 24; n++) {
                println(i.getAddress() + " " + i);
                if (i.getFlowType().isTerminal() || (i.getFlowType().isJump() && !i.getFlowType().isConditional())) break;
                i = getInstructionAt(i.getMaxAddress().add(1));
            }
        }
    }
}
