// Report the active architecture without changing the program.
// @category OldMac
import ghidra.app.script.GhidraScript;
public class TargetInfo extends GhidraScript {
    public void run() throws Exception {
        println("language=" + currentProgram.getLanguageID());
        println("bigEndian=" + currentProgram.getLanguage().isBigEndian());
        println("pointerSize=" + currentProgram.getDefaultPointerSize());
    }
}
