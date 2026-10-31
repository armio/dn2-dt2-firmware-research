// DumpClosure.java - walk a call closure from root addresses, emitting
// FN/INST/REF lines in the format build_graft.py parses (prefix-stripping
// relies on this exact script name).
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

public class DumpClosure extends GhidraScript {
    private final Set<Address> visited = new HashSet<>();
    private final Deque<Address> work = new ArrayDeque<>();

    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            work.add(currentProgram.getAddressFactory().getAddress(a));
        }
        while (!work.isEmpty()) {
            Address root = work.poll();
            if (root == null) {
                continue;
            }
            Function f = getFunctionContaining(root);
            if (f == null) {
                f = createFunction(root, null);
                if (f == null) {
                    continue;
                }
            }
            Address entry = f.getEntryPoint();
            if (!visited.add(entry)) {
                continue;
            }
            System.out.printf("FN %s %s %d %s%s%n", entry,
                f.getBody().getMaxAddress(), f.getBody().getNumAddresses(),
                f.getName(), f.isThunk() ? " THUNK" : "");
            InstructionIterator it = currentProgram.getListing()
                .getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction inst = it.next();
                System.out.printf("INST %s %d%n",
                    inst.getAddress(), inst.getLength());
                String desc = inst.toString();
                for (Reference r : inst.getReferencesFrom()) {
                    Address to = r.getToAddress();
                    System.out.printf("REF %s %s %s ; %s%n",
                        inst.getAddress(), to, r.getReferenceType(), desc);
                    String ty = r.getReferenceType().toString();
                    boolean flow = ty.contains("CALL") || ty.contains("JUMP");
                    boolean fnPtr = (desc.startsWith("lea") || desc.startsWith("pea"))
                        && currentProgram.getFunctionManager()
                            .getFunctionAt(to) != null;
                    if (flow || fnPtr) {
                        work.add(to);
                    }
                }
            }
        }
    }
}
