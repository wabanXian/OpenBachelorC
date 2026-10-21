import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Export one already-analyzed function without rerunning auto-analysis. */
public final class ExportFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("address, output path and timeout required");
        Address address = toAddr(args[0]);
        int timeoutSeconds = Integer.parseInt(args[2]);
        Function function = getFunctionAt(address);
        if (function == null) function = getFunctionContaining(address);
        if (function == null) throw new IllegalArgumentException("no function at " + address);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(function, timeoutSeconds, monitor);
        if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
        StringBuilder ranges = new StringBuilder();
        AddressRangeIterator iterator = function.getBody().getAddressRanges();
        while (iterator.hasNext()) {
            AddressRange range = iterator.next();
            if (ranges.length() > 0) ranges.append(", ");
            ranges.append(range.getMinAddress()).append("-").append(range.getMaxAddress());
        }
        String text = "// name: " + function.getName(true) + "\n" +
            "// entry: " + function.getEntryPoint() + "\n" +
            "// signature: " + function.getSignature() + "\n" +
            "// body: " + ranges + "\n\n" +
            result.getDecompiledFunction().getC() + "\n";
        Files.writeString(Path.of(args[1]), text, StandardCharsets.UTF_8);
        println("REA persistent query wrote " + args[1]);
    }
}
