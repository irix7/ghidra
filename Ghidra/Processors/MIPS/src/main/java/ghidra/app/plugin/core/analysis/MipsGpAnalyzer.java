/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.util.task.TaskMonitor;

/**
 * Seeds the MIPS {@code gp} register with its global-pointer value at each function
 * entry, and {@code t9} with the function's own address (the PIC ABI guarantees t9
 * holds the callee address on entry).  IRIX/MIPSpro (CPIC) shared objects and kernels
 * maintain a constant {@code gp} per image (recorded in {@code .reginfo}/{@code .MIPS.options}/
 * {@code DT_MIPS_GP_VALUE} and imported as the {@code _mips_gp_value} /
 * {@code _mips_gp0_value} symbols), but every prologue recomputes it as
 * {@code gp = t9 + const}; without t9 the recomputation defeats a gp-only seed.
 * Seeding both turns gp-relative GOT and small-data references into resolvable
 * constants, replacing {@code unaff_gp_lo}, magic offsets and {@code (**(code **)...)}
 * call spam.  The decompiler picks stored register values up via its tracked-register
 * query at the function entry ({@code DecompileCallback.getTrackedRegisters}).
 */
public class MipsGpAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "MIPS Global Pointer";

	private static final String[] GP_SYMBOLS =
		{ "_mips_gp_value", "_mips_gp0_value", "_gp" };

	public MipsGpAnalyzer() {
		super(NAME,
			"Seeds the MIPS gp register with the image global-pointer value at function entries",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return "MIPS".equalsIgnoreCase(program.getLanguage().getProcessor().toString()) &&
			findGpSymbol(program) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Symbol gpSym = findGpSymbol(program);
		if (gpSym == null) {
			return false;
		}
		Register gp = program.getLanguage().getRegister("gp");
		Register t9 = program.getLanguage().getRegister("t9");
		if (gp == null || t9 == null) {
			return false;
		}
		Address gpValue = gpSym.getAddress();
		if (!gpValue.isMemoryAddress()) {
			return false;
		}
		BigInteger value = BigInteger.valueOf(gpValue.getOffset());
		ProgramContext context = program.getProgramContext();
		boolean changed = false;
		try {
			for (Function function : program.getFunctionManager().getFunctions(set, true)) {
				monitor.checkCancelled();
				if (function.isThunk() || function.isExternal()) {
					continue;
				}
				Address entry = function.getEntryPoint();
				context.setValue(gp, entry, entry, value);
				context.setValue(t9, entry, entry,
					BigInteger.valueOf(entry.getOffset()));
				changed = true;
			}
		}
		catch (ContextChangeException e) {
			log.appendMsg(getName(), "Failed to set gp value: " + e.getMessage());
		}
		return changed;
	}

	private static Symbol findGpSymbol(Program program) {
		SymbolTable symbolTable = program.getSymbolTable();
		for (String name : GP_SYMBOLS) {
			List<Symbol> symbols = symbolTable.getGlobalSymbols(name);
			if (!symbols.isEmpty()) {
				return symbols.get(0);
			}
		}
		return null;
	}
}
