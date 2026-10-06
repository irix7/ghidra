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
package ghidra.app.util.bin.format.dwarf;

import java.util.*;
import java.util.function.Consumer;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Applies DWARF subprogram PC ranges to Ghidra function bodies, and demotes any function
 * entry that falls inside a DWARF range but is not itself a DWARF subprogram.
 * <p>
 * The DWARF importer runs early in analysis, so its bodies can later be clipped by
 * functions created by other analyzers (eg. shared-return or constant-propagation call
 * targets inside a hand-written assembly function).  A one-time instance of this analyzer
 * is scheduled at {@link AnalysisPriority#LOW_PRIORITY} so the DWARF bodies are
 * re-applied after those analyzers have run.
 */
class DWARFFunctionBodyFixupAnalyzer extends AbstractAnalyzer {

	/**
	 * Entry point and body range of a DWARF subprogram.
	 * 
	 * @param entry entry point address
	 * @param body body address set
	 * @param name function name (for diagnostics)
	 */
	static record FunctionBodyInfo(Address entry, AddressSet body, String name) {
	}

	private final List<FunctionBodyInfo> funcBodies;
	private final Set<Address> dwarfEntries;

	DWARFFunctionBodyFixupAnalyzer(List<FunctionBodyInfo> funcBodies,
			Set<Address> dwarfEntries) {
		super("DWARF Function Body Fixup",
			"Applies DWARF function body ranges and demotes nested non-DWARF function entries",
			AnalyzerType.BYTE_ANALYZER);
		this.funcBodies = funcBodies;
		this.dwarfEntries = dwarfEntries;
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		apply(program, funcBodies, dwarfEntries, msg -> log.appendMsg(getName(), msg));
		return true;
	}

	/**
	 * Applies the specified DWARF function bodies to the program, demoting nested
	 * non-DWARF function entries as needed.
	 * 
	 * @param program program to update
	 * @param funcBodies DWARF subprogram entry points and body ranges
	 * @param dwarfEntries set of all DWARF subprogram entry points
	 * @param warn receives diagnostic messages about bodies that could not be applied
	 */
	static void apply(Program program, List<FunctionBodyInfo> funcBodies,
			Set<Address> dwarfEntries, Consumer<String> warn) {

		FunctionManager functionMgr = program.getFunctionManager();
		SymbolTable symbolTable = program.getSymbolTable();

		AddressSet dwarfFuncBodies = new AddressSet();
		for (FunctionBodyInfo info : funcBodies) {
			if (!info.body().isEmpty()) {
				dwarfFuncBodies.add(info.body());
			}
		}
		if (dwarfFuncBodies.isEmpty()) {
			return;
		}

		// Demote functions that are not DWARF subprograms but start inside a DWARF function.
		// Thunks (eg. shared-return eret jumps to a common epilogue) are also demoted when
		// strictly inside an authoritative DWARF range: the DWARF range describes the whole
		// hand-written assembly function, and the demoted name remains as a label so branch
		// targets and address-taken references still resolve.  Thunks outside DWARF ranges
		// keep their existing behaviour.
		List<Function> toDemote = new ArrayList<>();
		FunctionIterator fit = functionMgr.getFunctions(dwarfFuncBodies, true);
		while (fit.hasNext()) {
			Function f = fit.next();
			Address entry = f.getEntryPoint();
			if (dwarfFuncBodies.contains(entry) && !dwarfEntries.contains(entry) &&
				!f.isExternal() && (!f.isThunk() || isStrictlyInsideDwarfRange(entry, funcBodies))) {
				toDemote.add(f);
			}
		}
		for (Function f : toDemote) {
			Address entry = f.getEntryPoint();
			String name = f.getName();
			Namespace ns = f.getParentNamespace();
			if (functionMgr.removeFunction(entry)) {
				try {
					// Keep the demoted name as a label so intra-function branches and
					// address-taken references still resolve.  An existing primary
					// (eg. DWARF label) is left in place.
					boolean hasName = false;
					for (Symbol s : symbolTable.getSymbols(entry)) {
						if (name.equals(s.getName())) {
							hasName = true;
							break;
						}
					}
					if (!hasName) {
						symbolTable.createLabel(entry, name, ns, SourceType.IMPORTED);
					}
				}
				catch (InvalidInputException e) {
					warn.accept("DWARF: failed to convert function %s @ %s to a label"
							.formatted(name, entry));
				}
			}
		}

		// Apply the DWARF ranges, with a second pass for bodies that initially overlap
		AddressSetView loaded = program.getMemory().getLoadedAndInitializedAddressSet();
		List<FunctionBodyInfo> retry = new ArrayList<>();
		for (FunctionBodyInfo info : funcBodies) {
			if (!setFunctionBody(functionMgr, info, loaded)) {
				retry.add(info);
			}
		}
		for (FunctionBodyInfo info : retry) {
			if (!setFunctionBody(functionMgr, info, loaded)) {
				warn.accept("DWARF: unable to set body of function %s @ %s (overlap)"
						.formatted(info.name(), info.entry()));
			}
		}
	}

	/**
	 * Returns true if the address lies strictly inside a DWARF subprogram body, ie. it is
	 * contained in a DWARF range but is not itself a DWARF subprogram entry point.
	 *
	 * @param entry address to test
	 * @param funcBodies DWARF subprogram entry points and body ranges
	 * @return true if strictly inside a DWARF range
	 */
	private static boolean isStrictlyInsideDwarfRange(Address entry,
			List<FunctionBodyInfo> funcBodies) {
		for (FunctionBodyInfo info : funcBodies) {
			if (!entry.equals(info.entry()) && info.body().contains(entry)) {
				return true;
			}
		}
		return false;
	}

	private static boolean setFunctionBody(FunctionManager functionMgr, FunctionBodyInfo info,
			AddressSetView loaded) {
		Function f = functionMgr.getFunctionAt(info.entry());
		AddressSet body = new AddressSet(info.body()).intersect(loaded);
		if (f == null || body.isEmpty()) {
			return true;
		}
		try {
			f.setBody(body);
			return true;
		}
		catch (OverlappingFunctionException e) {
			return false;
		}
	}
}
