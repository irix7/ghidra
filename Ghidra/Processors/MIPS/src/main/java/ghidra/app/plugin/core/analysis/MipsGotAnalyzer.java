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

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Names IRIX GOT slot labels after the symbols their pointers target.  The ELF loader
 * lays down {@code PTR_*}, {@code PTR_FUN_*}, {@code PTR_DAT_*} ... auto labels on the
 * pointer data in the 64K global-pointer window ({@code _gp} +/- {@code 0x7ff0}), so
 * indirect calls ({@code lw t9,off(gp); jalr t9}) decompile as
 * {@code (**(code **)PTR_FUN_memcpy_...)(...)}.  Renaming each slot after its target
 * ({@code __got_memcpy}, {@code __got_memcpy@plt} for a PLT thunk, {@code __got___iob}
 * for data) turns that spam into readable target names.  Auto labels whose targets
 * have no meaningful name, and slots the user has already named, are left alone.
 */
public class MipsGotAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "MIPS GOT Slots";

	private static final String GOT_PREFIX = "__got_";
	private static final String PTR_PREFIX = "PTR_";
	private static final long GOT_WINDOW = 0x7ff0;

	private static final String[] GP_SYMBOLS = { "_mips_gp_value", "_mips_gp0_value" };
	private static final String[] AUTO_LABEL_PREFIXES =
		{ "LAB_", "DAT_", "UINT_", "PTR_", "FUN_", "SUB_" };

	public MipsGotAnalyzer() {
		super(NAME, "Names MIPS GOT slots after the functions/data they point to",
			AnalyzerType.DATA_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
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
		Address gpAddr = gpSym.getAddress();
		if (!gpAddr.isMemoryAddress()) {
			return false;
		}
		AddressSpace space = gpAddr.getAddressSpace();
		long gp = gpAddr.getOffset();
		long lo = Math.max(0, gp - GOT_WINDOW);
		long hi = gp + GOT_WINDOW;
		if (lo > hi) {
			return false;
		}
		AddressSetView gotRegion = new AddressSet(space.getAddress(lo), space.getAddress(hi));
		AddressSetView toScan = set == null ? gotRegion : set.intersect(gotRegion);
		if (toScan.isEmpty()) {
			return false;
		}
		Listing listing = program.getListing();
		boolean changed = false;
		for (Data data : listing.getDefinedData(toScan, true)) {
			monitor.checkCancelled();
			if (data.getDataType() instanceof Pointer) {
				changed |= nameSlot(program, data, log);
			}
		}
		return changed;
	}

	/**
	 * Renames the label at {@code data}'s address after the name of the symbol its
	 * pointer targets.  Returns true if the program was modified.
	 */
	private static boolean nameSlot(Program program, Data data, MessageLog log) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol slot = symbolTable.getPrimarySymbol(data.getAddress());
		if (slot == null) {
			return false;
		}
		if (slot.getSource() == SourceType.USER_DEFINED) {
			return false; // user-defined; leave alone
		}
		String slotName = slot.getName();
		if (!slotName.startsWith(PTR_PREFIX) && !slotName.startsWith(GOT_PREFIX)) {
			return false; // not a loader GOT label (or already named with something else)
		}
		Reference ref = data.getPrimaryReference(0);
		if (ref == null) {
			ref = program.getReferenceManager().getPrimaryReferenceFrom(data.getAddress(), 0);
		}
		if (ref == null) {
			return false;
		}
		String targetName = resolveTargetName(program, ref.getToAddress());
		if (targetName == null) {
			return false;
		}
		String newName = GOT_PREFIX + sanitize(targetName);
		if (newName.equals(slotName)) {
			return false;
		}
		List<Symbol> existing = symbolTable.getGlobalSymbols(newName);
		if (!existing.isEmpty()) {
			// Collision with an unrelated symbol; leave the loader label in place.
			log.appendMsg(NAME, "GOT slot " + data.getAddress() + " keeps label " + slotName +
				" because " + newName + " already exists at " + existing.get(0).getAddress());
			return false;
		}
		try {
			slot.setName(newName, SourceType.IMPORTED);
			return true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendMsg(NAME,
				"Failed to name GOT slot " + data.getAddress() + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Returns a meaningful name for the symbol the GOT slot points at: the name of the
	 * function (defined, thunk or external) containing the target, or the name of the
	 * data symbol at the target.  Returns null when the target has no meaningful name.
	 */
	private static String resolveTargetName(Program program, Address target) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(target);
		if (function == null) {
			function = functionManager.getFunctionAt(target);
		}
		String functionName = null;
		if (function != null) {
			functionName = function.getName();
			if (!functionName.isBlank() && !isAutoLabel(functionName)) {
				return functionName;
			}
		}
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(target);
		if (symbol != null && symbol.getSource() != SourceType.DEFAULT) {
			String symbolName = symbol.getName();
			if (!symbolName.isBlank() && !isAutoLabel(symbolName)) {
				return symbolName;
			}
		}
		if (functionName != null && !functionName.isBlank()) {
			return functionName; // keep the name meaningful even if FUN_-style
		}
		return null;
	}

	private static boolean isAutoLabel(String name) {
		for (String prefix : AUTO_LABEL_PREFIXES) {
			if (name.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Keeps only ASCII name characters so the new label is always importable
	 * (no spaces, no non-ASCII); anything else becomes an underscore.
	 */
	private static String sanitize(String name) {
		StringBuilder sb = new StringBuilder(name.length());
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (c < 0x80 && (Character.isLetterOrDigit(c) || c == '_' || c == '.' ||
				c == '$' || c == '@')) {
				sb.append(c);
			}
			else {
				sb.append('_');
			}
		}
		return sb.toString();
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
