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

import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Names IRIX .MIPS.stubs entries after the dynamic symbols they dispatch to and turns
 * them into thunks to the imported function.  Each IRIX PLT stub carries its .dynsym
 * index in the delay slot of its {@code jalr} ({@code ori t8, zero, symindex}), so the
 * mapping is unambiguous.  Result: stub functions become {@code name@plt} one-liner
 * thunks and calls through them decompile to the real callee names instead of walking
 * into the rld resolver.
 */
public class MipsStubsAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "MIPS PLT Stubs";
	private static final String STUBS_BLOCK = ".MIPS.stubs";

	public MipsStubsAnalyzer() {
		super(NAME, "Names IRIX .MIPS.stubs PLT entries as thunks to their dynamic symbols",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return "MIPS".equalsIgnoreCase(program.getLanguage().getProcessor().toString()) &&
			program.getExecutableFormat() != null &&
			program.getExecutableFormat().equals(ElfLoader.ELF_NAME) &&
			program.getMemory().getBlock(STUBS_BLOCK) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MemoryBlock stubs = program.getMemory().getBlock(STUBS_BLOCK);
		if (stubs == null || !set.intersects(stubs.getStart(), stubs.getEnd())) {
			return false;
		}
		ElfSymbol[] dynsyms = readDynamicSymbols(program);
		if (dynsyms == null) {
			return false;
		}
		boolean changed = false;
		Listing listing = program.getListing();
		Register t8 = program.getLanguage().getRegister("t8");
		Address addr = stubs.getStart();
		Address end = stubs.getEnd();
		while (addr != null && addr.compareTo(end) <= 0) {
			monitor.checkCancelled();
			Instruction insn = listing.getInstructionAt(addr);
			if (insn == null) {
				addr = addr.add(4);
				continue;
			}
			Integer symIndex = getSymIndex(insn, t8);
			if (symIndex != null && symIndex >= 0 && symIndex < dynsyms.length) {
				ElfSymbol sym = dynsyms[symIndex];
				String name = sym.getNameAsString();
				if (!name.isBlank()) {
					changed |= nameStub(program, addr, name, log);
				}
			}
			addr = addr.add(4);
		}
		return changed;
	}

	/**
	 * Returns the .dynsym index encoded in an {@code ori t8, zero, idx} delay-slot
	 * instruction, or null.
	 */
	private static Integer getSymIndex(Instruction insn, Register t8) {
		if (!insn.isInDelaySlot()) {
			return null;
		}
		String mnemonic = insn.getMnemonicString();
		if (!("ori".equals(mnemonic) || "_ori".equals(mnemonic))) {
			return null;
		}
		if (insn.getNumOperands() < 3 || insn.getRegister(0) == null ||
			!t8.equals(insn.getRegister(0))) {
			return null;
		}
		// The immediate is the last operand; earlier operands may expose scalar 0
		// (the zero register).
		for (int i = insn.getNumOperands() - 1; i >= 0; i--) {
			Scalar scalar = insn.getScalar(i);
			if (scalar != null && scalar.getUnsignedValue() < 0x10000) {
				return (int) scalar.getUnsignedValue();
			}
		}
		return null;
	}

	private static boolean nameStub(Program program, Address oriAddr, String name, MessageLog log) {
		// The stub is lw t9,off(gp) [or t7,ra,zero] jalr t9 / ori t8,zero,idx.
		Listing listing = program.getListing();
		Address entry = oriAddr;
		Instruction insn = listing.getInstructionAt(oriAddr.subtract(4));
		for (int i = 0; i < 3 && insn != null; i++) {
			if (insn.getMnemonicString().startsWith("lw") ||
				insn.getMnemonicString().equals("lwu") ||
				insn.getMnemonicString().equals("ld")) {
				entry = insn.getAddress();
				break;
			}
			insn = listing.getInstructionAt(insn.getAddress().subtract(4));
		}
		Function stub = program.getFunctionManager().getFunctionAt(entry);
		if (stub == null) {
			// Create the stub function even if it is inside a larger function body
			// (the loader may have merged the whole .MIPS.stubs region).
			AddressSetView body = new AddressSet(entry, oriAddr.add(3));
			CreateFunctionCmd cmd = new CreateFunctionCmd(name + "@plt", entry, body,
				SourceType.IMPORTED);
			if (!cmd.applyTo(program)) {
				return false;
			}
			stub = program.getFunctionManager().getFunctionAt(entry);
			if (stub == null) {
				return false;
			}
		}
		if (stub.isThunk() && stub.getName().equals(name + "@plt")) {
			return false;
		}
		if (stub.getSymbol().getSource().isHigherPriorityThan(SourceType.IMPORTED)) {
			return false; // user-defined; leave alone
		}
		String pltName = name + "@plt";
		Function target = resolveTarget(program, name);
		try {
			if (target != null && !stub.isThunk()) {
				stub.setThunkedFunction(target);
			}
			if (!stub.getName().equals(pltName) &&
				stub.getSymbol().getSource() != SourceType.USER_DEFINED) {
				stub.setName(pltName, SourceType.IMPORTED);
			}
			return true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendMsg(NAME, "Failed to name stub " + stub.getEntryPoint() + ": " +
				e.getMessage());
			return false;
		}
	}

	private static Function resolveTarget(Program program, String name) {
		FunctionManager fm = program.getFunctionManager();
		MemoryBlock stubs = program.getMemory().getBlock(STUBS_BLOCK);
		// Prefer a defined function with this name outside .MIPS.stubs, else an external.
		for (Function f : fm.getFunctions(true)) {
			if (name.equals(f.getName()) &&
				(stubs == null || !stubs.contains(f.getEntryPoint()))) {
				return f;
			}
		}
		FunctionIterator it = fm.getExternalFunctions();
		while (it.hasNext()) {
			Function f = it.next();
			if (name.equals(f.getName())) {
				return f;
			}
		}
		return null;
	}

	private static ElfSymbol[] readDynamicSymbols(Program program) {
		var fileBytes = program.getMemory().getAllFileBytes();
		if (fileBytes.size() != 1) {
			return null;
		}
		try (ByteProvider provider = new FileBytesProvider(fileBytes.get(0))) {
			ElfHeader elf = new ElfHeader(provider, null);
			// IRIX dynamic symbols use SHT_MIPS_DYNSYM and are only reachable via DT_SYMTAB,
			// which requires the full parse.
			elf.parse();
			ElfSymbolTable dynsyms = elf.getDynamicSymbolTable();
			if (dynsyms == null) {
				for (ElfSymbolTable table : elf.getSymbolTables()) {
					if (ElfSectionHeaderConstants.dot_dynsym.equals(
						table.getTableSectionHeader().getNameAsString())) {
						dynsyms = table;
						break;
					}
				}
			}
			return dynsyms != null ? dynsyms.getSymbols() : null;
		}
		catch (IOException | ElfException e) {
			return null;
		}
	}
}
