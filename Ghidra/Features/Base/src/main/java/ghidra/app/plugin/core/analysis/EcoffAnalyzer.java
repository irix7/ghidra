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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.ecoff.EcoffDebug;
import ghidra.app.util.bin.format.ecoff.EcoffDebug.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Automatically discovered by Ghidra's Analyzer class search. */
public class EcoffAnalyzer extends AbstractAnalyzer {
	private static final String LOADED = "ECOFF Debug Loaded";
	// A four-byte MIPS instruction and its delay slot can touch seven bytes after its start.
	private static final int MIPS_DISASSEMBLY_LOOKAHEAD = 7;

	public EcoffAnalyzer() {
		super("ECOFF Debug", "Import MIPS ECOFF procedures, symbols and basic types without DWARF.",
			AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!"MIPS".equals(program.getLanguage().getProcessor().toString()) ||
			!ElfLoader.ELF_NAME.equals(program.getExecutableFormat()) ||
			DWARFProgram.isDWARF(program) || program.getMemory().getBlock(".debug_info") != null ||
			program.getMemory().getBlock(".zdebug_info") != null ||
			program.getMemory().getBlock(".debug") != null) {
			return false;
		}
		try (ByteProvider provider = originalBytes(program)) {
			if (provider != null) {
				ElfHeader elf = new ElfHeader(provider, null);
				elf.parseSectionHeaders();
				return elf.is32Bit() && elf.getSection(".mdebug") != null &&
					elf.getSection(".debug_info") == null &&
					elf.getSection(".zdebug_info") == null && elf.getSection(".debug") == null;
			}
		}
		catch (IOException | ElfException e) {
			// No original ELF bytes, or no usable section table.
		}
		return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		if (program.getOptions(Program.PROGRAM_INFO).getBoolean(LOADED, false) ||
			!canAnalyze(program)) {
			return true;
		}
		try (ByteProvider provider = originalBytes(program)) {
			if (provider == null) {
				return false;
			}
			ElfHeader elf = new ElfHeader(provider, log::appendMsg);
			elf.parseSectionHeaders();
			ElfSectionHeader section = elf.getSection(".mdebug");
			long offset = section.getOffset(), size = section.getSize();
			if (offset < 0 || size < 0 || offset > provider.length() ||
				size > provider.length() - offset) {
				throw new IOException(".mdebug section exceeds original file bounds");
			}
			EcoffDebug debug = EcoffDebug.parse(new ByteProviderWrapper(provider, offset, size),
				offset, elf.isLittleEndian(), monitor);
			List<EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> authoredBodies =
				importDebug(program, elf.isRelocatable(), debug, monitor, log);
			if (!authoredBodies.isEmpty()) {
				// Later analyzers recompute function bodies from flow (eg. the entry-point
				// second pass, switch recovery and call fixups), which drops ECOFF addresses
				// left without instructions. Re-apply the authoritative ranges last.
				AddressSet union = new AddressSet();
				for (EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo info : authoredBodies) {
					union.add(info.body());
				}
				AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(
					new EcoffFunctionBodyFixupAnalyzer(authoredBodies), union);
			}
			program.getOptions(Program.PROGRAM_INFO).setBoolean(LOADED, true);
			return true;
		}
		catch (IOException | ElfException e) {
			log.appendMsg("ECOFF .mdebug", e.getMessage());
			return false;
		}
	}

	private static ByteProvider originalBytes(Program program) {
		var files = program.getMemory().getAllFileBytes();
		return files.size() == 1 ? new FileBytesProvider(files.get(0)) : null;
	}

	// Package visibility permits synthetic program-model tests without fixture files.
	// Returns the authoritative procedure ranges authored by this import, so a late
	// one-time analyzer can re-apply bodies clipped by later analysis.
	List<EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> importDebug(Program program,
		boolean relocatable, EcoffDebug debug, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		List<EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> authoredBodies = new ArrayList<>();
		AddressSet functionEntries = new AddressSet();
		for (FileDescriptor file : debug.files()) {
			for (Procedure pd : file.procedures()) {
				monitor.checkCanceled();
				Symbol sym = pd.symbol();
				if (sym == null || !sym.isProcedure() || sym.isStab() ||
					sym.storage() != EcoffDebug.SC_TEXT || sym.name().isEmpty()) {
					continue;
				}
				// PDR addresses can be file-relative. The associated SYMR is the symbol address.
				Address entry = address(program, relocatable, sym);
				if (entry == null) {
					continue;
				}
				try {
					MemoryBlock block = program.getMemory().getBlock(entry);
					if (!block.isExecute()) {
						continue;
					}
					Function function = program.getFunctionManager().getFunctionAt(entry);
					if (function == null &&
						program.getFunctionManager().getFunctionContaining(entry) != null) {
						// Retain the ECOFF name as a label, not an entry inside an owned body.
						continue;
					}
					AddressSet body = null;
					boolean placeholder = function != null &&
						function.getBody().getNumAddresses() == 1 &&
						!function.getSymbol().getSource().isHigherPriorityThan(SourceType.IMPORTED);
					if (function == null || placeholder) {
						boolean sized = pd.size() > 0 &&
							pd.size() <= block.getEnd().subtract(entry) + 1 && (pd.size() & 3) == 0;
						body = sized ? new AddressSet(entry, entry.add(pd.size() - 1)) :
							new AddressSet(block.getStart(), block.getEnd());
						// Restrict decoding before following flow, not just the final function body.
						AddressSet decode = new AddressSet(body);
						AddressSet lookup = new AddressSet(body);
						Address end = body.getMaxAddress();
						try {
							lookup.add(end, end.addNoWrap(MIPS_DISASSEMBLY_LOOKAHEAD));
						}
						catch (AddressOverflowException e) {
							lookup.add(end, end.getAddressSpace().getMaxAddress());
						}
						var overlaps = program.getFunctionManager().getFunctionsOverlapping(lookup);
						while (overlaps.hasNext()) {
							Function other = overlaps.next();
							if (!placeholder || !other.getEntryPoint().equals(entry)) {
								body = body.subtract(other.getBody());
								decode = decode.subtract(other.getBody());
								// Delay slots bypass the restricted set. Also exclude starts which
								// could decode an instruction or its slot into an owned range.
								for (AddressRange range : other.getBody().getAddressRanges()) {
									Address first = range.getMinAddress();
									Address minimum = first.getAddressSpace().getMinAddress();
									if (!first.equals(minimum)) {
										Address prefix;
										try {
											prefix = first.subtractNoWrap(MIPS_DISASSEMBLY_LOOKAHEAD);
										}
										catch (AddressOverflowException e) {
											prefix = minimum;
										}
										decode.delete(prefix, first.previous());
									}
								}
							}
						}
						if (!decode.contains(entry)) {
							continue;
						}
						new DisassembleCommand(entry, decode, true).applyTo(program, monitor);
						if (program.getListing().getInstructionAt(entry) == null) {
							continue;
						}
						if (!sized) {
							body = new AddressSet(
								CreateFunctionCmd.getFunctionBody(program, entry, monitor)).intersect(body);
						}
						if (function == null) {
							function = program.getFunctionManager().createFunction(
								sym.name(), entry, body, SourceType.IMPORTED);
						}
					}
					if (function != null) {
						functionEntries.add(entry);
						if (function.getSymbol().getSource() == SourceType.DEFAULT) {
							function.setName(sym.name(), SourceType.IMPORTED);
						}
						if (body != null && !function.getSymbol().getSource().isHigherPriorityThan(
										SourceType.IMPORTED)) {
							function.setBody(body);
							authoredBodies.add(new EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo(
								entry, new AddressSet(body), sym.name()));
						}
						if (function.getRepeatableComment() == null && !file.name().isEmpty()) {
							function.setRepeatableComment("ECOFF source: " + file.name());
						}
						// Importing a return type locks the entire signature. Do not import it
						// until ECOFF parameter import is supported.
					}
				}
				catch (Exception e) {
					if (e instanceof CancelledException ce) {
						throw ce;
					}
					log.appendMsg("ECOFF procedure " + sym.name(), e.getMessage());
				}
			}
			for (Symbol sym : file.symbols()) {
				monitor.checkCanceled();
				importSymbol(program, relocatable, sym, log);
			}
		}
		for (Symbol sym : debug.externals()) {
			monitor.checkCanceled();
			importSymbol(program, relocatable, sym, log);
		}
		// The normal known no-return pass precedes ECOFF's format-analysis priority.
		// Reuse its configured rules only at function entries processed by this import.
		NoReturnFunctionAnalyzer knownNoReturn = new NoReturnFunctionAnalyzer();
		var options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		if (!functionEntries.isEmpty() && knownNoReturn.canAnalyze(program) &&
			options.getBoolean(
				knownNoReturn.getName(), knownNoReturn.getDefaultEnablement(program))) {
			knownNoReturn.optionsChanged(options.getOptions(knownNoReturn.getName()), program);
			knownNoReturn.added(program, functionEntries, monitor, log);
		}
		return authoredBodies;
	}

	private void importSymbol(Program program, boolean relocatable, Symbol sym, MessageLog log) {
		if (sym.isStab() || sym.name().isEmpty()) {
			return;
		}
		try {
			DataType type = dataType(program, sym.type());
			if (sym.kind() == 10) {
				if (type != null && !(type instanceof VoidDataType)) {
					program.getDataTypeManager().resolve(
						new TypedefDataType(new CategoryPath("/ECOFF"), sym.name(), type),
						DataTypeConflictHandler.KEEP_HANDLER);
				}
				return;
			}
			if (!(sym.kind() == 1 || sym.kind() == 2 ||
				sym.kind() == EcoffDebug.ST_LABEL || sym.isProcedure())) {
				return;
			}
			Address addr = address(program, relocatable, sym);
			if (addr == null) {
				return;
			}
			program.getSymbolTable().createLabel(addr, sym.name(), SourceType.IMPORTED);
			if ((sym.kind() == 1 || sym.kind() == 2) && sym.storage() != EcoffDebug.SC_TEXT &&
				type != null && type.getLength() > 0) {
				// Listing.createData refuses conflicts; never clear existing instructions or data.
				program.getListing().createData(addr, type);
			}
		}
		catch (Exception e) {
			log.appendMsg("ECOFF symbol " + sym.name(), e.getMessage());
		}
	}

	static Address address(Program program, boolean relocatable, Symbol sym) {
		String section = switch (sym.storage()) {
			case EcoffDebug.SC_TEXT -> ".text";
			case 2 -> ".data";
			case 3 -> ".bss";
			case 13 -> ".sdata";
			case 14 -> ".sbss";
			case 15 -> ".rodata";
			case 22 -> ".init";
			case 26 -> ".fini";
			default -> null; // Register numbers, offsets, undefined/common sizes are not addresses.
		};
		if (section == null) {
			return null;
		}
		try {
			Address result;
			if (relocatable) {
				MemoryBlock block = program.getMemory().getBlock(section);
				if (block == null && sym.storage() == 15) {
					block = program.getMemory().getBlock(".rdata");
				}
				if (block == null || sym.value() >= block.getSize()) {
					return null;
				}
				result = block.getStart().add(sym.value());
			}
			else {
				Long originalBase = ElfLoader.getElfOriginalImageBase(program);
				long adjustment =
					originalBase == null ? 0 : program.getImageBase().getOffset() - originalBase;
				result = program.getAddressFactory()
							 .getDefaultAddressSpace()
							 .getAddress(sym.value())
							 .addWrap(adjustment);
			}
			return program.getMemory().contains(result) ? result : null;
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	static DataType dataType(Program program, Type type) {
		if (type == null) {
			return null;
		}
		DataType result = switch (type.basicType()) {
			case 1 ->
				program.getDefaultPointerSize() == 8 ? UnsignedLongLongDataType.dataType
													 : UnsignedIntegerDataType.dataType;
			case 2 -> CharDataType.dataType;
			case 3 -> UnsignedCharDataType.dataType;
			case 4 -> ShortDataType.dataType;
			case 5 -> UnsignedShortDataType.dataType;
			case 6 -> IntegerDataType.dataType;
			case 7 -> UnsignedIntegerDataType.dataType;
			case 8 -> LongDataType.dataType;
			case 9 -> UnsignedLongDataType.dataType;
			case 10 -> FloatDataType.dataType;
			case 11 -> DoubleDataType.dataType;
			case 26 -> VoidDataType.dataType;
			case 27, 30, 32, 35 -> LongLongDataType.dataType;
			case 28, 31, 33, 34, 36 -> UnsignedLongLongDataType.dataType;
			default -> null;
		};
		if (result != null) {
			result = result.clone(program.getDataTypeManager());
			for (int i = 0; i < type.pointerDepth(); i++) {
				result = new PointerDataType(result, program.getDataTypeManager());
			}
		}
		return result;
	}

	/**
	 * Re-applies the authoritative ECOFF procedure ranges recorded by
	 * {@link EcoffAnalyzer#importDebug}, following the DWARF late body-fixup pattern.
	 * <p>
	 * The ECOFF import runs early, so its bodies can later be clipped when other analyzers
	 * recompute function bodies from instruction flow (eg. the disassemble-entry-points
	 * second pass, switch recovery and call fixups): any address left without an instruction
	 * is dropped from the body even though the ECOFF range is authoritative. A one-time
	 * instance of this analyzer is scheduled at {@link AnalysisPriority#LOW_PRIORITY} so the
	 * recorded bodies are restored after those analyzers have run.
	 * <p>
	 * Unlike the DWARF fixup, nested non-ECOFF functions are never demoted. An overlap only
	 * skips that restore with a warning, so user-owned and analyzer-owned bodies are never
	 * carved. Signatures are never touched.
	 */
	public static final class EcoffFunctionBodyFixupAnalyzer extends AbstractAnalyzer {

		/**
		 * Entry point and authoritative body range of an ECOFF procedure.
		 *
		 * @param entry entry point address
		 * @param body body address set authored by the ECOFF import
		 * @param name function name (for diagnostics)
		 */
		public record FunctionBodyInfo(Address entry, AddressSet body, String name) {
		}

		private final List<FunctionBodyInfo> funcBodies;

		public EcoffFunctionBodyFixupAnalyzer(List<FunctionBodyInfo> funcBodies) {
			super("ECOFF Function Body Fixup",
				"Re-applies authoritative ECOFF procedure bodies clipped by later analysis",
				AnalyzerType.BYTE_ANALYZER);
			this.funcBodies = List.copyOf(funcBodies);
			setPriority(AnalysisPriority.LOW_PRIORITY);
			setSupportsOneTimeAnalysis();
		}

		@Override
		public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
				MessageLog log) {
			apply(program, funcBodies, msg -> log.appendMsg(getName(), msg));
			return true;
		}

		/**
		 * Restores the recorded ECOFF bodies without carving other function bodies.
		 *
		 * @param program program to update
		 * @param funcBodies ECOFF procedure entry points and authored body ranges
		 * @param warn receives diagnostic messages about bodies that could not be restored
		 */
		static void apply(Program program, List<FunctionBodyInfo> funcBodies,
				Consumer<String> warn) {
			if (funcBodies.isEmpty()) {
				return;
			}
			FunctionManager functionMgr = program.getFunctionManager();
			AddressSetView loaded = program.getMemory().getLoadedAndInitializedAddressSet();
			List<FunctionBodyInfo> retry = new ArrayList<>();
			for (FunctionBodyInfo info : funcBodies) {
				if (!setFunctionBody(functionMgr, info, loaded)) {
					retry.add(info);
				}
			}
			for (FunctionBodyInfo info : retry) {
				if (!setFunctionBody(functionMgr, info, loaded)) {
					warn.accept("ECOFF: unable to restore body of function %s @ %s (overlap)"
							.formatted(info.name(), info.entry()));
				}
			}
		}

		private static boolean setFunctionBody(FunctionManager functionMgr, FunctionBodyInfo info,
				AddressSetView loaded) {
			Function function = functionMgr.getFunctionAt(info.entry());
			if (function == null || function.isExternal() || function.isThunk()) {
				return true;
			}
			if (function.getSymbol().getSource().isHigherPriorityThan(SourceType.IMPORTED)) {
				// A user-owned entry took over after import; never carve it.
				return true;
			}
			AddressSet body = new AddressSet(info.body()).intersect(loaded);
			if (body.isEmpty() || function.getBody().equals(body)) {
				return true;
			}
			try {
				function.setBody(body);
				return true;
			}
			catch (OverlappingFunctionException e) {
				return false;
			}
		}
	}
}
