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

import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers MIPS inline dispatch tables.
 * <p>
 * Hand-written assembly (eg. IRIX LOCORE/FP emulation code) selects a small handler
 * with a computed jump into code that immediately follows the dispatcher:
 * 
 * <pre>
 *   lui   t4,0x8800
 *   addiu t4,t4,0x6db8      ; base of handler table
 *   sll   t5,a0,0x3         ; index * 8
 *   addu  t4,t4,t5
 *   jr    t4
 *   _nop
 * ...handlers at 0x88006db8, 8 bytes apart...
 * </pre>
 * 
 * The table is code, not data, and the index has no bounds check, so neither flow
 * following nor the decompiler's jump-table model recovery can find it
 * ("Could not recover jumptable ... Too many branches").  This analyzer recognises
 * the address computation, disassembles the handler entries, and writes a
 * {@link JumpTable} override so the decompiler renders the dispatch as a switch.
 * <p>
 * Only bases that fall inside the containing function are accepted, which keeps the
 * transform away from ordinary function-pointer tables in data sections.
 */
public class MipsInlineDispatchAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "MIPS Inline Dispatch";
	private static final String DESCRIPTION =
		"Recovers computed jumps into inline handler tables inside a function";

	private static final String OPTION_ENABLE = "Recover Inline Dispatch Tables";
	private static final String OPTION_ENABLE_DESC =
		"Detect jr to an address built from a base plus a scaled index inside the same " +
			"function, disassemble the handler entries and register the table with the " +
			"decompiler.";

	private static final int MAX_BACK_SCAN = 16;
	private static final int MAX_TARGETS = 512;

	private boolean enabled = true;

	public MipsInlineDispatchAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor p = program.getLanguage().getProcessor();
		return p != null && "MIPS".equalsIgnoreCase(p.toString());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		if (!enabled) {
			return false;
		}

		Listing listing = program.getListing();
		FunctionManager functionMgr = program.getFunctionManager();

		int recovered = 0;
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext() && !monitor.isCancelled()) {
			Instruction jr = instructions.next();
			String mnemonic = jr.getMnemonicString();
			if (!mnemonic.equals("jr") && !mnemonic.equals("_jr")) {
				continue;
			}
			Register targetReg = jr.getRegister(0);
			if (targetReg == null || "ra".equals(targetReg.getName())) {
				continue;
			}
			Function function = functionMgr.getFunctionContaining(jr.getAddress());
			if (function == null) {
				continue;
			}
			if (recoverTable(program, function, jr, targetReg, monitor, log)) {
				recovered++;
			}
		}
		if (recovered > 0) {
			Msg.info(this, "MIPS Inline Dispatch: recovered " + recovered + " table(s)");
		}
		return recovered > 0;
	}

	private boolean recoverTable(Program program, Function function, Instruction jr,
			Register targetReg, TaskMonitor monitor, MessageLog log) {

		AddressSetView body = function.getBody();
		Instruction current = jr;
		Register baseReg = targetReg;
		long addressBase = -1;
		long baseLow = -1;
		int stride = 4;
		boolean sawAddu = false;
		boolean pointerTable = false;
		long pointerOffset = 0;

		Listing listing = program.getListing();

		for (int step = 0; step < MAX_BACK_SCAN; step++) {
			Instruction prev = listing.getInstructionBefore(current.getAddress());
			if (prev == null || !body.contains(prev.getAddress()) ||
				prev.getFlowType().isTerminal() || prev.getFlowType().isJump()) {
				break;
			}
			current = prev;

			Register written = current.getRegister(0);
			if (!sameRegister(written, baseReg)) {
				continue;
			}
			String mnemonic = current.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				mnemonic = mnemonic.substring(1);
			}

			switch (mnemonic) {
				case "addu":
				case "daddu": {
					Register rs = current.getRegister(1);
					Register rt = current.getRegister(2);
					Register other = null;
					if (sameRegister(baseReg, rs)) {
						other = rt;
					}
					else if (sameRegister(baseReg, rt)) {
						other = rs;
					}
					if (other == null) {
						return false;
					}
					if (pointerTable) {
						continue; // pointer table entry size does not depend on the index scale
					}
					int shift = findShift(listing, body, current, other);
					if (shift < 0) {
						return false;
					}
					stride = 1 << shift;
					sawAddu = true;
					continue; // keep tracking baseReg through the lower address computation
				}
				case "addiu": {
					Register rs = current.getRegister(1);
					Scalar imm = current.getScalar(2);
					if (imm == null) {
						return false;
					}
					if ("zero".equals(rs != null ? rs.getName() : null)) {
						addressBase = imm.getSignedValue();
						return finish(program, function, jr, addressBase, stride, sawAddu, monitor,
							log);
					}
					if (!sameRegister(baseReg, rs)) {
						return false;
					}
					baseLow = imm.getSignedValue();
					continue;
				}
				case "lui": {
					Scalar imm = current.getScalar(1);
					if (imm == null) {
						return false;
					}
					long hi = imm.getUnsignedValue() << 16;
					addressBase = hi + (baseLow >= 0 ? baseLow : 0);
					if (pointerTable) {
						return finishPointerTable(program, function, jr,
							addressBase + pointerOffset, monitor, log);
					}
					return finish(program, function, jr, addressBase, stride, sawAddu, monitor, log);
				}
				case "lw":
				case "ld": {
					// jr target was loaded from a pointer table in memory
					if (pointerTable) {
						return false;
					}
					Register addrReg = null;
					Scalar off = null;
					for (int i = 1; i < 3; i++) {
						for (Object obj : current.getOpObjects(i)) {
							if (obj instanceof Register r) {
								addrReg = r;
							}
							else if (obj instanceof Scalar s) {
								off = s;
							}
						}
					}
					if (addrReg == null) {
						return false;
					}
					pointerTable = true;
					pointerOffset = off != null ? off.getSignedValue() : 0;
					baseReg = addrReg;
					continue;
				}
				default:
					return false;
			}
		}

		return false;
	}

	/**
	 * Finds the shift amount applied to the specified index register by a preceding
	 * sll/dsll within the same basic block.
	 */
	private int findShift(Listing listing, AddressSetView body, Instruction from, Register index) {
		Instruction current = from;
		for (int i = 0; i < 6; i++) {
			Instruction prev = listing.getInstructionBefore(current.getAddress());
			if (prev == null || !body.contains(prev.getAddress()) ||
				prev.getFlowType().isTerminal() || prev.getFlowType().isJump()) {
				return -1;
			}
			current = prev;
			Register written = current.getRegister(0);
			if (!sameRegister(written, index)) {
				continue;
			}
			String mnemonic = current.getMnemonicString();
			if (mnemonic.startsWith("_")) {
				mnemonic = mnemonic.substring(1);
			}
			if (mnemonic.equals("sll") || mnemonic.equals("dsll")) {
				Scalar sh = current.getScalar(2);
				if (sh != null && sh.getUnsignedValue() < 5) {
					return (int) sh.getUnsignedValue();
				}
			}
			return -1;
		}
		return -1;
	}

	private boolean finish(Program program, Function function, Instruction jr, long base, int stride,
			boolean sawAddu, TaskMonitor monitor, MessageLog log) {

		if (!sawAddu) {
			return false;
		}
		AddressSetView body = function.getBody();
		AddressSpace space = jr.getAddress().getAddressSpace();
		if (!space.isValidRange(base, 1)) {
			return false;
		}
		Address baseAddr = space.getAddress(base);
		if (!body.contains(baseAddr) || baseAddr.equals(function.getEntryPoint())) {
			return false;
		}

		Address end = body.getMaxAddress();
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		ArrayList<Address> targets = new ArrayList<>();

		Instruction existing = program.getListing().getInstructionAt(jr.getAddress());
		if (existing == null) {
			return false;
		}

		Address addr = baseAddr;
		while (targets.size() < MAX_TARGETS && addr.compareTo(end) <= 0) {
			if (program.getListing().getInstructionAt(addr) == null) {
				AddressSet decoded = disassembler.disassemble(addr, null);
				if (decoded == null || decoded.isEmpty()) {
					break;
				}
			}
			targets.add(addr);
			addr = addr.add(stride);
		}
		return applyTable(program, function, jr, targets, log);
	}

	/**
	 * Handles a jr target loaded from a table of pointers in memory.  Only pointer
	 * values that land inside the containing function are accepted, which keeps
	 * ordinary data-section function pointer tables out of scope.
	 */
	private boolean finishPointerTable(Program program, Function function, Instruction jr,
			long tableBase, TaskMonitor monitor, MessageLog log) {

		AddressSetView body = function.getBody();
		AddressSpace space = jr.getAddress().getAddressSpace();
		int pointerSize = program.getDefaultPointerSize();
		if (pointerSize != 4 && pointerSize != 8) {
			return false;
		}
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, null);
		ArrayList<Address> targets = new ArrayList<>();

		for (int i = 0; i < MAX_TARGETS; i++) {
			long entryOffset = tableBase + (long) i * pointerSize;
			if (!space.isValidRange(entryOffset, pointerSize)) {
				break;
			}
			Address entryAddr = space.getAddress(entryOffset);
			long pointer;
			try {
				pointer = pointerSize == 4 ? program.getMemory().getInt(entryAddr) & 0xFFFFFFFFL
						: program.getMemory().getLong(entryAddr);
			}
			catch (Exception e) {
				break;
			}
			if (!space.isValidRange(pointer, 1)) {
				break;
			}
			Address target = space.getAddress(pointer);
			if (!body.contains(target)) {
				break;
			}
			if (program.getListing().getInstructionAt(target) == null) {
				AddressSet decoded = disassembler.disassemble(target, null);
				if (decoded == null || decoded.isEmpty()) {
					break;
				}
			}
			targets.add(target);
		}

		return applyTable(program, function, jr, targets, log);
	}

	private boolean applyTable(Program program, Function function, Instruction jr,
			ArrayList<Address> targets, MessageLog log) {

		if (targets.size() < 2) {
			return false;
		}
		try {
			JumpTable table = new JumpTable(jr.getAddress(), targets, true, 0);
			table.writeOverride(function);

			ReferenceManager refMgr = program.getReferenceManager();
			for (Address target : targets) {
				refMgr.addMemoryReference(jr.getAddress(), target, RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			}
			log.appendMsg(getName(), "Recovered inline dispatch at %s in %s (%d entries)"
					.formatted(jr.getAddress(), function.getName(), targets.size()));
			return true;
		}
		catch (Exception e) {
			Msg.warn(this, "Failed to register inline dispatch at %s: %s".formatted(
				jr.getAddress(), e.getMessage()));
			return false;
		}
	}

	private static boolean sameRegister(Register a, Register b) {
		if (a == null || b == null) {
			return false;
		}
		return a.equals(b) || a.getBaseRegister().equals(b.getBaseRegister());
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_ENABLE, enabled, null, OPTION_ENABLE_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		enabled = options.getBoolean(OPTION_ENABLE, enabled);
	}
}
