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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Types the flow of bare MIPS argument-register callback stubs as indirect tail calls.
 * Inspired by upstream PR #8547, but does not infer a callback prototype from the
 * wrapper's parameter count or persist guessed types as user-defined variables.
 */
public class MipsIndirectTailCallAnalyzer extends AbstractAnalyzer {

	public MipsIndirectTailCallAnalyzer() {
		super("MIPS Indirect Tail Calls",
			"Types bare jr a1/a2 callback stubs as computed call terminators",
			AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return "MIPS".equalsIgnoreCase(program.getLanguage().getProcessor().toString());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (!canAnalyze(program)) {
			return false;
		}
		boolean changed = false;
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();
		InstructionIterator instructions = listing.getInstructions(set, true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction jump = instructions.next();
			if (!"jr".equals(jump.getMnemonicString()) || jump.isInDelaySlot() ||
				jump.getLength() != 4 || jump.getDelaySlotDepth() != 1 ||
				jump.getFlowOverride() != FlowOverride.NONE || jump.getFallFrom() != null) {
				continue;
			}
			Register target = jump.getRegister(0);
			if (target == null ||
				!("a1".equals(target.getName()) || "a2".equals(target.getName()))) {
				continue;
			}
			Function function = program.getFunctionManager().getFunctionAt(jump.getAddress());
			if (function == null || function.isThunk() || function.getBody().getNumAddresses() != 8 ||
				!function.getBody().contains(jump.getAddress(), jump.getAddress().add(7))) {
				continue;
			}
			Instruction delay = listing.getInstructionAt(jump.getAddress().add(4));
			if (delay == null || !delay.isInDelaySlot() || delay.getLength() != 4 ||
				!"_nop".equals(delay.getMnemonicString()) ||
				delay.getFlowOverride() != FlowOverride.NONE) {
				continue;
			}

			// A shared tail or a switch case can have exactly the same two instructions.
			boolean ambiguous = false;
			for (Reference reference : references.getReferencesFrom(jump.getAddress())) {
				if (reference.getReferenceType().isFlow()) {
					ambiguous = true;
				}
			}
			ReferenceIterator incoming = references.getReferencesTo(jump.getAddress());
			while (incoming.hasNext()) {
				if (incoming.next().getReferenceType().isJump()) {
					ambiguous = true;
				}
			}
			if (references.hasReferencesTo(delay.getAddress())) {
				ambiguous = true;
			}
			for (Symbol symbol : program.getSymbolTable().getSymbols(jump.getAddress())) {
				// Decompiler switch overrides can exist without flow references.
				if (symbol.getParentNamespace().getName().startsWith("jmp_") &&
					("switch".equals(symbol.getName()) || symbol.getName().startsWith("case_"))) {
					ambiguous = true;
				}
			}
			if (ambiguous) {
				continue;
			}
			jump.setFlowOverride(FlowOverride.CALL_RETURN);
			log.appendMsg(getName(), "Typed indirect tail call at " + jump.getAddress());
			changed = true;
		}
		return changed;
	}
}
