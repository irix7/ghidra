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
package ghidra.app.decompiler;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

@RunWith(Parameterized.class)
public class MipsDelaySlotFlowTest extends AbstractGhidraHeadlessIntegrationTest {

	@Parameters(name = "{0}")
	public static List<String> languages() {
		return List.of(ProgramBuilder._MIPS, ProgramBuilder._MIPS_6432);
	}

	private final String language;
	private ProgramBuilder builder;
	private DecompInterface decompiler;

	public MipsDelaySlotFlowTest(String language) {
		this.language = language;
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Delay slot entries", language);
		builder.createMemory("text", "1000", 0x100);
		decompiler = new DecompInterface();
	}

	@After
	public void tearDown() {
		decompiler.dispose();
		builder.dispose();
	}

	private void predecessor(String bytes) throws Exception {
		// The slot is also an independent entry: li v0,7; jr ra; nop.
		builder.setBytes("1000", bytes + " 24 02 00 07 03 e0 00 08 00 00 00 00");
		builder.setBytes("1020", "24 42 00 01 03 e0 00 08 00 00 00 00");
		builder.disassemble("1000", 8, false);
		builder.disassemble("1008", 8, false);
		builder.disassemble("1020", 12, false);
		Instruction slot = builder.getProgram().getListing().getInstructionAt(builder.addr("1004"));
		assertTrue(slot.isInDelaySlot());
		assertEquals(builder.addr("1008"), slot.getFallThrough());
		assertEquals(PcodeOp.COPY, slot.getPcode()[0].getOpcode());
	}

	private String decompile(Function function) {
		assertTrue(decompiler.openProgram(builder.getProgram()));
		DecompileResults result = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
		assertTrue(result.getErrorMessage(), result.decompileCompleted());
		return result.getDecompiledFunction().getC();
	}

	@Test
	public void testEntryInUnconditionalJumpSlot() throws Exception {
		predecessor("08 00 04 08"); // j 1020
		Function entry = builder.createEmptyFunction("slotEntry", "1004", 12, null);
		assertEquals(new AddressSet(builder.addr("1004"), builder.addr("100f")),
			CreateFunctionCmd.getFunctionBody(builder.getProgram(), builder.addr("1004")));
		assertTrue(decompile(entry).contains("return 7;"));
		CodeBlock block = new BasicBlockModel(builder.getProgram())
			.getCodeBlockAt(builder.addr("1004"), TaskMonitor.DUMMY);
		assertEquals(builder.addr("1004"), block.getFirstStartAddress());
		assertEquals(0, block.getNumDestinations(TaskMonitor.DUMMY));
	}

	@Test
	public void testEntryInIndirectJumpSlotAfterSharedReturnAnalysis() throws Exception {
		predecessor("03 20 00 08"); // jr t9, as in #4675
		Function target = builder.createEmptyFunction("target", "1020", 12, null);
		builder.createMemoryReference("1000", "1020", RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
		Function entry = builder.createEmptyFunction("slotEntry", "1004", 12, null);
		builder.tx(() -> new SharedReturnAnalysisCmd(target.getBody(), false, false)
			.applyTo(builder.getProgram(), TaskMonitor.DUMMY));
		assertEquals(FlowOverride.CALL_RETURN,
			builder.getProgram().getListing().getInstructionAt(builder.addr("1000")).getFlowOverride());
		assertEquals(FlowOverride.NONE,
			builder.getProgram().getListing().getInstructionAt(builder.addr("1004")).getFlowOverride());
		String c = decompile(entry);
		assertTrue(c, c.contains("return 7;"));
		assertFalse(c, c.contains("UNRECOVERED_JUMPTABLE"));
	}

	@Test
	public void testEntryInConditionalBranchSlotDecompiles() throws Exception {
		predecessor("10 a0 00 07"); // beq a1,zero,1020
		Function entry = builder.createEmptyFunction("slotEntry", "1004", 12, null);
		assertEquals(new AddressSet(builder.addr("1004"), builder.addr("100f")),
			CreateFunctionCmd.getFunctionBody(builder.getProgram(), builder.addr("1004")));
		assertTrue(decompile(entry).contains("return 7;"));
	}

	@Test
	public void testBranchIntoSlotWithoutExecutingPredecessor() throws Exception {
		predecessor("08 00 04 08");
		// beq a0,zero,1004; nop; li v0,9; jr ra; nop
		builder.setBytes("1040", "10 80 ff f0 00 00 00 00 24 02 00 09 03 e0 00 08 00 00 00 00");
		builder.disassemble("1040", 20, false);
		Function function = builder.createEmptyFunction("branchIntoSlot", "1040", 20, null);
		AddressSet body = new AddressSet(function.getBody());
		body.add(builder.addr("1004"), builder.addr("100f"));
		builder.tx(() -> function.setBody(body));
		String c = decompile(function);
		assertTrue(c, c.contains("return 7;"));
		assertTrue(c, c.contains("return 9;"));
		assertFalse(c, c.contains("overlaps instruction"));
	}

	@Test
	public void testBothEntryPathsProduceCorrectValuesWithOverlapWarning() throws Exception {
		predecessor("08 00 04 08");
		// beq a0,zero,1004; nop; j 1000; nop
		builder.setBytes("1040", "10 80 ff f0 00 00 00 00 08 00 04 00 00 00 00 00");
		builder.disassemble("1040", 16, false);
		Function function = builder.createEmptyFunction("bothEntries", "1040", 16, null);
		AddressSet body = new AddressSet(function.getBody());
		body.add(builder.addr("1000"), builder.addr("100f"));
		body.add(builder.addr("1020"), builder.addr("102b"));
		builder.tx(() -> function.setBody(body));
		String c = decompile(function);
		assertTrue(c, c.contains("return 7;"));
		assertTrue(c, c.contains("return 8;"));
		// Bundled jump/slot p-code is still diagnosed as overlapping instructions.
		assertTrue(c, c.contains("overlaps instruction"));
	}

	@Ignore("Known limitation: block models merge a conditional branch and its independently entered slot")
	@Test
	public void testConditionalSlotEntryHasIndependentBlockFlow() throws Exception {
		predecessor("10 a0 00 07");
		builder.createEmptyFunction("slotEntry", "1004", 12, null);
		BasicBlockModel model = new BasicBlockModel(builder.getProgram());
		model.getCodeBlockAt(builder.addr("1000"), TaskMonitor.DUMMY);
		CodeBlock block = model.getCodeBlockAt(builder.addr("1004"), TaskMonitor.DUMMY);
		assertEquals("Direct entry must not inherit the preceding branch", builder.addr("1004"),
			block.getFirstStartAddress());
		assertEquals(0, block.getNumDestinations(TaskMonitor.DUMMY));
	}
}
