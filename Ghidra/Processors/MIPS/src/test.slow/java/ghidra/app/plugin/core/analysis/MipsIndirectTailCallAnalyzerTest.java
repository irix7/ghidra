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

import static org.junit.Assert.*;

import java.util.ArrayList;

import org.junit.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class MipsIndirectTailCallAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private Program program;
	private MipsIndirectTailCallAnalyzer analyzer = new MipsIndirectTailCallAnalyzer();

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Tail calls", ProgramBuilder._MIPS_6432);
		program = builder.getProgram();
		builder.createMemory("text", "1000", 0x1000);
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Instruction instruction(long offset) {
		return program.getListing().getInstructionAt(addr(offset));
	}

	private Function stub(String bytes, int bodySize) throws Exception {
		builder.setBytes("1000", bytes);
		builder.disassemble("1000", bytes.split(" ").length);
		return builder.createEmptyFunction("callbackStub", "1000", bodySize, null);
	}

	private boolean analyse(AddressSetView set, TaskMonitor monitor) throws Exception {
		return builder.tx(() -> analyzer.added(program, set, monitor, new MessageLog()));
	}

	private boolean analyse() throws Exception {
		return analyse(new AddressSet(addr(0x1000), addr(0x1fff)), TaskMonitor.DUMMY);
	}

	private void assertUnchanged() throws Exception {
		assertFalse(analyse());
		assertEquals(FlowOverride.NONE, instruction(0x1000).getFlowOverride());
	}

	@Test
	public void testA1StubAndIdempotence() throws Exception {
		Function function = stub("00 a0 00 08 00 00 00 00", 8); // jr a1; nop
		AddressSet body = new AddressSet(function.getBody());
		String signature = function.getSignature().toString();
		SourceType source = function.getSignatureSource();
		builder.createMemoryCallReference("1100", "1000");
		assertTrue(analyse());
		assertEquals(FlowOverride.CALL_RETURN, instruction(0x1000).getFlowOverride());
		assertTrue(instruction(0x1000).getFlowType().isCall());
		assertTrue(instruction(0x1000).getFlowType().isComputed());
		assertTrue(instruction(0x1000).getFlowType().isTerminal());
		assertNull(instruction(0x1000).getFallThrough());
		boolean call = false;
		boolean returns = false;
		for (PcodeOp op : instruction(0x1000).getPcode(true)) {
			assertNotEquals(PcodeOp.BRANCHIND, op.getOpcode());
			call |= op.getOpcode() == PcodeOp.CALLIND;
			returns |= op.getOpcode() == PcodeOp.RETURN;
		}
		assertTrue(call);
		assertTrue(returns);
		assertEquals(body, function.getBody());
		assertEquals(signature, function.getSignature().toString());
		assertEquals(source, function.getSignatureSource());
		assertEquals(0, function.getLocalVariables().length);
		assertTrue(instruction(0x1004).isInDelaySlot());
		assertFalse(analyse());
	}

	@Test
	public void testA2StubWithPartialInstructionSet() throws Exception {
		stub("00 c0 00 08 00 00 00 00", 8); // jr a2; nop
		assertTrue(analyse(new AddressSet(addr(0x1000)), TaskMonitor.DUMMY));
		assertEquals(FlowOverride.CALL_RETURN, instruction(0x1000).getFlowOverride());
	}

	@Test
	public void testMips32Stub() throws Exception {
		builder.dispose();
		builder = new ProgramBuilder("Tail calls 32", ProgramBuilder._MIPS);
		program = builder.getProgram();
		builder.createMemory("text", "1000", 0x1000);
		stub("00 a0 00 08 00 00 00 00", 8);
		assertTrue(analyse());
	}

	@Test
	public void testReturnRegister() throws Exception {
		stub("03 e0 00 08 00 00 00 00", 8); // jr ra; nop
		assertUnchanged();
	}

	@Test
	public void testOtherTargetRegister() throws Exception {
		stub("03 20 00 08 00 00 00 00", 8); // jr t9; nop
		assertUnchanged();
	}

	@Test
	public void testNonNopDelaySlot() throws Exception {
		stub("00 c0 00 08 24 02 00 01", 8); // jr a2; li v0,1
		assertUnchanged();
	}

	@Test
	public void testInlineCacheReturnTable() throws Exception {
		stub("00 c0 00 08 00 00 00 00 00 c0 00 08 00 00 00 00", 16);
		assertUnchanged();
		assertEquals(FlowOverride.NONE, instruction(0x1008).getFlowOverride());
	}

	@Test
	public void testTargetComputedBeforeJump() throws Exception {
		stub("3c 05 00 00 24 a5 10 00 00 a0 00 08 00 00 00 00", 16);
		assertFalse(analyse());
		assertEquals(FlowOverride.NONE, instruction(0x1008).getFlowOverride());
	}

	@Test
	public void testSharedTailEntry() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		builder.createMemoryJumpReference("1100", "1000");
		assertUnchanged();
	}

	@Test
	public void testDelaySlotEntryReference() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		builder.createMemoryCallReference("1100", "1004");
		assertUnchanged();
	}

	@Test
	public void testSingleResolvedJumpTarget() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		Reference reference = builder.createMemoryReference("1000", "1200",
			RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
		assertUnchanged();
		assertEquals(reference, program.getReferenceManager().getReferencesFrom(addr(0x1000))[0]);
	}

	@Test
	public void testSwitchOverrideWithoutReferences() throws Exception {
		Function function = stub("00 a0 00 08 00 00 00 00", 8);
		ArrayList<Address> targets = new ArrayList<>();
		targets.add(addr(0x1200));
		targets.add(addr(0x1300));
		builder.tx(() -> new JumpTable(addr(0x1000), targets, true, 0).writeOverride(function));
		assertUnchanged();
	}

	@Test
	public void testSwitchCaseWithoutReferences() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		Function dispatcher = builder.createEmptyFunction("dispatcher", "1100", 8, null);
		ArrayList<Address> targets = new ArrayList<>();
		targets.add(addr(0x1000));
		targets.add(addr(0x1200));
		builder.tx(() -> new JumpTable(addr(0x1100), targets, true, 0).writeOverride(dispatcher));
		assertUnchanged();
	}

	@Test
	public void testExistingFlowOverride() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		builder.tx(() -> instruction(0x1000).setFlowOverride(FlowOverride.RETURN));
		assertFalse(analyse());
		assertEquals(FlowOverride.RETURN, instruction(0x1000).getFlowOverride());
	}

	@Test
	public void testIncompleteBody() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 4);
		assertUnchanged();
	}

	@Test
	public void testDisjointBody() throws Exception {
		Function function = stub("00 a0 00 08 00 00 00 00", 8);
		AddressSet body = new AddressSet(addr(0x1000), addr(0x1003));
		body.add(addr(0x1100), addr(0x1103));
		builder.tx(() -> function.setBody(body));
		assertUnchanged();
	}

	@Test
	public void testMissingFunction() throws Exception {
		builder.setBytes("1000", "00 a0 00 08 00 00 00 00");
		builder.disassemble("1000", 8);
		assertUnchanged();
	}

	@Test
	public void testFallThroughIntoStub() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		builder.createMemory("previous", "ffc", 4);
		builder.setBytes("ffc", "00 00 00 00");
		builder.disassemble("ffc", 4);
		assertUnchanged();
	}

	@Test
	public void testThunkIsNotChanged() throws Exception {
		Function function = stub("00 a0 00 08 00 00 00 00", 8);
		Function target = builder.createEmptyFunction("target", "1200", 8, null);
		builder.tx(() -> function.setThunkedFunction(target));
		assertUnchanged();
	}

	@Test
	public void testNonMipsIsNotEnabled() throws Exception {
		builder.dispose();
		builder = new ProgramBuilder("Other processor", ProgramBuilder._X86);
		program = builder.getProgram();
		assertFalse(analyzer.canAnalyze(program));
		assertFalse(analyzer.getDefaultEnablement(program));
		assertFalse(analyse());
	}

	@Test(expected = CancelledException.class)
	public void testCancellation() throws Exception {
		stub("00 a0 00 08 00 00 00 00", 8);
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		analyzer.added(program, new AddressSet(addr(0x1000)), monitor, new MessageLog());
	}
}
