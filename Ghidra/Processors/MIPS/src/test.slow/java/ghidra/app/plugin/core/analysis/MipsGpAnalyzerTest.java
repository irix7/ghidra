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

import java.math.BigInteger;

import org.junit.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MipsGpAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("gp seed", ProgramBuilder._MIPS);
		builder.createMemory(".text", "1000", 0x100);
		builder.createMemory(".MIPS.options", "2000", 0x18);
		builder.createEmptyFunction("func_a", "1000", 12, null);
		builder.createEmptyFunction("func_b", "1020", 12, null);
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testSeedsGpAndT9AtFunctionEntries() throws Exception {
		builder.getProgram()
				.getSymbolTable()
				.createLabel(builder.addr("2100"), "_mips_gp_value", SourceType.IMPORTED);
		MipsGpAnalyzer analyzer = new MipsGpAnalyzer();
		assertTrue(analyzer.canAnalyze(builder.getProgram()));
		boolean changed = builder.tx(() -> analyzer.added(builder.getProgram(),
			builder.getProgram().getMemory(), TaskMonitor.DUMMY, new MessageLog()));
		assertTrue(changed);

		Register gp = builder.getProgram().getLanguage().getRegister("gp");
		Register t9 = builder.getProgram().getLanguage().getRegister("t9");
		var ctx = builder.getProgram().getProgramContext();
		assertEquals(BigInteger.valueOf(0x2100), ctx.getValue(gp, builder.addr("1000"), false));
		assertEquals(BigInteger.valueOf(0x1000), ctx.getValue(t9, builder.addr("1000"), false));
		assertEquals(BigInteger.valueOf(0x2100), ctx.getValue(gp, builder.addr("1020"), false));
		assertEquals(BigInteger.valueOf(0x1020), ctx.getValue(t9, builder.addr("1020"), false));
	}

	@Test
	public void testSkipsThunksAndExternals() throws Exception {
		builder.getProgram()
				.getSymbolTable()
				.createLabel(builder.addr("2100"), "_mips_gp0_value", SourceType.IMPORTED);
		Function thunk = builder.tx(
			() -> builder.getProgram()
					.getFunctionManager()
					.createThunkFunction("thunk1", null, builder.addr("1020"),
						new AddressSet(builder.addr("1020")), builder.getProgram()
								.getFunctionManager()
								.getFunctionAt(builder.addr("1000")),
						SourceType.IMPORTED));
		assertNotNull(thunk);
		MipsGpAnalyzer analyzer = new MipsGpAnalyzer();
		builder.tx(() -> analyzer.added(builder.getProgram(), builder.getProgram().getMemory(),
			TaskMonitor.DUMMY, new MessageLog()));
		var ctx = builder.getProgram().getProgramContext();
		Register gp = builder.getProgram().getLanguage().getRegister("gp");
		assertNull(ctx.getValue(gp, builder.addr("1020"), false));
	}

	@Test
	public void testNoGpSymbolNoAnalysis() {
		assertFalse(new MipsGpAnalyzer().canAnalyze(builder.getProgram()));
	}
}
