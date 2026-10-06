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

import org.junit.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MipsGotAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	// GOT window: gp = 0x18000 -> [0x10010, 0x1fff0]
	private static final String GP_ADDR = "18000";

	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("got", ProgramBuilder._MIPS);
		builder.createMemory(".got", "10000", 0x100);
		builder.createMemory(".text", "20000", 0x100);
		builder.createMemory(".stubs", "21000", 0x100);
		builder.createMemory(".data", "22000", 0x100);
		builder.createEmptyFunction("memcpy", "20000", 8, null);
		builder.tx(() -> builder.getProgram()
				.getFunctionManager()
				.createThunkFunction("printf@plt", null, builder.addr("21000"),
					new AddressSet(builder.addr("21000")),
					builder.getProgram().getFunctionManager().getFunctionAt(builder.addr("20000")),
					SourceType.IMPORTED));
		// Named data target.
		builder.applyDataType("22000", new ByteDataType());
		builder.tx(() -> builder.getProgram()
				.getSymbolTable()
				.createLabel(builder.addr("22000"), "__iob", SourceType.IMPORTED));
		// Unnamed data target.
		builder.applyDataType("22020", new ByteDataType());

		addSlot("10010", "PTR_FUN_memcpy_10010", SourceType.IMPORTED, "20000");
		addSlot("10014", "PTR_FUN_printf_10014", SourceType.IMPORTED, "21000");
		addSlot("10018", "PTR_DAT_10018", SourceType.IMPORTED, "22000");
		addSlot("1001c", "PTR_user_1001c", SourceType.USER_DEFINED, "20000");
		addSlot("10020", null, null, "20000");
		addSlot("10024", "PTR_DAT_10024", SourceType.IMPORTED, "22020");
		addSlot("10028", "PTR_FUN_memcpy2_10028", SourceType.IMPORTED, "20000");
		addSlot("1002c", "__DT_PLTGOT", SourceType.IMPORTED, "20000");
	}

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	private void addSlot(String slotAddr, String label, SourceType source, String targetAddr)
			throws Exception {
		long target = Long.parseLong(targetAddr, 16);
		String bytes = String.format("%08x", target);
		builder.setBytes(slotAddr, bytes);
		builder.applyDataType(slotAddr, new Pointer32DataType());
		if (label != null) {
			builder.tx(() -> builder.getProgram()
					.getSymbolTable()
					.createLabel(builder.addr(slotAddr), label, source));
		}
		builder.createMemoryReference(slotAddr, targetAddr, RefType.DATA, SourceType.ANALYSIS, 0);
	}

	private boolean runAnalyzer() {
		return builder.tx(() -> new MipsGotAnalyzer().added(builder.getProgram(),
			builder.getProgram().getMemory(), TaskMonitor.DUMMY, new MessageLog()));
	}

	private void addGpSymbol(String name) throws Exception {
		builder.tx(() -> builder.getProgram()
				.getSymbolTable()
				.createLabel(builder.addr(GP_ADDR), name, SourceType.IMPORTED));
	}

	private Symbol symbolAt(String addr) {
		return builder.getProgram().getSymbolTable().getPrimarySymbol(builder.addr(addr));
	}

	@Test
	public void testNamesFunctionAndDataSlots() throws Exception {
		addGpSymbol("_mips_gp_value");
		MipsGotAnalyzer analyzer = new MipsGotAnalyzer();
		assertTrue(analyzer.canAnalyze(builder.getProgram()));
		assertTrue(runAnalyzer());

		Symbol slot = symbolAt("10010");
		assertEquals("__got_memcpy", slot.getName());
		assertEquals(SourceType.IMPORTED, slot.getSource());
		assertEquals("__got_printf@plt", symbolAt("10014").getName());
		assertEquals("__got___iob", symbolAt("10018").getName());
	}

	@Test
	public void testSkipsUserDefinedAndAutoLabels() throws Exception {
		addGpSymbol("_mips_gp0_value");
		boolean changed = runAnalyzer();
		assertTrue(changed);

		// User-defined label preserved even though it has a PTR_ prefix.
		assertEquals("PTR_user_1001c", symbolAt("1001c").getName());
		// No label, no rename.
		assertNull(symbolAt("10020"));
		// Auto-labelled target (no symbol at target, no function) left alone.
		assertEquals("PTR_DAT_10024", symbolAt("10024").getName());
		// Collision: __got_memcpy already taken by the 10010 slot.
		assertEquals("PTR_FUN_memcpy2_10028", symbolAt("10028").getName());
		// Loader-named (IMPORTED) slot without PTR_ prefix left alone.
		assertEquals("__DT_PLTGOT", symbolAt("1002c").getName());
	}

	@Test
	public void testIdempotent() throws Exception {
		addGpSymbol("_mips_gp_value");
		assertTrue(runAnalyzer());
		assertFalse(runAnalyzer());
		assertEquals("__got_memcpy", symbolAt("10010").getName());
	}

	@Test
	public void testNoGpSymbolNoAnalysis() throws Exception {
		MipsGotAnalyzer analyzer = new MipsGotAnalyzer();
		assertFalse(analyzer.canAnalyze(builder.getProgram()));
		addGpSymbol("_mips_gp_value");
		assertTrue(analyzer.canAnalyze(builder.getProgram()));
	}
}
