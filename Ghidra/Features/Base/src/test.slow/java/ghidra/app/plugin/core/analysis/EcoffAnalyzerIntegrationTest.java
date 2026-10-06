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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.ecoff.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class EcoffAnalyzerIntegrationTest extends AbstractGhidraHeadlessIntegrationTest {
	private ProgramDB program;
	private int transaction;

	@Before
	public void setUp() throws Exception {
		var language = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("MIPS:BE:32:default"));
		program =
			new ProgramDB("synthetic ECOFF", language, language.getDefaultCompilerSpec(), this);
		transaction = program.startTransaction("synthetic ECOFF");
		var text = program.getMemory().createInitializedBlock(
			".text", addr(0x1000), 0x100, (byte)0, TaskMonitor.DUMMY, false);
		text.setExecute(true);
		program.getMemory().createInitializedBlock(
			".data", addr(0x2000), 0x100, (byte)0, TaskMonitor.DUMMY, false);
		program.getMemory().createUninitializedBlock(".bss", addr(0x3000), 0x100, false);
		// jr ra; nop, with another two nops inside the explicit debug range.
		program.getMemory().setBytes(addr(0x1000), new byte[] {3, (byte)0xe0, 0, 8, 0, 0, 0, 0});
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.endTransaction(transaction, true);
			program.release(this);
		}
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void importBytes(byte[] bytes) throws Exception {
		EcoffDebug debug = EcoffDebug.parse(
			new ByteArrayProvider(bytes), EcoffDebugTest.ORIGIN, false, TaskMonitor.DUMMY);
		new EcoffAnalyzer().importDebug(program, false, debug, TaskMonitor.DUMMY, new MessageLog());
	}

	private void importBytesWithParameters(byte[] bytes) throws Exception {
		EcoffDebug debug = EcoffDebug.parse(
			new ByteArrayProvider(bytes), EcoffDebugTest.ORIGIN, false, TaskMonitor.DUMMY);
		MessageLog log = new MessageLog();
		new EcoffAnalyzer().importDebug(program, false, debug, TaskMonitor.DUMMY, log);
		importLog = log.toString();
	}

	private String importLog;

	private List<EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> importBodies(
		byte[] bytes) throws Exception {
		EcoffDebug debug = EcoffDebug.parse(
			new ByteArrayProvider(bytes), EcoffDebugTest.ORIGIN, false, TaskMonitor.DUMMY);
		return new EcoffAnalyzer().importDebug(
			program, false, debug, TaskMonitor.DUMMY, new MessageLog());
	}

	@Test
	public void testFunctionsRangesSourceSymbolsAndTypedefs() throws Exception {
		importBytes(EcoffDebugTest.fixture(false, true));
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals("run", function.getName());
		assertEquals(SourceType.IMPORTED, function.getSymbol().getSource());
		assertEquals(new AddressSet(addr(0x1000), addr(0x100f)), function.getBody());
		assertEquals("ECOFF source: a.c", function.getRepeatableComment());
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(Undefined.isUndefined(function.getReturnType()));
		assertEquals("counter", program.getSymbolTable().getPrimarySymbol(addr(0x2000)).getName());
		assertTrue(program.getListing().getDataAt(addr(0x2000)).getDataType() instanceof Pointer);
		assertTrue(program.getDataTypeManager().getDataType(new CategoryPath("/ECOFF"), "word")
					   instanceof TypeDef);
	}

	@Test
	public void testProcedureParametersAndLocalsAreImported() throws Exception {
		importBytesWithParameters(EcoffDebugTest.fixtureWithParameters(false, true));
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals("run", function.getName());
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		Parameter[] params = function.getParameters();
		assertEquals(2, params.length);
		assertEquals("alpha", params[0].getName());
		assertEquals(SourceType.IMPORTED, params[0].getSource());
		assertTrue(params[0].getVariableStorage().isRegisterStorage());
		assertEquals("a0", params[0].getVariableStorage().getRegister().getName());
		assertEquals("int", params[0].getDataType().getName());
		assertEquals("beta", params[1].getName());
		assertTrue(params[1].getVariableStorage().isStackStorage());
		assertEquals(16, params[1].getVariableStorage().getStackOffset());
		assertTrue(params[1].getDataType() instanceof Pointer);
		Function hidden = program.getFunctionManager().getFunctionAt(addr(0x1040));
		assertNotNull(hidden);
		assertEquals("hidden", hidden.getName());
		assertEquals(0, hidden.getParameterCount());
		assertEquals(SourceType.DEFAULT, hidden.getSignatureSource());
		assertTrue(importLog.contains("2 parameter(s) imported"));
	}

	@Test
	public void testParameterImportNeverOverwritesUserDefinedSignature() throws Exception {
		Function function = program.getFunctionManager().createFunction("run", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x100f)), SourceType.USER_DEFINED);
		function.setReturnType(DoubleDataType.dataType, SourceType.USER_DEFINED);
		importBytesWithParameters(EcoffDebugTest.fixtureWithParameters(false, true));
		assertEquals(0, function.getParameterCount());
		assertEquals("double", function.getReturnType().getName());
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
	}

	@Test
	public void testParameterImportNeverOverwritesUserDefinedParameters() throws Exception {
		Function function = program.getFunctionManager().createFunction("run", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x100f)), SourceType.IMPORTED);
		Parameter user = new ParameterImpl("mine", Undefined4DataType.dataType, 4, program,
			SourceType.USER_DEFINED);
		function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, false,
			SourceType.USER_DEFINED, user);
		importBytesWithParameters(EcoffDebugTest.fixtureWithParameters(false, true));
		Parameter[] params = function.getParameters();
		assertEquals(1, params.length);
		assertEquals("mine", params[0].getName());
		assertEquals(SourceType.USER_DEFINED, params[0].getSource());
	}

	@Test
	public void testDuplicateParameterNamesAbandonTheWholeImport() throws Exception {
		byte[] bytes = EcoffDebugTest.fixtureWithParameters(false, true);
		// Rename beta to alpha: the parameter list is rejected, so nothing is applied.
		System.arraycopy("alpha\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0,
			bytes, EcoffDebugTest.PSS + 18, 6);
		importBytesWithParameters(bytes);
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals(0, function.getParameterCount());
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(importLog.contains("ECOFF parameters run"));
	}

	@Test
	public void testExecAbsoluteStaticsLabelsAndStaticProceduresAreNamed() throws Exception {
		importBytesWithParameters(EcoffDebugTest.fixtureWithParameters(false, true));
		assertNotNull(program.getSymbolTable().getGlobalSymbol("note", addr(0x1050)));
		assertNotNull(program.getSymbolTable().getGlobalSymbol("counter", addr(0x2000)));
		assertTrue(program.getListing().getDataAt(addr(0x2000)).getDataType() instanceof Pointer);
		assertNotNull(program.getSymbolTable().getGlobalSymbol("external", addr(0x3000)));
		// The static procedure becomes a function, not merely a label.
		Function hidden = program.getFunctionManager().getFunctionAt(addr(0x1040));
		assertNotNull(hidden);
		assertEquals(SourceType.IMPORTED, hidden.getSymbol().getSource());
	}

	@Test
	public void testUserFunctionAndSignatureArePreserved() throws Exception {
		Function function = program.getFunctionManager().createFunction("user_name", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x1007)), SourceType.USER_DEFINED);
		function.setReturnType(DoubleDataType.dataType, SourceType.USER_DEFINED);
		function.setRepeatableComment("user source");
		importBytes(EcoffDebugTest.fixture(false, true));
		assertEquals("user_name", function.getName());
		assertEquals("double", function.getReturnType().getName());
		assertEquals("user source", function.getRepeatableComment());
		assertEquals(new AddressSet(addr(0x1000), addr(0x1007)), function.getBody());
		assertNotNull(program.getSymbolTable().getGlobalSymbol("run", addr(0x1000)));
	}

	@Test
	public void testAssemblyDoesNotLockEmptySignature() throws Exception {
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		bytes[EcoffDebugTest.FD + 60] = 3 << 3 | 1;
		importBytes(bytes);
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(Undefined.isUndefined(function.getReturnType()));
	}

	@Test
	public void testLateBodyFixupRestoresFlowClippedEcoffBody() throws Exception {
		// beq over a nop, then jr ra: clearing the nop leaves flow-reachable code on both
		// sides, so a flow-derived body drops the cleared address like the late pipeline
		// analyzers do to ECOFF ranges.
		program.getMemory().setBytes(addr(0x1000), new byte[] {0x10, 0, 0, 2, 0, 0, 0, 0, 0,
			0, 0, 0, 3, (byte) 0xe0, 0, 8});
		List<EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> authored =
			importBodies(EcoffDebugTest.fixture(false, true));
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		AddressSet expected = new AddressSet(addr(0x1000), addr(0x100f));
		assertEquals(expected, function.getBody());
		assertEquals(1, authored.size());
		assertEquals(addr(0x1000), authored.get(0).entry());
		assertEquals(expected, authored.get(0).body());
		program.getListing().clearCodeUnits(addr(0x1008), addr(0x1008), false);
		CreateFunctionCmd.fixupFunctionBody(program, function, TaskMonitor.DUMMY);
		assertFalse(expected.equals(function.getBody()));
		assertTrue(new EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer(authored).added(
			program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(expected, function.getBody());
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(Undefined.isUndefined(function.getReturnType()));
	}

	@Test
	public void testLateBodyFixupNeverCarvesOwnedBodies() throws Exception {
		List<EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> authored =
			importBodies(EcoffDebugTest.fixture(false, true));
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		AddressSet expected = new AddressSet(addr(0x1000), addr(0x100f));
		// A later analyzer clips the ECOFF body and owns the freed range; restoring the
		// authoritative range must not carve that owned body.
		AddressSet ownedRange = new AddressSet(addr(0x1008), addr(0x100b));
		function.setBody(expected.subtract(ownedRange));
		Function nested = program.getFunctionManager().createFunction("nested", addr(0x1008),
			ownedRange, SourceType.USER_DEFINED);
		List<String> warnings = new ArrayList<>();
		EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.apply(program, authored, warnings::add);
		assertEquals(expected.subtract(ownedRange), function.getBody());
		assertEquals(ownedRange, nested.getBody());
		assertEquals(1, warnings.size());
	}

	@Test
	public void testLateBodyFixupSkipsUserOwnedAndMissingFunctions() throws Exception {
		List<EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.FunctionBodyInfo> authored =
			importBodies(EcoffDebugTest.fixture(false, true));
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		function.setName("user_name", SourceType.USER_DEFINED);
		AddressSet clipped = new AddressSet(addr(0x1000), addr(0x1007));
		function.setBody(clipped);
		program.getFunctionManager().removeFunction(addr(0x1000));
		List<String> warnings = new ArrayList<>();
		EcoffAnalyzer.EcoffFunctionBodyFixupAnalyzer.apply(program, authored, warnings::add);
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x1000)));
		assertTrue(warnings.isEmpty());
	}

	@Test
	public void testOverlappingFunctionAndExistingDataAreNotRemoved() throws Exception {
		Function nested = program.getFunctionManager().createFunction("nested", addr(0x1008),
			new AddressSet(addr(0x1008), addr(0x100b)), SourceType.USER_DEFINED);
		program.getListing().createData(addr(0x2000), DoubleDataType.dataType);
		importBytes(EcoffDebugTest.fixture(false, true));
		assertEquals(nested, program.getFunctionManager().getFunctionAt(addr(0x1008)));
		assertEquals(
			"double", program.getListing().getDataAt(addr(0x2000)).getDataType().getName());
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals("run", function.getName());
		assertFalse(function.getBody().contains(addr(0x1008)));
		assertEquals(new AddressSet(addr(0x1008), addr(0x100b)), nested.getBody());
	}

	@Test
	public void testEnclosingUserFunctionIsNotCarved() throws Exception {
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x103f)), SourceType.USER_DEFINED);
		program.getMemory().setBytes(addr(0x1008),
			new byte[] {3, (byte) 0xe0, 0, 8, 0, 0, 0, 0});
		for (boolean sized : new boolean[] {true, false}) {
			byte[] bytes = EcoffDebugTest.fixture(false, true);
			ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.SYM + 12 + 4, 0x1008);
			if (!sized) {
				ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.AUX, 0);
			}
			importBytes(bytes);
			assertNull(program.getFunctionManager().getFunctionAt(addr(0x1008)));
			assertEquals(new AddressSet(addr(0x1000), addr(0x103f)), owner.getBody());
			assertEquals("owned", owner.getName());
			assertEquals(SourceType.USER_DEFINED, owner.getSymbol().getSource());
			assertNotNull(program.getSymbolTable().getGlobalSymbol("run", addr(0x1008)));
		}
	}

	@Test
	public void testUnknownSizeJumpDoesNotDisassembleOwnedUndefinedBytes() throws Exception {
		AddressSet ownedBody = new AddressSet(addr(0x1080), addr(0x108f));
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1080),
			ownedBody, SourceType.USER_DEFINED);
		program.getMemory().setBytes(addr(0x1000),
			new byte[] {8, 0, 4, 0x20, 0, 0, 0, 0}); // j 1080; nop
		program.getMemory().setBytes(addr(0x1080),
			new byte[] {3, (byte) 0xe0, 0, 8, 0, 0, 0, 0});
		assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
		assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.SYM + 24 + 4, 0);
		importBytes(bytes);
		Function recovered = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(recovered);
		assertNotNull(program.getListing().getInstructionAt(addr(0x1000)));
		assertNotNull(program.getListing().getInstructionAt(addr(0x1004)));
		assertFalse(recovered.getBody().intersects(ownedBody));
		assertEquals(ownedBody, owner.getBody());
		assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
		assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
		assertEquals("owned", owner.getName());
		assertEquals(SourceType.USER_DEFINED, owner.getSymbol().getSource());
	}

	@Test
	public void testImportedPlaceholderExpansionDisassemblesSafely() throws Exception {
		Function placeholder = program.getFunctionManager().createFunction("run", addr(0x1000),
			new AddressSet(addr(0x1000)), SourceType.IMPORTED);
		AddressSet ownedBody = new AddressSet(addr(0x1008), addr(0x100b));
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1008),
			ownedBody, SourceType.USER_DEFINED);
		assertNull(program.getListing().getInstructionAt(addr(0x1000)));
		importBytes(EcoffDebugTest.fixture(false, true));
		assertEquals(placeholder, program.getFunctionManager().getFunctionAt(addr(0x1000)));
		assertEquals(new AddressSet(addr(0x1000), addr(0x100f)).subtract(ownedBody),
			placeholder.getBody());
		assertNotNull(program.getListing().getInstructionAt(addr(0x1000)));
		assertNotNull(program.getListing().getInstructionAt(addr(0x1004)));
		assertEquals(ownedBody, owner.getBody());
		assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
		assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
	}

	@Test
	public void testExistingImportedNonPlaceholderBodyAndListingArePreserved() throws Exception {
		AddressSet ownedBody = new AddressSet(addr(0x1000), addr(0x1007));
		Function owner = program.getFunctionManager().createFunction("run", addr(0x1000),
			ownedBody, SourceType.IMPORTED);
		importBytes(EcoffDebugTest.fixture(false, true));
		assertEquals(ownedBody, owner.getBody());
		assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
		assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
	}

	@Test
	public void testDelaySlotCannotDecodeIntoOwnedUndefinedBytes() throws Exception {
		AddressSet ownedBody = new AddressSet(addr(0x1004), addr(0x100b));
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1004),
			ownedBody, SourceType.USER_DEFINED);
		program.getMemory().setBytes(addr(0x1000),
			new byte[] {8, 0, 4, 0x20, 0, 0, 0, 0}); // j 1080; owned delay slot
		for (boolean sized : new boolean[] {true, false}) {
			byte[] bytes = EcoffDebugTest.fixture(false, true);
			if (!sized) {
				ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.SYM + 24 + 4, 0);
			}
			importBytes(bytes);
			assertEquals(ownedBody, owner.getBody());
			assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
			assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
			assertNull(program.getFunctionManager().getFunctionAt(addr(0x1000)));
			assertNotNull(program.getSymbolTable().getGlobalSymbol("run", addr(0x1000)));
		}
	}

	@Test
	public void testTextLabelDescriptorDoesNotAbortRemainingImport() throws Exception {
		byte[] bytes = java.util.Arrays.copyOf(EcoffDebugTest.fixture(false, true), 456);
		// Relocate the PDR table and put a label descriptor before the real procedure.
		System.arraycopy(bytes, EcoffDebugTest.PD, bytes, 352, 52);
		System.arraycopy(bytes, EcoffDebugTest.PD, bytes, 404, 52);
		ByteBuffer b = ByteBuffer.wrap(bytes);
		b.putInt(24, 2).putInt(28, EcoffDebugTest.ORIGIN + 352);
		b.putShort(EcoffDebugTest.FD + 42, (short) 2);
		b.putInt(352, 0x1040).putInt(352 + 4, 0);
		b.putInt(EcoffDebugTest.SYM, 16).putInt(EcoffDebugTest.SYM + 4, 0x1040);
		b.putInt(EcoffDebugTest.SYM + 8,
			EcoffDebug.ST_LABEL << 26 | EcoffDebug.SC_TEXT << 21 | EcoffDebug.INDEX_NIL);
		importBytes(bytes);
		assertEquals(1, program.getFunctionManager().getFunctionCount());
		assertEquals("run", program.getFunctionManager().getFunctionAt(addr(0x1000)).getName());
		assertNotNull(program.getSymbolTable().getGlobalSymbol("word", addr(0x1040)));
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x1040)));
		assertNull(program.getListing().getInstructionAt(addr(0x1040)));
		assertNotNull(program.getListing().getDefinedDataAt(addr(0x2000)));
		assertNotNull(program.getDataTypeManager().getDataType(new CategoryPath("/ECOFF"), "word"));
		assertNotNull(program.getSymbolTable().getGlobalSymbol("external", addr(0x3000)));
	}

	@Test
	public void testStrippedExternalLabelDescriptorStaysALabel() throws Exception {
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		ByteBuffer b = ByteBuffer.wrap(bytes);
		b.putInt(EcoffDebugTest.FD + 20, 0).putInt(EcoffDebugTest.PD + 4, 0);
		b.putInt(EcoffDebugTest.EXT + 8, 0x1040);
		b.putInt(EcoffDebugTest.EXT + 12,
			EcoffDebug.ST_LABEL << 26 | EcoffDebug.SC_TEXT << 21 | EcoffDebug.INDEX_NIL);
		importBytes(bytes);
		assertEquals(0, program.getFunctionManager().getFunctionCount());
		assertNotNull(program.getSymbolTable().getGlobalSymbol("external", addr(0x1040)));
		assertNull(program.getListing().getInstructionAt(addr(0x1040)));
	}

	@Test
	public void testUnknownSizeImportedPlaceholderIsDisassembled() throws Exception {
		Function placeholder = program.getFunctionManager().createFunction("run", addr(0x1000),
			new AddressSet(addr(0x1000)), SourceType.IMPORTED);
		AddressSet ownedBody = new AddressSet(addr(0x1080), addr(0x108f));
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1080),
			ownedBody, SourceType.USER_DEFINED);
		program.getMemory().setBytes(addr(0x1000),
			new byte[] {8, 0, 4, 0x20, 0, 0, 0, 0}); // j 1080; nop
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.SYM + 24 + 4, 0);
		importBytes(bytes);
		assertEquals(new AddressSet(addr(0x1000), addr(0x1007)), placeholder.getBody());
		assertNotNull(program.getListing().getInstructionAt(addr(0x1000)));
		assertNotNull(program.getListing().getInstructionAt(addr(0x1004)));
		assertEquals(ownedBody, owner.getBody());
		assertFalse(program.getListing().getInstructions(ownedBody, true).hasNext());
		assertFalse(program.getListing().getDefinedData(ownedBody, true).hasNext());
	}

	@Test
	public void testKnownNoReturnRunsAfterEcoffOnlyNames() throws Exception {
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		Function unrelated = program.getFunctionManager().createFunction("sppanic_helper",
			addr(0x1080), new AddressSet(addr(0x1080)), SourceType.USER_DEFINED);
		NoReturnFunctionAnalyzer known = new NoReturnFunctionAnalyzer();
		assertTrue(known.canAnalyze(program));
		assertTrue(known.getPriority().priority() < new EcoffAnalyzer().getPriority().priority());
		known.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog());
		Function outsideImport = program.getFunctionManager().createFunction("abort",
			addr(0x1090), new AddressSet(addr(0x1090)), SourceType.USER_DEFINED);
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		System.arraycopy("sppanic\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
			0, bytes, EcoffDebugTest.SS + 8, 8);
		importBytes(bytes);
		Function function = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(function);
		assertEquals("sppanic", function.getName());
		assertTrue(function.hasNoReturn());
		assertFalse(unrelated.hasNoReturn());
		assertFalse(outsideImport.hasNoReturn());
	}

	@Test
	public void testKnownNoReturnLabelInsideOwnedBodyIsNotCarved() throws Exception {
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		Function owner = program.getFunctionManager().createFunction("owned", addr(0x1000),
			new AddressSet(addr(0x1000), addr(0x103f)), SourceType.USER_DEFINED);
		program.getMemory().setBytes(addr(0x1008),
			new byte[] {3, (byte) 0xe0, 0, 8, 0, 0, 0, 0});
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		System.arraycopy("sppanic\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
			0, bytes, EcoffDebugTest.SS + 8, 8);
		ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.SYM + 12 + 4, 0x1008);
		importBytes(bytes);
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x1008)));
		assertEquals(new AddressSet(addr(0x1000), addr(0x103f)), owner.getBody());
		assertFalse(owner.hasNoReturn());
		assertNotNull(program.getSymbolTable().getGlobalSymbol("sppanic", addr(0x1008)));
	}

	@Test
	public void testKnownNoReturnEnablementIsRespected() throws Exception {
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		program.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
			.setBoolean(new NoReturnFunctionAnalyzer().getName(), false);
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		System.arraycopy("sppanic\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
			0, bytes, EcoffDebugTest.SS + 8, 8);
		importBytes(bytes);
		assertFalse(program.getFunctionManager().getFunctionAt(addr(0x1000)).hasNoReturn());
	}

	@Test
	public void testKnownNoReturnBookmarksCanBeDisabled() throws Exception {
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		program.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
			.getOptions(new NoReturnFunctionAnalyzer().getName())
			.setBoolean("Create Analysis Bookmarks", false);
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		System.arraycopy("sppanic\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
			0, bytes, EcoffDebugTest.SS + 8, 8);
		importBytes(bytes);
		assertTrue(program.getFunctionManager().getFunctionAt(addr(0x1000)).hasNoReturn());
		assertNull(program.getBookmarkManager().getBookmark(addr(0x1000),
			ghidra.program.model.listing.BookmarkType.ANALYSIS, "Non-Returning Function"));
	}

	@Test
	public void testRebasedLinkedSymbolAddresses() {
		program.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
			.setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "1000");
		var sym = new EcoffDebug.Symbol("rebased", 0x2000, 1, 2, EcoffDebug.INDEX_NIL, null, false);
		// The default image base is zero, so the original symbol moves down by 0x1000.
		assertEquals(addr(0x1000), EcoffAnalyzer.address(program, false, sym));
	}

	@Test
	public void testMalformedDebugFailsBeforeImport() throws Exception {
		byte[] bytes = EcoffDebugTest.fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(EcoffDebugTest.PD + 4, Integer.MAX_VALUE);
		assertThrows(java.io.IOException.class, () -> importBytes(bytes));
		assertEquals(0, program.getFunctionManager().getFunctionCount());
		assertNull(program.getListing().getDefinedDataAt(addr(0x2000)));
	}

	@Test
	public void testAutomaticEligibilityImportAndPersistentLoadedFlag() throws Exception {
		assertTrue(
			ghidra.util.classfinder.ClassSearcher.getInstances(ghidra.app.services.Analyzer.class)
				.stream()
				.anyMatch(analyzer -> analyzer instanceof EcoffAnalyzer));
		ByteBuffer elf = ByteBuffer.allocate(0x400 + 352);
		elf.put(new byte[] {0x7f, 'E', 'L', 'F', 1, 2, 1});
		elf.putShort(16, (short)2).putShort(18, (short)8).putInt(20, 1);
		elf.putInt(32, 52).putShort(40, (short)52).putShort(46, (short)40);
		elf.putShort(48, (short)3).putShort(50, (short)2);
		elf.putInt(92, 1).putInt(96, 0x70000005);
		elf.putInt(108, 0x400).putInt(112, 352);
		elf.putInt(132, 9).putInt(136, 3).putInt(148, 0x100).putInt(152, 19);
		elf.position(0x100);
		elf.put("\0.mdebug\0.shstrtab\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
		elf.position(0x400);
		elf.put(EcoffDebugTest.fixture(false, true));
		program.getMemory().createFileBytes("synthetic ELF", 0, elf.capacity(),
			new java.io.ByteArrayInputStream(elf.array()), TaskMonitor.DUMMY);
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		EcoffAnalyzer analyzer = new EcoffAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		MessageLog log = new MessageLog();
		assertTrue(analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log));
		assertTrue(program.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
				.getBoolean("ECOFF Debug Loaded", false));
		assertNotNull(log.toString(), program.getFunctionManager().getFunctionAt(addr(0x1000)));
		assertEquals("run", program.getFunctionManager().getFunctionAt(addr(0x1000)).getName());
		assertTrue(
			analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog()));
		assertEquals(1, program.getFunctionManager().getFunctionCount());
		program.getMemory().createInitializedBlock(
			".debug_info", addr(0x5000), 16, (byte)0, TaskMonitor.DUMMY, false);
		assertFalse(analyzer.canAnalyze(program));
	}
}
