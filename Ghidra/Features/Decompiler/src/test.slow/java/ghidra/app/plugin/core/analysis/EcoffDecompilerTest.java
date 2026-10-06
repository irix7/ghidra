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

import org.junit.Test;

import ghidra.app.decompiler.*;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.ecoff.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class EcoffDecompilerTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testCProcedureParametersRemainRecoverable() throws Exception {
		var language = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("MIPS:BE:32:default"));
		ProgramDB program = new ProgramDB("ECOFF parameters", language,
			language.getDefaultCompilerSpec(), this);
		int transaction = program.startTransaction("ECOFF parameters");
		DecompInterface decompiler = new DecompInterface();
		try {
			var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
			program.getMemory().createInitializedBlock(".text", entry, 16, (byte) 0,
				TaskMonitor.DUMMY, false).setExecute(true);
			// addu v0,a0,a1; jr ra; nop. Both argument registers contribute to the return.
			program.getMemory().setBytes(entry, new byte[] {
				0, (byte) 0x85, 0x10, 0x21, 3, (byte) 0xe0, 0, 8, 0, 0, 0, 0});
			EcoffDebug debug = EcoffDebug.parse(new ByteArrayProvider(
				EcoffDebugTest.fixture(false, true)), EcoffDebugTest.ORIGIN, false, TaskMonitor.DUMMY);
			new EcoffAnalyzer().importDebug(program, false, debug, TaskMonitor.DUMMY, new MessageLog());
			var function = program.getFunctionManager().getFunctionAt(entry);
			assertNotNull(function);
			assertEquals(0, function.getParameterCount());
			assertTrue(decompiler.openProgram(program));
			DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
			assertTrue(results.getErrorMessage(), results.decompileCompleted());
			var prototype = results.getHighFunction().getFunctionPrototype();
			assertEquals(results.getDecompiledFunction().getC(), 2, prototype.getNumParams());
			assertEquals("a0", prototype.getParam(0).getStorage().getRegister().getName());
			assertEquals("a1", prototype.getParam(1).getStorage().getRegister().getName());
			assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		}
		finally {
			decompiler.dispose();
			program.endTransaction(transaction, false);
			program.release(this);
		}
	}
}
