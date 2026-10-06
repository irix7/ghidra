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

import java.util.Arrays;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class NoReturnFunctionAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testIrixNamesOnMipsElf() throws Exception {
		checkNames("MIPS:BE:64:64-32addr", "Executable and Linking Format (ELF)", true);
	}

	@Test
	public void testIrixNamesOnO32Elf() throws Exception {
		checkNames("MIPS:BE:32:default", "Executable and Linking Format (ELF)", true);
	}

	@Test
	public void testIrixNamesNotAppliedToOtherElfProcessors() throws Exception {
		checkNames("x86:LE:64:default", "Executable and Linking Format (ELF)", false);
	}

	@Test
	public void testIrixNamesNotAppliedToLittleEndianMips() throws Exception {
		checkNames("MIPS:LE:32:default", "Executable and Linking Format (ELF)", false);
	}

	@Test
	public void testIrixNamesNotAppliedToRawMips() throws Exception {
		checkNames("MIPS:BE:32:default", "Raw Binary", false);
	}

	private void checkNames(String language, String format, boolean irixNames) throws Exception {
		ProgramDB program = createDefaultProgram("noreturn", language, this);
		int transaction = program.startTransaction("Test known no-return names");
		try {
			program.setExecutableFormat(format);
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
			program.getMemory().createInitializedBlock("text", start, 0x100, (byte) 0,
				TaskMonitor.DUMMY, false).setExecute(true);
			String[] names = { "panic", "sppanic", "_sppanic", "_r4600_2_0_cacheop_eret",
				"_r4600_2_0_cacheop_eret_inst", "sppanic_helper" };
			Function[] functions = new Function[names.length];
			for (int i = 0; i < names.length; i++) {
				Address entry = start.add(i * 0x10);
				functions[i] = program.getFunctionManager().createFunction(names[i], entry,
					new AddressSet(entry), SourceType.IMPORTED);
			}

			boolean elf = format.equals("Executable and Linking Format (ELF)");
			assertEquals(irixNames, Arrays.stream(NonReturningFunctionNames.findDataFiles(program))
					.anyMatch(file -> file.getName().equals("MipsFunctionsThatDoNotReturn")));
			NoReturnFunctionAnalyzer analyzer = new NoReturnFunctionAnalyzer();
			if (analyzer.canAnalyze(program)) {
				analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog());
			}
			assertEquals(elf, functions[0].hasNoReturn());
			assertEquals(irixNames, functions[1].hasNoReturn());
			assertEquals(irixNames, functions[2].hasNoReturn());
			assertEquals(irixNames, functions[3].hasNoReturn());
			assertFalse(functions[4].hasNoReturn());
			assertFalse(functions[5].hasNoReturn());
		}
		finally {
			program.endTransaction(transaction, false);
			program.release(this);
		}
	}
}
