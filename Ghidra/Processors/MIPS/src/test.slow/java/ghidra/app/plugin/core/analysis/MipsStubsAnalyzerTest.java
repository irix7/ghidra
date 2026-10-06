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

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

import org.junit.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MipsStubsAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;
	private int transaction;

	@Before
	public void setUp() throws Exception {
		var language = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("MIPS:BE:32:default"));
		program =
			new ProgramDB("synthetic stubs", language, language.getDefaultCompilerSpec(), this);
		transaction = program.startTransaction("synthetic stubs");
		program.setExecutableFormat(ElfLoader.ELF_NAME);
		var stubs = program.getMemory().createInitializedBlock(
			".MIPS.stubs", addr(0x1000), 0x200, (byte) 0, TaskMonitor.DUMMY, false);
		stubs.setExecute(true);
		// lw t9,-0x7ff0(gp); or t7,ra,zero; jalr t9; ori t8,zero,1; nop ; repeated
		for (int i = 0; i < 4; i++) {
			program.getMemory().setBytes(addr(0x1000 + i * 20), new byte[] {
				(byte) 0x8f, (byte) 0xf9, (byte) 0x80, 0x10,     // lw t9,-0x7ff0(gp)
				0x01, (byte) 0xe0, 0x78, 0x25,             // or t7,ra,zero
				0x03, 0x20, 0x00, 0x08,                    // jalr t9
				0x34, 0x18, 0x00, (byte) (1 + i),          // ori t8,zero,1+i
				0, 0, 0, 0                                 // nop
			});
		}
		new ghidra.app.cmd.disassemble.DisassembleCommand(addr(0x1000), null, false)
				.applyTo(program, TaskMonitor.DUMMY);
		// Minimal big-endian ELF32 with a .dynsym holding one symbol ("target1").
		byte[] shstr = "\0.dynsym\0.dynstr\0.shstrtab\0".getBytes();
		byte[] dynstr = "\0target1\0".getBytes();
		ByteBuffer elf = ByteBuffer.allocate(0x400);
		elf.order(java.nio.ByteOrder.BIG_ENDIAN);
		elf.put(new byte[] { 0x7f, 'E', 'L', 'F', 1, 2, 1 }); // 32-bit BE
		elf.putShort(16, (short) 2).putShort(18, (short) 8).putInt(20, 1); // EXEC MIPS
		elf.putInt(32, 0x100).putShort(46, (short) 40); // shoff, shentsize
		elf.putShort(48, (short) 4).putShort(50, (short) 3); // shnum, shstrndx
		// section headers at 0x100: [null, .dynsym, .dynstr, .shstrtab]
		elf.position(0x100 + 40); // skip null section
		elf.putInt(1).putInt(11).putInt(0).putInt(0).putInt(0x200).putInt(0x20)
			.putInt(2).putInt(1).putInt(4).putInt(16); // .dynsym link=2 entsize=16
		elf.putInt(9).putInt(3).putInt(0).putInt(0).putInt(0x220).putInt(0x9)
			.putInt(0).putInt(0).putInt(1).putInt(0); // .dynstr
		elf.putInt(17).putInt(3).putInt(0).putInt(0).putInt(0x230).putInt(shstr.length)
			.putInt(0).putInt(0).putInt(1).putInt(0); // .shstrtab
		elf.position(0x200); // dynsym: null + target1
		elf.put(new byte[16]);
		elf.putInt(1).putInt(0).putInt(0).put((byte) 0x12).put((byte) 0).putShort((short) 0);
		elf.position(0x220);
		elf.put(dynstr);
		elf.position(0x230);
		elf.put(shstr);
		program.getMemory().createFileBytes("synthetic ELF", 0, elf.capacity(),
			new ByteArrayInputStream(elf.array()), TaskMonitor.DUMMY);
		var target = program.getMemory().createInitializedBlock(
			".text", addr(0x3000), 0x20, (byte) 0, TaskMonitor.DUMMY, false);
		target.setExecute(true);
		program.getListing().createFunction("target1", addr(0x3000),
			new ghidra.program.model.address.AddressSet(addr(0x3000), addr(0x3003)),
			SourceType.IMPORTED);
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.endTransaction(transaction, true);
			program.release(this);
		}
	}

	private ghidra.program.model.address.Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Test
	public void testNamesStubsAndThunksThem() throws Exception {
		MipsStubsAnalyzer analyzer = new MipsStubsAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		boolean changed = analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY,
			new MessageLog());
		assertTrue(changed);
		Function stub = program.getFunctionManager().getFunctionAt(addr(0x1000));
		assertNotNull(stub);
		assertEquals("target1@plt", stub.getName());
		assertTrue(stub.isThunk());
		assertEquals("target1", stub.getThunkedFunction(true).getName());
	}

	@Test
	public void testIdempotent() throws Exception {
		MipsStubsAnalyzer analyzer = new MipsStubsAnalyzer();
		analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, new MessageLog());
		assertFalse(analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY,
			new MessageLog()));
	}
}
