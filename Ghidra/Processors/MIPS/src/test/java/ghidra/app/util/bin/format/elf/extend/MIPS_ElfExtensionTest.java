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
package ghidra.app.util.bin.format.elf.extend;

import static org.junit.Assert.*;


import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;

/**
 * Tests MIPS-specific symbol section index handling.
 */
public class MIPS_ElfExtensionTest {

	private static byte[] bytes(int... intBytes) {
		byte[] result = new byte[intBytes.length];
		for (int i = 0; i < intBytes.length; i++) {
			result[i] = (byte) intBytes[i];
		}
		return result;
	}

	private ElfSymbol symbol(short shndx) throws Exception {
		// @formatter:off
		byte[] headerBytes = bytes(
			/* e_ident */ 0x7f, 'E', 'L', 'F', 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			/* e_type */ 0, 2,
			/* e_machine */ 0, 8,
			/* e_version */ 0, 0, 0, 1,
			/* e_entry */ 0, 0, 0, 0,
			/* e_phoff */ 0, 0, 0, 0,
			/* e_shoff */ 0, 0, 0, 0,
			/* e_flags */ 0x20, 0, 0, 0x20,
			/* e_ehsize */ 0, 52,
			/* e_phentsize */ 0, 0,
			/* e_phnum */ 0, 0,
			/* e_shentsize */ 0, 40,
			/* e_shnum */ 0, 0,
			/* e_shstrndx */ 0, 0
		);
		byte[] symbolBytes = bytes(
			/* st_name */ 0, 0, 0, 0,
			/* st_value */ 0, 0, 0, 0,
			/* st_size */ 0, 0, 0, 0,
			/* st_info */ 0x10 /* GLOBAL NOTYPE */, 0,
			/* st_shndx */ (shndx >> 8) & 0xff, shndx & 0xff
		);
		// @formatter:on
		ElfHeader header = new ElfHeader(new ByteArrayProvider(headerBytes), s -> {
		});
		return new ElfSymbol(new BinaryReader(new ByteArrayProvider(symbolBytes), false), 1, null,
			header);
	}

	@Test
	public void testSmallUndefinedSymbolIsExternal() throws Exception {
		ElfSymbol symbol = symbol(MIPS_ElfExtension.SHN_MIPS_SUNDEFINED);
		MIPS_ElfExtension extension = new MIPS_ElfExtension();

		assertEquals(Address.NO_ADDRESS, extension.calculateSymbolAddress(null, symbol));
	}

	@Test
	public void testStandardUndefinedSymbolNotHandled() throws Exception {
		ElfSymbol symbol = symbol((short) 0);
		MIPS_ElfExtension extension = new MIPS_ElfExtension();

		assertNull(extension.calculateSymbolAddress(null, symbol));
	}

	@Test
	public void testNonProcessorSpecificSectionIndexNotHandled() throws Exception {
		ElfSymbol symbol = symbol((short) 1);
		MIPS_ElfExtension extension = new MIPS_ElfExtension();

		assertNull(extension.calculateSymbolAddress(null, symbol));
	}
}
