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

import java.lang.reflect.Proxy;
import java.util.Map;

import org.junit.Test;

import ghidra.app.util.bin.format.ecoff.EcoffDebug;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

public class EcoffAnalyzerTest {
	private final AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);

	@SuppressWarnings("unchecked")
	private <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
		return (T)Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler);
	}

	private MemoryBlock block(long start, long size) {
		return proxy(MemoryBlock.class, (p, m, a) -> switch (m.getName()) {
			case "getStart" -> space.getAddress(start);
			case "getSize" -> size;
			default -> throw new UnsupportedOperationException(m.getName());
		});
	}

	private Program relocatableProgram() {
		Map<String, MemoryBlock> blocks = Map.of(".text", block(0x10000, 0x100), ".data",
			block(0x20000, 0x80), ".bss", block(0x30000, 0x40), ".rdata", block(0x40000, 0x40));
		Memory memory = proxy(Memory.class, (p, m, a) -> switch (m.getName()) {
			case "getBlock" -> blocks.get(a[0]);
			case "contains" -> true;
			default -> throw new UnsupportedOperationException(m.getName());
		});
		return proxy(Program.class, (p, m, a) -> {
			if (m.getName().equals("getMemory"))
				return memory;
			throw new UnsupportedOperationException(m.getName());
		});
	}

	private EcoffDebug.Symbol symbol(long value, int storage) {
		return new EcoffDebug.Symbol(
			"synthetic", value, 1, storage, EcoffDebug.INDEX_NIL, null, false);
	}

	@Test
	public void testRelocatableStorageClassesMapToLoadedSections() {
		Program p = relocatableProgram();
		assertEquals(space.getAddress(0x10000), EcoffAnalyzer.address(p, true, symbol(0, 1)));
		assertEquals(space.getAddress(0x20010), EcoffAnalyzer.address(p, true, symbol(16, 2)));
		assertEquals(space.getAddress(0x30004), EcoffAnalyzer.address(p, true, symbol(4, 3)));
		assertEquals(space.getAddress(0x40008), EcoffAnalyzer.address(p, true, symbol(8, 15)));
		assertNull(EcoffAnalyzer.address(p, true, symbol(0x100, 1)));
		assertNull(EcoffAnalyzer.address(p, true, symbol(0xffffffffL, 1)));
		assertNull(EcoffAnalyzer.address(p, true, symbol(0, 13)));
	}

	@Test
	public void testUndefinedCommonRegistersAndOffsetsAreNotAddresses() {
		Program p = relocatableProgram();
		for (int sc : new int[] {0, 4, 5, 6, 7, 8, 9, 11, 16, 17, 18, 19, 21}) {
			assertNull(EcoffAnalyzer.address(p, true, symbol(8, sc)));
		}
	}

	@Test
	public void testBasicTypesAndUnsupportedReferences() throws Exception {
		ghidra.util.UniversalIdGenerator.initialize();
		ProgramBasedDataTypeManager dtm = proxy(ProgramBasedDataTypeManager.class, (p, m, a) -> {
			if (m.getName().equals("getDataOrganization")) {
				return DataOrganizationImpl.getDefaultOrganization();
			}
			throw new UnsupportedOperationException(m.getName());
		});
		Program program = proxy(Program.class, (p, m, a) -> switch (m.getName()) {
			case "getDataTypeManager" -> dtm;
			case "getDefaultPointerSize" -> 4;
			default -> throw new UnsupportedOperationException(m.getName());
		});
		assertEquals(4, EcoffAnalyzer.dataType(program, new EcoffDebug.Type(6, 0)).getLength());
		assertEquals(8, EcoffAnalyzer.dataType(program, new EcoffDebug.Type(35, 0)).getLength());
		DataType pointer = EcoffAnalyzer.dataType(program, new EcoffDebug.Type(7, 2));
		assertTrue(pointer instanceof Pointer);
		assertTrue(((Pointer)pointer).getDataType() instanceof Pointer);
		assertEquals("uint", ((Pointer)((Pointer)pointer).getDataType()).getDataType().getName());
		assertNull(EcoffAnalyzer.dataType(program, null));
		for (int basic : new int[] {0, 12, 13, 14, 15, 16, 17, 20}) {
			assertNull(EcoffAnalyzer.dataType(program, new EcoffDebug.Type(basic, 1)));
		}
	}
}
