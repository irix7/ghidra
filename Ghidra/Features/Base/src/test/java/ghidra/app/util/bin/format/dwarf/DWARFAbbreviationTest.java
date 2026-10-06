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
package ghidra.app.util.bin.format.dwarf;

import static ghidra.app.util.bin.format.dwarf.DWARFTag.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Map;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFForm;

/**
 * Tests reading .debug_abbrev, including the vendor-specific layout used by the
 * SGI MIPSpro compiler.
 */
public class DWARFAbbreviationTest {

	private static byte[] bytes(int... intBytes) {
		byte[] result = new byte[intBytes.length];
		for (int i = 0; i < intBytes.length; i++) {
			result[i] = (byte) intBytes[i];
		}
		return result;
	}

	private BinaryReader br(int... intBytes) {
		return new BinaryReader(new ByteArrayProvider(bytes(intBytes)), true);
	}

	private Map<Integer, DWARFAbbreviation> read(BinaryReader reader) throws IOException {
		return DWARFAbbreviation.readAbbreviations(reader, null);
	}

	@Test
	public void testStandardTable() throws IOException {
		// @formatter:off
		Map<Integer, DWARFAbbreviation> abbrs = read(br(
			/* abbrev 1 */ 1, DW_TAG_compile_unit.getId(), 1,
				DW_AT_name.getId(), DW_FORM_string.getId(), 0, 0,
			/* end of table */ 0
		));
		// @formatter:on

		assertEquals(1, abbrs.size());
		DWARFAbbreviation abbr = abbrs.get(1);
		assertNotNull(abbr);
		assertEquals(DW_TAG_compile_unit, abbr.getTag());
		assertTrue(abbr.hasChildren());
		assertEquals(1, abbr.getAttributeCount());
		assertEquals(DW_AT_name, abbr.getAttributeAt(0).getAttributeId());
	}

	@Test
	public void testMissingTableTerminator() throws IOException {
		// SGI MIPSpro omits the final end-of-table marker; the section simply ends
		// after the last abbreviation's attribute list.
		// @formatter:off
		Map<Integer, DWARFAbbreviation> abbrs = read(br(
			/* abbrev 1 */ 1, DW_TAG_compile_unit.getId(), 0,
				DW_AT_name.getId(), DW_FORM_string.getId(), 0, 0
		));
		// @formatter:on

		assertEquals(1, abbrs.size());
		assertEquals(DW_TAG_compile_unit, abbrs.get(1).getTag());
	}

	@Test
	public void testUnknownVendorAttribute() throws IOException {
		// unknown attributes (eg. DW_AT_MIPS_has_inlines) must not stop the parser
		// @formatter:off
		Map<Integer, DWARFAbbreviation> abbrs = read(br(
			/* abbrev 1 */ 1, DW_TAG_compile_unit.getId(), 0,
				/* DW_AT_MIPS_has_inlines (0x200b) as ULEB128 */ 0x8b, 0x40,
				DW_FORM_data1.getId(), 0, 0,
			/* end of table */ 0
		));
		// @formatter:on

		assertEquals(1, abbrs.size());
		DWARFAbbreviation abbr = abbrs.get(1);
		assertNull(abbr.getAttributeAt(0).getAttributeId());
		assertEquals(DW_FORM_data1, abbr.getAttributeAt(0).getAttributeForm());
	}

	@Test
	public void testConcatenatedSgiBlocks() throws IOException {
		// SGI MIPSpro stores each compilation unit's abbreviations in a separate block,
		// concatenated with no end-of-table marker, with abbreviation codes restarting at 1.
		// @formatter:off
		BinaryReader reader = br(
			/* block A, abbrev 1 */ 1, DW_TAG_compile_unit.getId(), 0, 0, 0,
			/* block A, abbrev 2 */ 2, DW_TAG_subprogram.getId(), 0, 0, 0,
			/* block B, abbrev 1 */ 1, DW_TAG_variable.getId(), 0, 0, 0,
			/* block B, abbrev 2 */ 2, DW_TAG_subprogram.getId(), 0, 0, 0
		);
		// @formatter:on

		Map<Integer, DWARFAbbreviation> blockA = read(reader);
		assertEquals(2, blockA.size());
		assertEquals(DW_TAG_compile_unit, blockA.get(1).getTag());
		assertEquals(DW_TAG_subprogram, blockA.get(2).getTag());

		reader.setPointerIndex(10);
		Map<Integer, DWARFAbbreviation> blockB = read(reader);
		assertEquals(2, blockB.size());
		assertEquals(DW_TAG_variable, blockB.get(1).getTag());
		assertEquals(DW_TAG_subprogram, blockB.get(2).getTag());
	}
}
