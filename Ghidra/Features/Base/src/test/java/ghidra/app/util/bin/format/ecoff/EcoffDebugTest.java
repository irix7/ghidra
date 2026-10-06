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
package ghidra.app.util.bin.format.ecoff;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.*;
import java.util.Arrays;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class EcoffDebugTest {
	public static final int ORIGIN = 0x400;
	public static final int PD = 96, SYM = 148, AUX = 208, SS = 220, FD = 252, EXTSS = 324,
							EXT = 336;

	/** Five local records and one procedure, deliberately using non-zero file/table bases. */
	public static byte[] fixture(boolean little, boolean auxBig) {
		ByteBuffer b =
			ByteBuffer.allocate(352).order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		b.putShort(0, (short)0x7009);
		b.putShort(2, (short)0x305);
		table(b, 24, 1, PD);
		table(b, 32, 5, SYM);
		table(b, 48, 3, AUX);
		table(b, 56, 32, SS);
		table(b, 64, 12, EXTSS);
		table(b, 72, 1, FD);
		table(b, 88, 1, EXT);
		b.putInt(PD, 0x1000).putInt(PD + 4, 1).putInt(PD + 32, 32);
		b.putShort(PD + 36, (short)29).putShort(PD + 38, (short)31);
		b.putInt(PD + 40, 10).putInt(PD + 44, 20);
		byte[] strings = "\0\0\0\0a.c\0run\0counter\0word\0".getBytes(
			java.nio.charset.StandardCharsets.US_ASCII);
		b.position(SS);
		b.put(strings);
		b.position(EXTSS);
		b.put("\0external\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
		// The first local symbol is a file record; PDR.isym is relative to this FDR.
		sym(b, SYM, 0, 0, 11, 1, 5, little);
		sym(b, SYM + 12, 4, 0x1000, 6, 1, 0, little);
		sym(b, SYM + 24, 4, 16, 8, 1, 1, little);
		sym(b, SYM + 36, 8, 0x2000, 2, 2, 2, little);
		sym(b, SYM + 48, 16, 0, 10, 11, 2, little);
		b.putInt(FD, 0x1000).putInt(FD + 4, 0).putInt(FD + 8, 4).putInt(FD + 12, 28);
		b.putInt(FD + 16, 0).putInt(FD + 20, 5);
		b.putShort(FD + 42, (short)1);
		b.putInt(FD + 48, 3);
		b.put(FD + 60, (byte)(auxBig ? (little ? 0x80 : 1) : 0));
		ByteBuffer aux =
			b.duplicate().order(auxBig ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		aux.putInt(AUX, 3); // first symbol after the procedure's matching stEnd
		b.put(AUX + 4, (byte)(auxBig ? 6 : 6 << 2)); // return int
		b.put(AUX + 8, (byte)(auxBig ? 7 : 7 << 2)); // unsigned int *
		b.put(AUX + 10, (byte)(auxBig ? 0x10 : 1));
		b.putShort(EXT + 2, (short)-1);
		sym(b, EXT + 4, 1, 0x3000, 1, 3, EcoffDebug.INDEX_NIL, little);
		return b.array();
	}

	private static void table(ByteBuffer b, int field, int count, int offset) {
		b.putInt(field, count).putInt(field + 4, ORIGIN + offset);
	}

	private static void sym(ByteBuffer b, int pos, int iss, int value, int kind, int storage,
		int index, boolean little) {
		b.putInt(pos, iss).putInt(pos + 4, value);
		b.putInt(pos + 8,
			little ? kind | storage << 6 | index << 12 : kind << 26 | storage << 21 | index);
	}

	private EcoffDebug parse(byte[] bytes, boolean little) throws Exception {
		return EcoffDebug.parse(new ByteArrayProvider(bytes), ORIGIN, little, TaskMonitor.DUMMY);
	}

	@Test
	public void testBothEndiannessesAndCompileHostAuxOrder() throws Exception {
		for (boolean little : new boolean[] {false, true}) {
			for (boolean auxBig : new boolean[] {false, true}) {
				EcoffDebug d = parse(fixture(little, auxBig), little);
				var f = d.files().get(0);
				assertEquals("a.c", f.name());
				assertEquals(0, f.language());
				assertEquals(auxBig, f.auxBigEndian());
				assertEquals(5, f.symbols().size());
				var pd = f.procedures().get(0);
				assertEquals("run", pd.symbol().name());
				assertEquals(0x1000, pd.address());
				assertEquals(16, pd.size());
				assertEquals(32, pd.frameSize());
				assertEquals(29, pd.frameRegister());
				assertEquals(31, pd.returnRegister());
				assertEquals(10, pd.lineLow());
				assertEquals(20, pd.lineHigh());
				assertEquals(new EcoffDebug.Type(6, 0), pd.symbol().type());
				assertEquals(new EcoffDebug.Type(7, 1), f.symbols().get(3).type());
				assertEquals("counter", f.symbols().get(3).name());
				assertEquals("external", d.externals().get(0).name());
				assertEquals(0x3000, d.externals().get(0).value());
			}
		}
	}

	@Test
	public void testEmptyTablesIgnoreUnusedOffsets() throws Exception {
		ByteBuffer b = ByteBuffer.allocate(96).order(ByteOrder.BIG_ENDIAN);
		b.putShort(0, (short)0x7009);
		b.putInt(28, -1);
		assertTrue(parse(b.array(), false).files().isEmpty());
	}

	@Test
	public void testTruncationAtEveryByte() throws Exception {
		byte[] b = fixture(false, true);
		for (int i = 0; i < b.length; i++) {
			byte[] truncated = Arrays.copyOf(b, i);
			assertThrows(IOException.class, () -> parse(truncated, false));
		}
	}

	@Test
	public void testBadHeaderAndAbsoluteOffsets() throws Exception {
		byte[] bytes = fixture(false, true);
		assertThrows(IOException.class, () -> parse(bytes, true));
		assertThrows(IOException.class,
			() -> EcoffDebug.parse(new ByteArrayProvider(bytes), 0, false, TaskMonitor.DUMMY));
		ByteBuffer.wrap(bytes).putInt(28, PD); // section-relative is not file-absolute
		assertThrows(IOException.class, () -> parse(bytes, false));
	}

	@Test
	public void testUnsignedCountsAndTableOverlap() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(24, -1);
		byte[] excessive = bytes;
		assertThrows(IOException.class, () -> parse(excessive, false));
		bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(36, ORIGIN + PD);
		byte[] overlap = bytes;
		assertThrows(IOException.class, () -> parse(overlap, false));
	}

	@Test
	public void testInvalidFileSlicesAndProcedureReferences() throws Exception {
		for (int field : new int[] {FD + 8, FD + 16, FD + 44, PD + 4}) {
			byte[] bytes = fixture(false, true);
			ByteBuffer.wrap(bytes).putInt(field, 0x7fffffff);
			assertThrows(IOException.class, () -> parse(bytes, false));
		}
		byte[] bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putShort(EXT + 2, (short)1);
		assertThrows(IOException.class, () -> parse(bytes, false));
	}

	@Test
	public void testDescriptorReferencesRequireTextProceduresOrLabels() throws Exception {
		for (boolean little : new boolean[] {false, true}) {
			for (int[] fields : new int[][] {{5, 2}, {6, 2}, {14, 2}, {1, 1}}) {
				byte[] bytes = fixture(little, !little);
				ByteBuffer b = ByteBuffer.wrap(bytes).order(
					little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
				sym(b, SYM + 12, 4, 0x1000, fields[0], fields[1], 0, little);
				assertThrows(IOException.class, () -> parse(bytes, little));
			}
			byte[] bytes = fixture(little, !little);
			ByteBuffer b = ByteBuffer.wrap(bytes).order(
				little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
			sym(b, SYM + 12, 4, 0x1000, 14, 1, 0, little);
			assertTrue(parse(bytes, little).files().get(0).procedures().get(0)
				.symbol().isProcedure());
			sym(b, SYM + 12, 4, 0x1000, 5, 1, EcoffDebug.INDEX_NIL, little);
			var localLabel = parse(bytes, little).files().get(0).procedures().get(0);
			assertFalse(localLabel.symbol().isProcedure());
			assertEquals("run", localLabel.symbol().name());
			assertEquals(0, localLabel.size());
			b.putInt(FD + 20, 0).putInt(PD + 4, 0);
			sym(b, EXT + 4, 1, 0x3000, 5, 1, EcoffDebug.INDEX_NIL, little);
			var externalLabel = parse(bytes, little).files().get(0).procedures().get(0);
			assertTrue(externalLabel.symbol().external());
			assertFalse(externalLabel.symbol().isProcedure());
			assertEquals("external", externalLabel.symbol().name());
			assertEquals(0, externalLabel.size());
			sym(b, EXT + 4, 1, 0x3000, 5, 2, EcoffDebug.INDEX_NIL, little);
			assertThrows(IOException.class, () -> parse(bytes, little));
		}
	}

	@Test
	public void testStringsCannotEscapeFileStringSlice() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(SYM + 12, 28);
		byte[] invalidIndex = bytes;
		assertThrows(IOException.class, () -> parse(invalidIndex, false));
		bytes = fixture(false, true);
		Arrays.fill(bytes, SS + 4, SS + 32, (byte)'x');
		byte[] unterminated = bytes;
		assertThrows(IOException.class, () -> parse(unterminated, false));
	}

	@Test
	public void testOverlappingFileSlicesAreRejected() throws Exception {
		byte[] bytes = Arrays.copyOf(fixture(false, true), 496);
		System.arraycopy(bytes, FD, bytes, 352, 72);
		System.arraycopy(bytes, FD, bytes, 424, 72);
		table(ByteBuffer.wrap(bytes), 72, 2, 352);
		IOException symbols = assertThrows(IOException.class, () -> parse(bytes, false));
		assertEquals("Overlapping ECOFF file symbol slices", symbols.getMessage());
		ByteBuffer.wrap(bytes).putInt(424 + 20, 0);
		IOException procedures = assertThrows(IOException.class, () -> parse(bytes, false));
		assertEquals("Overlapping ECOFF file procedure slices", procedures.getMessage());
	}

	@Test
	public void testUnsupportedTypesAndStabsDoNotBecomeNativeTypes() throws Exception {
		byte[] bytes = fixture(false, true);
		bytes[AUX + 10] = 0x30; // array qualifier
		assertNull(parse(bytes, false).files().get(0).symbols().get(3).type());
		bytes[AUX + 10] = 0x10;
		bytes[AUX + 8] |= (byte)0x80; // bitfield
		assertNull(parse(bytes, false).files().get(0).symbols().get(3).type());
		ByteBuffer b = ByteBuffer.wrap(bytes);
		sym(b, SYM + 36, 8, 0x2000, 2, 2, 0x8f324, false);
		var stab = parse(bytes, false).files().get(0).symbols().get(3);
		assertTrue(stab.isStab());
		assertNull(stab.type());
	}

	@Test
	public void testMatchingEndRequiredForSize() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(SYM + 24 + 8, 8 << 26 | 1 << 21 | 0);
		assertEquals(0, parse(bytes, false).files().get(0).procedures().get(0).size());
	}

	@Test
	public void testFileRelativeSymbolAndAuxiliaryBases() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer b = ByteBuffer.wrap(bytes);
		b.putInt(FD + 16, 1).putInt(FD + 20, 4).putInt(PD + 4, 0);
		b.putInt(FD + 44, 1).putInt(FD + 48, 2);
		b.putInt(AUX + 4, 2);
		b.putInt(AUX + 8, 6 << 24);
		sym(b, SYM + 24, 4, 16, 8, 1, 0, false);
		sym(b, SYM + 36, 8, 0x2000, 2, 2, 1, false);
		sym(b, SYM + 48, 16, 0, 10, 11, 1, false);
		var f = parse(bytes, false).files().get(0);
		assertEquals(4, f.symbols().size());
		assertEquals("run", f.procedures().get(0).symbol().name());
		assertEquals(16, f.procedures().get(0).size());
		assertEquals(new EcoffDebug.Type(6, 0), f.procedures().get(0).symbol().type());
		assertEquals(new EcoffDebug.Type(6, 0), f.symbols().get(2).type());
	}

	@Test
	public void testUnsignedSymbolValuesAndNilNames() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer.wrap(bytes).putInt(SYM + 12 + 4, 0x88001000).putInt(SYM, -1);
		var f = parse(bytes, false).files().get(0);
		assertEquals(0x88001000L, f.symbols().get(1).value());
		assertEquals("", f.symbols().get(0).name());
	}

	@Test
	public void testRecordLimitBeforeAllocation() throws Exception {
		ByteBuffer header = ByteBuffer.allocate(96);
		header.putShort(0, (short)0x7009);
		table(header, 24, 2_000_001, 96);
		ByteArrayProvider provider = new ByteArrayProvider(header.array()) {
			@Override
			public long length() {
				return 1_000_000_000;
			}
		};
		IOException error = assertThrows(
			IOException.class, () -> EcoffDebug.parse(provider, ORIGIN, false, TaskMonitor.DUMMY));
		assertEquals("ECOFF record limit exceeded", error.getMessage());
	}

	@Test
	public void testStrippedFileProcedureUsesExternalSymbols() throws Exception {
		byte[] bytes = fixture(false, true);
		ByteBuffer b = ByteBuffer.wrap(bytes);
		b.putInt(FD + 20, 0).putInt(PD + 4, 0);
		sym(b, EXT + 4, 1, 0x3000, 6, 1, EcoffDebug.INDEX_NIL, false);
		var pd = parse(bytes, false).files().get(0).procedures().get(0);
		assertEquals("external", pd.symbol().name());
		assertTrue(pd.symbol().external());
		assertEquals(0, pd.size());
	}

	@Test
	public void testCancellationPropagates() throws Exception {
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		assertThrows(CancelledException.class,
			()
				-> EcoffDebug.parse(
					new ByteArrayProvider(fixture(false, true)), ORIGIN, false, monitor));
	}
}
