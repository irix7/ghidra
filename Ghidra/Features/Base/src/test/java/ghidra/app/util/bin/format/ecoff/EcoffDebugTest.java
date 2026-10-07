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
	public static final int PPD = 96, PSYM = 200, PAUX = 332, PSS = 364, PFD = 417,
							PEXTSS = 489, PEXT = 499;

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

	/**
	 * Eleven local records: a file record, procedure {@code run} with a register
	 * parameter (alpha, a0), a stack parameter (beta, frame offset 16) and a register
	 * local (tmp), its matching stEnd, static data, a typedef, a static procedure
	 * {@code hidden} with its stEnd and a text label. Also one external record.
	 */
	public static byte[] fixtureWithParameters(boolean little, boolean auxBig) {
		ByteBuffer b = ByteBuffer.allocate(515)
				.order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		b.putShort(0, (short)0x7009);
		b.putShort(2, (short)0x305);
		table(b, 24, 2, PPD);
		table(b, 32, 11, PSYM);
		table(b, 48, 8, PAUX);
		table(b, 56, 53, PSS);
		table(b, 64, 10, PEXTSS);
		table(b, 72, 1, PFD);
		table(b, 88, 1, PEXT);
		b.putInt(PPD, 0x1000).putInt(PPD + 4, 1).putInt(PPD + 32, 32);
		b.putShort(PPD + 36, (short)29).putShort(PPD + 38, (short)31);
		b.putInt(PPD + 40, 10).putInt(PPD + 44, 20);
		b.putInt(PPD + 52, 0x1040).putInt(PPD + 56, 8).putInt(PPD + 84, 8);
		b.putShort(PPD + 88, (short)29).putShort(PPD + 90, (short)31);
		byte[] strings =
			"\0\0\0\0a.c\0run\0alpha\0beta\0tmp\0counter\0word\0hidden\0note\0".getBytes(
				java.nio.charset.StandardCharsets.US_ASCII);
		b.position(PSS);
		b.put(strings);
		b.position(PEXTSS);
		b.put("\0external\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
		sym(b, PSYM, 4, 0, EcoffDebug.ST_FILE, 1, 5, little);
		sym(b, PSYM + 12, 8, 0x1000, 6, 1, 0, little);
		sym(b, PSYM + 24, 12, 4, 3, 4, 2, little);
		sym(b, PSYM + 36, 18, 16, 3, 5, 3, little);
		sym(b, PSYM + 48, 23, 8, 4, 4, 4, little);
		sym(b, PSYM + 60, 8, 16, 8, 1, 1, little);
		sym(b, PSYM + 72, 27, 0x2000, 2, 2, 5, little);
		sym(b, PSYM + 84, 35, 0, 10, 11, 5, little);
		sym(b, PSYM + 96, 40, 0x1040, 14, 1, 6, little);
		sym(b, PSYM + 108, 40, 8, 8, 1, 8, little);
		sym(b, PSYM + 120, 47, 0x1050, 5, 1, EcoffDebug.INDEX_NIL, little);
		b.putInt(PFD, 0x1000).putInt(PFD + 4, 4).putInt(PFD + 8, 0).putInt(PFD + 12, 53);
		b.putInt(PFD + 16, 0).putInt(PFD + 20, 11);
		b.putShort(PFD + 42, (short)2);
		b.putInt(PFD + 48, 8);
		b.put(PFD + 60, (byte)(auxBig ? (little ? 0x80 : 1) : 0));
		ByteBuffer aux =
			b.duplicate().order(auxBig ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		aux.putInt(PAUX, 6); // first local symbol after run's matching stEnd
		aux.put(PAUX + 4, (byte)(auxBig ? 6 : 6 << 2)); // run returns int
		aux.put(PAUX + 8, (byte)(auxBig ? 6 : 6 << 2)); // alpha: int
		aux.put(PAUX + 12, (byte)(auxBig ? 7 : 7 << 2)); // beta: unsigned int *
		aux.put(PAUX + 14, (byte)(auxBig ? 0x10 : 1));
		aux.put(PAUX + 16, (byte)(auxBig ? 6 : 6 << 2)); // tmp: int
		aux.put(PAUX + 20, (byte)(auxBig ? 7 : 7 << 2)); // counter: unsigned int *
		aux.put(PAUX + 22, (byte)(auxBig ? 0x10 : 1));
		aux.putInt(PAUX + 24, 10); // first local symbol after hidden's matching stEnd
		aux.put(PAUX + 28, (byte)(auxBig ? 26 : 26 << 2)); // hidden returns void
		b.putShort(PEXT + 2, (short)-1);
		sym(b, PEXT + 4, 1, 0x3000, 1, 3, EcoffDebug.INDEX_NIL, little);
		return b.array();
	}

	/**
	 * A procedure {@code run} whose stProc is followed by an interleaved stLabel
	 * (alternate entry) and stStatic (local static) before its matching stEnd.
	 * IRIX MIPSpro emits this; a linear stProc/stEnd scan would truncate the
	 * procedure to size 0, but the PDR's auxiliary record still binds the stEnd.
	 */
	public static byte[] fixtureWithInterleavedRecords(boolean little, boolean auxBig) {
		byte[] bytes = fixture(little, auxBig);
		ByteBuffer b = ByteBuffer.wrap(bytes)
				.order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		sym(b, SYM + 24, 4, 0x1004, EcoffDebug.ST_LABEL, 1, EcoffDebug.INDEX_NIL, little);
		sym(b, SYM + 36, 8, 0x10, EcoffDebug.ST_STATIC, 2, EcoffDebug.INDEX_NIL, little);
		sym(b, SYM + 48, 16, 0x18, EcoffDebug.ST_END, 1, 1, little);
		ByteBuffer aux =
			b.duplicate().order(auxBig ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		aux.putInt(AUX, 5); // first local symbol after run's matching stEnd (slot 4)
		return bytes;
	}

	/**
	 * Two procedures emitted as a group (stProc A, stProc B) with their stEnd
	 * records reversed (stEnd B, stEnd A), as seen in IRIX hand-written assembly
	 * (e.g. libgl fast2d.s). Each PDR's auxiliary record selects its own stEnd.
	 */
	public static byte[] fixtureWithOutOfOrderProcedures(boolean little, boolean auxBig) {
		final int OPD = 96, OSYM = 200, OAUX = 260, OSS = 268, OEXTSS = 292, OFD = 304, OEXT = 376;
		ByteBuffer b = ByteBuffer.allocate(400)
				.order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		b.putShort(0, (short)0x7009);
		b.putShort(2, (short)0x715);
		table(b, 24, 2, OPD);
		table(b, 32, 5, OSYM);
		table(b, 48, 2, OAUX);
		table(b, 56, 16, OSS);
		table(b, 64, 12, OEXTSS);
		table(b, 72, 1, OFD);
		table(b, 88, 1, OEXT);
		b.putInt(OPD, 0x1000).putInt(OPD + 4, 1);
		b.putInt(OPD + 52, 0x1010).putInt(OPD + 56, 2);
		b.position(OSS);
		b.put("\0\0\0\0a.c\0run\0two\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
		b.position(OEXTSS);
		b.put("\0external\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
		sym(b, OSYM, 0, 0, EcoffDebug.ST_FILE, 1, 5, little);
		sym(b, OSYM + 12, 4, 0x1000, EcoffDebug.ST_PROC, 1, 0, little);
		sym(b, OSYM + 24, 8, 0x1010, EcoffDebug.ST_PROC, 1, 1, little);
		sym(b, OSYM + 36, 8, 0x30, EcoffDebug.ST_END, 1, 2, little);
		sym(b, OSYM + 48, 8, 0x20, EcoffDebug.ST_END, 1, 1, little);
		b.putInt(OFD, 0x1000).putInt(OFD + 4, 0).putInt(OFD + 8, 4).putInt(OFD + 12, 12);
		b.putInt(OFD + 16, 0).putInt(OFD + 20, 5);
		b.putShort(OFD + 42, (short)2);
		b.putInt(OFD + 48, 2);
		b.put(OFD + 60, (byte)(auxBig ? (little ? 0x80 : 1) : 0));
		ByteBuffer aux =
			b.duplicate().order(auxBig ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		aux.putInt(OAUX, 5);     // A's matching stEnd is slot 4
		aux.putInt(OAUX + 4, 4); // B's matching stEnd is slot 3
		b.putShort(OEXT + 2, (short)-1);
		sym(b, OEXT + 4, 1, 0x3000, 1, 3, EcoffDebug.INDEX_NIL, little);
		return b.array();
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
				assertTrue(pd.parameters().isEmpty());
				assertTrue(pd.locals().isEmpty());
				assertEquals(new EcoffDebug.Type(6, 0), pd.symbol().type());
				assertEquals(new EcoffDebug.Type(7, 1), f.symbols().get(3).type());
				assertEquals("counter", f.symbols().get(3).name());
				assertEquals("external", d.externals().get(0).name());
				assertEquals(0x3000, d.externals().get(0).value());
			}
		}
	}

	private EcoffDebug parseWithParameters(byte[] bytes, boolean little) throws Exception {
		return EcoffDebug.parse(new ByteArrayProvider(bytes), ORIGIN, little, TaskMonitor.DUMMY);
	}

	@Test
	public void testProcedureParametersLocalsAndStaticSymbols() throws Exception {
		for (boolean little : new boolean[] {false, true}) {
			for (boolean auxBig : new boolean[] {false, true}) {
				EcoffDebug d = parseWithParameters(fixtureWithParameters(little, auxBig), little);
				var f = d.files().get(0);
				assertEquals(11, f.symbols().size());
				assertEquals(2, f.procedures().size());
				var run = f.procedures().get(0);
				assertEquals("run", run.symbol().name());
				assertEquals(16, run.size());
				assertEquals(32, run.frameSize());
				assertEquals(2, run.parameters().size());
				assertEquals(1, run.locals().size());
				EcoffDebug.Symbol alpha = run.parameters().get(0);
				assertEquals("alpha", alpha.name());
				assertEquals(EcoffDebug.ST_PARAM, alpha.kind());
				assertEquals(EcoffDebug.SC_REGISTER, alpha.storage());
				assertEquals(4, alpha.value());
				assertEquals(new EcoffDebug.Type(6, 0), alpha.type());
				EcoffDebug.Symbol beta = run.parameters().get(1);
				assertEquals("beta", beta.name());
				assertEquals(EcoffDebug.SC_ABS, beta.storage());
				assertEquals(16, beta.value());
				assertEquals(new EcoffDebug.Type(7, 1), beta.type());
				EcoffDebug.Symbol tmp = run.locals().get(0);
				assertEquals("tmp", tmp.name());
				assertEquals(EcoffDebug.SC_REGISTER, tmp.storage());
				assertEquals(8, tmp.value());
				assertEquals(new EcoffDebug.Type(6, 0), tmp.type());
				var hidden = f.procedures().get(1);
				assertEquals("hidden", hidden.symbol().name());
				assertTrue(hidden.symbol().isProcedure());
				assertEquals(0x1040, hidden.address());
				assertEquals(8, hidden.size());
				assertTrue(hidden.parameters().isEmpty());
				assertTrue(hidden.locals().isEmpty());
				assertEquals("counter", f.symbols().get(6).name());
				assertEquals(new EcoffDebug.Type(7, 1), f.symbols().get(6).type());
				assertEquals("word", f.symbols().get(7).name());
				assertEquals("note", f.symbols().get(10).name());
				assertEquals(EcoffDebug.ST_LABEL, f.symbols().get(10).kind());
				assertEquals("external", d.externals().get(0).name());
			}
		}
	}

	@Test
	public void testParametersStopAtTheMatchingProcedureEnd() throws Exception {
		byte[] bytes = fixtureWithParameters(false, true);
		// Turn alpha into run's stEnd: beta and tmp must not attach to any procedure.
		sym(ByteBuffer.wrap(bytes), PSYM + 24, 12, 16, 8, 1, 1, false);
		var f = parseWithParameters(bytes, false).files().get(0);
		var run = f.procedures().get(0);
		assertEquals("run", run.symbol().name());
		assertTrue(run.parameters().isEmpty());
		assertTrue(run.locals().isEmpty());
	}

	@Test
	public void testParametersDoNotCrossIntoFollowingStaticData() throws Exception {
		byte[] bytes = fixtureWithParameters(false, true);
		// Remove run's stEnd: the procedure stays open, so everything up to the next
		// matching end is still associated, but the static data must never become a
		// parameter of a later procedure.
		ByteBuffer b = ByteBuffer.wrap(bytes);
		sym(b, PSYM + 60, 8, 16, 2, 2, 1, false); // replace stEnd with stStatic
		var f = parseWithParameters(bytes, false).files().get(0);
		var run = f.procedures().get(0);
		assertEquals(2, run.parameters().size()); // alpha and beta precede the replacement
		// hidden still opens after its own record; its parameters remain empty.
		assertTrue(f.procedures().get(1).parameters().isEmpty());
	}

	@Test
	public void testParameterFixtureTruncationAtEveryByte() throws Exception {
		byte[] b = fixtureWithParameters(false, true);
		for (int i = 0; i < b.length; i++) {
			byte[] truncated = Arrays.copyOf(b, i);
			assertThrows(IOException.class, () -> parseWithParameters(truncated, false));
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

	/** IRIX MIPSpro uses a non-zero HDRR version stamp (0x715 / 0x728). */
	@Test
	public void testIrixNonZeroVersionStampIsAccepted() throws Exception {
		for (int vstamp : new int[] {0x715, 0x728}) {
			for (boolean little : new boolean[] {false, true}) {
				byte[] bytes = fixture(little, !little);
				ByteBuffer.wrap(bytes)
						.order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN)
						.putShort(2, (short)vstamp);
				var f = parse(bytes, little).files().get(0);
				assertEquals("run", f.procedures().get(0).symbol().name());
				assertEquals(16, f.procedures().get(0).size());
			}
		}
	}

	@Test
	public void testInterleavedLabelAndStaticDoNotTruncateProcedure() throws Exception {
		for (boolean little : new boolean[] {false, true}) {
			for (boolean auxBig : new boolean[] {false, true}) {
				var f = parse(fixtureWithInterleavedRecords(little, auxBig), little).files().get(0);
				assertEquals(EcoffDebug.ST_LABEL, f.symbols().get(2).kind());
				assertEquals(EcoffDebug.ST_STATIC, f.symbols().get(3).kind());
				var run = f.procedures().get(0);
				assertEquals("run", run.symbol().name());
				assertEquals(0x18, run.size());
			}
		}
	}

	@Test
	public void testOutOfOrderGroupedProceduresAreRecovered() throws Exception {
		for (boolean little : new boolean[] {false, true}) {
			for (boolean auxBig : new boolean[] {false, true}) {
				var f =
					parse(fixtureWithOutOfOrderProcedures(little, auxBig), little).files().get(0);
				assertEquals(2, f.procedures().size());
				var a = f.procedures().get(0);
				var b = f.procedures().get(1);
				assertEquals("run", a.symbol().name());
				assertEquals(0x1000, a.address());
				assertEquals(0x20, a.size());
				assertEquals("two", b.symbol().name());
				assertEquals(0x1010, b.address());
				assertEquals(0x30, b.size());
			}
		}
	}
}
