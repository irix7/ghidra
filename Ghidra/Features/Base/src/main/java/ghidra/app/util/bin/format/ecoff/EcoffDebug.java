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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Bounded reader for the 32-bit MIPS ECOFF symbolic format used in ELF .mdebug.
 * The provider contains only the section; HDRR offsets are absolute within the original file.
 *
 * Independently implemented from format descriptions in binutils include/coff/{sym.h,
 * symconst.h,mips.h,ecoff.h} (sourceware.org/git/binutils-gdb.git). Also consulted
 * astrelsky/ghidra_mdebug (EcoffHdrr/Fdr/Pdr) and chaoticgd/ccc (mdebug_section.cpp,
 * mdebug_importer.cpp), both on github.com. No implementation code is copied.
 * Procedure end and auxiliary semantics were also checked against GDB's mdebugread.c
 * on the binutils-2_40-branch and the SGI Mdebug documentation (David Anderson's
 * Mdebug.ps): stParam/stLocal records are attached to their enclosing text procedure
 * and their values are register numbers (scRegister/scVarRegister) or frame offsets
 * from the virtual frame pointer (any other storage class).
 * Unlike CCC, moved sections with stale offsets are not heuristically repaired.
 */
public final class EcoffDebug {
	public static final int HEADER_SIZE = 96;
	public static final int INDEX_NIL = 0xfffff;
	public static final int ST_NIL = 0;
	public static final int ST_GLOBAL = 1;
	public static final int ST_STATIC = 2;
	public static final int ST_PARAM = 3;
	public static final int ST_LOCAL = 4;
	public static final int ST_LABEL = 5;
	public static final int ST_PROC = 6;
	public static final int ST_BLOCK = 7;
	public static final int ST_END = 8;
	public static final int ST_MEMBER = 9;
	public static final int ST_TYPEDEF = 10;
	public static final int ST_FILE = 11;
	public static final int ST_STATIC_PROC = 14;
	public static final int ST_CONSTANT = 15;
	public static final int SC_TEXT = 1;
	public static final int SC_DATA = 2;
	public static final int SC_BSS = 3;
	public static final int SC_REGISTER = 4;
	public static final int SC_ABS = 5;
	public static final int SC_VAR = 16;
	public static final int SC_VAR_REGISTER = 19;
	private static final int MAX_RECORDS = 2_000_000;
	private static final int MAX_STRING = 65536;
	private static final long MAX_DECODED_STRING_BYTES = 64 * 1024 * 1024;

	/** Unsupported auxiliary encodings have no recovered type, not an invented placeholder. */
	public record Type(int basicType, int pointerDepth) {}
	public record Symbol(
		String name, long value, int kind, int storage, int index, Type type, boolean external) {
		public boolean isProcedure() {
			return kind == ST_PROC || kind == ST_STATIC_PROC;
		}
		public boolean isStab() {
			return (index & 0xfff00) == 0x8f300;
		}
	}
	public record Procedure(long address, Symbol symbol, long size, int frameSize,
		int frameRegister, int returnRegister, int lineLow, int lineHigh,
		List<Symbol> parameters, List<Symbol> locals) {}
	public record FileDescriptor(String name, long address, int language, boolean auxBigEndian,
		List<Symbol> symbols, List<Procedure> procedures) {}

	private record Table(long offset, long count, int stride) {}
	private final BinaryReader reader;
	private final ByteProvider provider;
	private long decodedStringBytes;
	private final Table[] tables = new Table[11];
	private final List<FileDescriptor> files = new ArrayList<>();
	private final List<Symbol> externals = new ArrayList<>();

	private EcoffDebug(ByteProvider provider, long origin, boolean littleEndian)
		throws IOException {
		this.provider = provider;
		reader = new BinaryReader(provider, littleEndian);
		if (origin < 0 || provider.length() < HEADER_SIZE ||
			reader.readUnsignedShort(0) != 0x7009) {
			throw new IOException("Invalid or unsupported ECOFF symbolic header");
		}
		// Compressed lines use cbLine, not ilineMax, as their byte count.
		int[] countFields = {8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88};
		int[] strides = {1, 8, 52, 12, 12, 4, 1, 1, 72, 4, 16};
		long records = 0;
		for (int i = 0; i < tables.length; i++) {
			long count = reader.readUnsignedInt(countFields[i]);
			long absolute = reader.readUnsignedInt(countFields[i] + 4);
			long offset = absolute - origin;
			if (count != 0 && (offset < HEADER_SIZE || offset > provider.length() ||
								  count > (provider.length() - offset) / strides[i])) {
				throw new IOException("ECOFF table " + i + " exceeds .mdebug bounds");
			}
			tables[i] = new Table(offset, count, strides[i]);
			if (i != 0 && i != 6 && i != 7) {
				records += count;
			}
		}
		if (records > MAX_RECORDS) {
			throw new IOException("ECOFF record limit exceeded");
		}
		for (int i = 0; i < tables.length; i++) {
			Table a = tables[i];
			for (int j = i + 1; j < tables.length; j++) {
				Table b = tables[j];
				if (a.count != 0 && b.count != 0 && a.offset < b.offset + b.count * b.stride &&
					b.offset < a.offset + a.count * a.stride) {
					throw new IOException("Overlapping ECOFF tables");
				}
			}
		}
	}

	/** Parse and validate before any program changes. Does not close the caller's provider. */
	public static EcoffDebug parse(ByteProvider section, long fileOffset, boolean littleEndian,
		TaskMonitor monitor) throws IOException, CancelledException {
		monitor.checkCanceled();
		EcoffDebug result = new EcoffDebug(section, fileOffset, littleEndian);
		result.read(monitor);
		return result;
	}

	public List<FileDescriptor> files() {
		return Collections.unmodifiableList(files);
	}
	public List<Symbol> externals() {
		return Collections.unmodifiableList(externals);
	}

	private long at(int table, long index) throws IOException {
		Table t = tables[table];
		if (index < 0 || index >= t.count) {
			throw new IOException("Invalid ECOFF table " + table + " index " + index);
		}
		return t.offset + index * t.stride;
	}

	private void slice(int table, long base, long count) throws IOException {
		if (base > tables[table].count || count > tables[table].count - base) {
			throw new IOException("Invalid ECOFF file descriptor slice for table " + table);
		}
	}

	private String string(int table, long base, long size, long index) throws IOException {
		if (index == 0xffffffffL) {
			return "";
		}
		if (index >= size) {
			throw new IOException("Invalid ECOFF string index");
		}
		long start = at(table, base + index);
		int limit = (int)Math.min(size - index, MAX_STRING);
		// Read in bounded chunks, so a short string does not read the entire string table.
		ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(limit, 256));
		int used = 0;
		while (used < limit) {
			int n = Math.min(256, limit - used);
			byte[] chunk = provider.readBytes(start + used, n);
			for (int j = 0; j < n; j++) {
				if (chunk[j] == 0) {
					decodedStringBytes += used + j;
					if (decodedStringBytes > MAX_DECODED_STRING_BYTES) {
						throw new IOException("ECOFF decoded string limit exceeded");
					}
					bytes.write(chunk, 0, j);
					return bytes.toString(StandardCharsets.UTF_8);
				}
			}
			bytes.write(chunk, 0, n);
			used += n;
		}
		throw new IOException("Unterminated or oversized ECOFF string");
	}

	private Symbol symbol(long pos, int stringTable, long stringBase, long stringSize, long auxBase,
		long auxCount, boolean auxBig, boolean external) throws IOException {
		long bits = reader.readUnsignedInt(pos + 8);
		boolean little = reader.isLittleEndian();
		int kind = (int)(little ? bits & 63 : bits >>> 26);
		int storage = (int)(little ? (bits >>> 6) & 31 : (bits >>> 21) & 31);
		int index = (int)(little ? bits >>> 12 : bits & INDEX_NIL);
		Type type = null;
		boolean stab = (index & 0xfff00) == 0x8f300;
		if (!stab && index != INDEX_NIL &&
			(kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == ST_PROC ||
				kind == ST_STATIC_PROC || kind == 9 || kind == 10)) {
			long typeIndex = (long)index + ((kind == ST_PROC || kind == ST_STATIC_PROC) ? 1 : 0);
			if (typeIndex < auxCount) {
				type = type(auxBase + typeIndex, auxBig);
			}
		}
		return new Symbol(string(stringTable, stringBase, stringSize, reader.readUnsignedInt(pos)),
			reader.readUnsignedInt(pos + 4), kind, storage, index, type, external);
	}

	private Type type(long index, boolean big) throws IOException {
		byte[] tir = provider.readBytes(at(5, index), 4);
		int flags = Byte.toUnsignedInt(tir[0]);
		if ((flags & (big ? 0xc0 : 3)) != 0) {
			return null; // Bitfields and continued qualifier records need more auxiliary decoding.
		}
		int basic = big ? flags & 63 : flags >>> 2;
		if (!(basic >= 1 && basic <= 11 || basic >= 26 && basic <= 28 ||
				basic >= 30 && basic <= 36)) {
			return null; // Aggregate and relative type references are not scalar types.
		}
		int pointers = 0;
		int[] order = {2, 3, 1}; // tq0/1, tq2/3, tq4/5, not physical byte order.
		for (int byteIndex : order) {
			int b = Byte.toUnsignedInt(tir[byteIndex]);
			for (int j = 0; j < 2; j++) {
				int q = (b >>> ((big ? 1 - j : j) * 4)) & 15;
				if (q == 1) {
					pointers++;
				}
				else if (q != 0 && q != 5 && q != 6) {
					return null;
				}
			}
		}
		return new Type(basic, pointers);
	}

	private void read(TaskMonitor monitor) throws IOException, CancelledException {
		// External symbols precede file parsing because PDRs in stripped files refer to EXTRs.
		for (int i = 0; i < tables[10].count; i++) {
			monitor.checkCanceled();
			long pos = at(10, i);
			int ifd = reader.readShort(pos + 2);
			if (ifd < -1 || ifd >= tables[8].count) {
				throw new IOException("Invalid ECOFF external file index");
			}
			long auxBase = 0, auxCount = 0;
			boolean auxBig = false;
			if (ifd >= 0) {
				long fd = at(8, ifd);
				auxBase = reader.readUnsignedInt(fd + 44);
				auxCount = reader.readUnsignedInt(fd + 48);
				slice(5, auxBase, auxCount);
				auxBig = auxBig(fd);
			}
			externals.add(symbol(pos + 4, 7, 0, tables[7].count, auxBase, auxCount, auxBig, true));
		}
		BitSet ownedSymbols = new BitSet(), ownedProcedures = new BitSet();
		monitor.initialize(tables[8].count);
		for (int i = 0; i < tables[8].count; i++) {
			monitor.checkCanceled();
			long fd = at(8, i);
			long ss = reader.readUnsignedInt(fd + 8), cbSs = reader.readUnsignedInt(fd + 12);
			long symBase = reader.readUnsignedInt(fd + 16), symCount =
																reader.readUnsignedInt(fd + 20);
			long auxBase = reader.readUnsignedInt(fd + 44), auxCount =
																reader.readUnsignedInt(fd + 48);
			int pdBase = reader.readUnsignedShort(fd + 40), pdCount =
																reader.readUnsignedShort(fd + 42);
			slice(6, ss, cbSs);
			slice(3, symBase, symCount);
			slice(2, pdBase, pdCount);
			slice(5, auxBase, auxCount);
			slice(9, reader.readUnsignedInt(fd + 52), reader.readUnsignedInt(fd + 56));
			slice(4, reader.readUnsignedInt(fd + 32), reader.readUnsignedInt(fd + 36));
			slice(0, reader.readUnsignedInt(fd + 64), reader.readUnsignedInt(fd + 68));
			String name = string(6, ss, cbSs, reader.readUnsignedInt(fd + 4));
			boolean auxBig = auxBig(fd);
			int flags = Byte.toUnsignedInt(reader.readByte(fd + 60));
			int language = reader.isLittleEndian() ? flags & 31 : flags >>> 3;
			List<Symbol> symbols = new ArrayList<>();
			for (int j = 0; j < symCount; j++) {
				monitor.checkCanceled();
				int global = (int)symBase + j;
				if (ownedSymbols.get(global)) {
					throw new IOException("Overlapping ECOFF file symbol slices");
				}
				ownedSymbols.set(global);
				symbols.add(symbol(at(3, global), 6, ss, cbSs, auxBase, auxCount, auxBig, false));
			}
			// stParam and stLocal records belong to the open text procedure: the last
			// stProc/stStaticProc before a matching stEnd (whose index references the
			// procedure's local record, per the SGI mdebug specification). Nested blocks
			// do not detach them, since only a matching procedure stEnd closes a procedure.
			Map<Integer, List<Symbol>> parametersByProc = new HashMap<>();
			Map<Integer, List<Symbol>> localsByProc = new HashMap<>();
			Deque<Integer> openProcedures = new ArrayDeque<>();
			for (int j = 0; j < symbols.size(); j++) {
				monitor.checkCanceled();
				Symbol s = symbols.get(j);
				if (s.isProcedure() && s.storage() == SC_TEXT && !s.isStab()) {
					openProcedures.push(j);
					parametersByProc.put(j, new ArrayList<>());
					localsByProc.put(j, new ArrayList<>());
				}
				else if (s.kind() == ST_END && !openProcedures.isEmpty() &&
					s.index() == openProcedures.peek()) {
					openProcedures.pop();
				}
				else if (!openProcedures.isEmpty()) {
					if (s.kind() == ST_PARAM) {
						parametersByProc.get(openProcedures.peek()).add(s);
					}
					else if (s.kind() == ST_LOCAL) {
						localsByProc.get(openProcedures.peek()).add(s);
					}
				}
			}
			List<Procedure> procedures = new ArrayList<>();
			for (int j = 0; j < pdCount; j++) {
				monitor.checkCanceled();
				if (ownedProcedures.get(pdBase + j)) {
					throw new IOException("Overlapping ECOFF file procedure slices");
				}
				ownedProcedures.set(pdBase + j);
				long pd = at(2, pdBase + j);
				int isym = reader.readInt(pd + 4);
				Symbol sym = null;
				long size = 0;
				if (isym != -1) {
					List<Symbol> source = symCount == 0 ? externals : symbols;
					if (isym < 0 || isym >= source.size()) {
						throw new IOException("Invalid ECOFF procedure symbol index");
					}
					sym = source.get(isym);
					// PDRs describe every text label, including stripped external labels.
					if ((!sym.isProcedure() && sym.kind != ST_LABEL) ||
						sym.storage != SC_TEXT || sym.isStab()) {
						throw new IOException("ECOFF descriptor must reference a text procedure or label");
					}
					if (symCount != 0 && sym.isProcedure() && !sym.isStab() &&
						sym.index != INDEX_NIL && sym.index < auxCount) {
						BinaryReader auxReader = new BinaryReader(provider, !auxBig);
						long end = auxReader.readUnsignedInt(at(5, auxBase + sym.index));
						if (end > isym + 1 && end <= symbols.size()) {
							Symbol endSymbol = symbols.get((int)end - 1);
							if (endSymbol.kind == ST_END && endSymbol.storage == SC_TEXT &&
								endSymbol.index == isym) {
								size =
									endSymbol.value; // stEnd of a procedure stores its byte size.
							}
						}
					}
				}
				procedures.add(
					new Procedure(reader.readUnsignedInt(pd), sym, size, reader.readInt(pd + 32),
						reader.readUnsignedShort(pd + 36), reader.readUnsignedShort(pd + 38),
						reader.readInt(pd + 40), reader.readInt(pd + 44),
						List.copyOf(parametersByProc.getOrDefault(isym, List.of())),
						List.copyOf(localsByProc.getOrDefault(isym, List.of()))));
			}
			files.add(new FileDescriptor(name, reader.readUnsignedInt(fd), language, auxBig,
				List.copyOf(symbols), List.copyOf(procedures)));
			monitor.incrementProgress(1);
		}
	}

	private boolean auxBig(long fd) throws IOException {
		int flags = Byte.toUnsignedInt(reader.readByte(fd + 60));
		return (flags & (reader.isLittleEndian() ? 0x80 : 1)) != 0;
	}
}
