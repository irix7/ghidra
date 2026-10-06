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

import java.util.ArrayList;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.VariableStorage;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Tests for the n32 calling convention described by {@code mips64_32_n32.cspec}
 * (language {@code MIPS:BE:64:64-32addr}, compiler spec {@code n32}).
 *
 * The assertions encode the SGI MIPSpro N32 ABI (SGI part number 007-2816-005),
 * cross-checked against clang 21 -mabi=n32 -EB code generation:
 * <ul>
 * <li>The eight argument registers are an image of the first eight doublewords of the
 * argument structure; doubleword i is passed in either $4+i or $f12+i, so every argument
 * consumes one slot of both register classes (a float argument makes the corresponding
 * general register unavailable).</li>
 * <li>Composite arguments are sequences of 64-bit chunks: a chunk consisting solely of a
 * double field goes in the floating point register of its slot, everything else goes in
 * the integer register; partial chunks are left-justified in their register; excess
 * chunks spill to the stack.</li>
 * <li>Structs with one or two floating point fields (of the same primitive type) are
 * returned in $f0/$f2; other composite results of at most 128 bits are returned in
 * $2/$3, left-justified in partial registers; larger results use an implicit first
 * parameter pointing at caller-reserved storage, with the pointer returned in $2.</li>
 * <li>Floating point parameters in the variable part of an argument list are passed in
 * integer registers.</li>
 * </ul>
 */
public class N32CallingConventionTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private PrototypeModel model;
	private DataTypeManager dtm;

	@Before
	public void setUp() throws Exception {
		// ProgramBuilder._MIPS_6432 = "MIPS:BE:64:64-32addr"; the ldefs default compiler
		// spec for that language is "o64", so request the "n32" spec explicitly.
		builder = new ProgramBuilder("n32 cspec", ProgramBuilder._MIPS_6432, "n32", this);
		dtm = builder.getProgram().getDataTypeManager();
		model = builder.getProgram()
				.getCompilerSpec()
				.getDefaultCallingConvention();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private Structure struct(String name, DataType... fields) {
		return builder.tx(() -> {
			Structure s = new StructureDataType(name, 0);
			for (DataType f : fields) {
				s.add(f);
			}
			return (Structure) dtm.resolve(s, DataTypeConflictHandler.DEFAULT_HANDLER);
		});
	}

	private void assertVarnode(VariableStorage storage, int index, String regName, int offset,
			int size) {
		Varnode[] vns = storage.getVarnodes();
		assertTrue("expected more varnodes in " + storage, index < vns.length);
		assertEquals(builder.getProgram().getLanguage().getRegister(regName).getAddress()
				.add(offset), vns[index].getAddress());
		assertEquals(size, vns[index].getSize());
	}

	private void assertNumVarnodes(VariableStorage storage, int count) {
		assertEquals(count, storage.getVarnodes().length);
	}

	private VariableStorage[] storageOf(DataType... types) {
		return model.getStorageLocations(builder.getProgram(), types, true);
	}

	@Test
	public void testSmallStructReturnLeftJustifiedInV0() {
		Structure s3 = struct("S3", CharDataType.dataType, CharDataType.dataType,
			CharDataType.dataType);
		VariableStorage[] locs = storageOf(s3);
		// clang: v0 = 0x010203 << 40 (struct bytes in the most significant 3 bytes of v0)
		assertNumVarnodes(locs[0], 1);
		assertVarnode(locs[0], 0, "v0", 0, 3);
	}

	@Test
	public void testTwelveByteStructReturnInV0V1() {
		Structure s12 = struct("S12", IntegerDataType.dataType, IntegerDataType.dataType,
			IntegerDataType.dataType);
		VariableStorage[] locs = storageOf(s12);
		// bytes 0-7 in v0, bytes 8-11 left-justified in v1
		assertNumVarnodes(locs[0], 2);
		assertVarnode(locs[0], 0, "v0", 0, 8);
		assertVarnode(locs[0], 1, "v1", 0, 4);
	}

	@Test
	public void testSingleDoubleStructReturnInF0() {
		Structure sd = struct("SD", DoubleDataType.dataType);
		VariableStorage[] locs = storageOf(sd);
		assertNumVarnodes(locs[0], 1);
		assertVarnode(locs[0], 0, "f0", 0, 8);
	}

	@Test
	public void testTwoDoubleStructReturnInF0F2() {
		Structure dd = struct("DD", DoubleDataType.dataType, DoubleDataType.dataType);
		VariableStorage[] locs = storageOf(dd);
		assertNumVarnodes(locs[0], 2);
		assertVarnode(locs[0], 0, "f0", 0, 8);
		assertVarnode(locs[0], 1, "f2", 0, 8);
	}

	@Test
	public void testMixedFloatIntStructReturnInV0V1() {
		// A struct whose fields are not all of one floating point type does not use
		// the floating point registers.
		Structure di = struct("DI", DoubleDataType.dataType, IntegerDataType.dataType);
		VariableStorage[] locs = storageOf(di);
		assertNumVarnodes(locs[0], 2);
		assertVarnode(locs[0], 0, "v0", 0, 8);
		assertVarnode(locs[0], 1, "v1", 0, 4);
	}

	@Test
	public void testLargeStructReturnHiddenPointerInA0() {
		Structure s24 = struct("S24", LongLongDataType.dataType, LongLongDataType.dataType,
			LongLongDataType.dataType);
		VariableStorage[] locs = storageOf(s24);
		// Return storage is the hidden pointer in a0, returned again in v0.
		assertEquals(2, locs.length);
		assertNumVarnodes(locs[0], 1);
		assertVarnode(locs[0], 0, "v0", 4, 4);
		assertNumVarnodes(locs[1], 1);
		assertVarnode(locs[1], 0, "a0", 4, 4);
	}

	@Test
	public void testSmallStructArgLeftJustifiedThenInt() {
		Structure s3 = struct("S3", CharDataType.dataType, CharDataType.dataType,
			CharDataType.dataType);
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, s3, IntegerDataType.dataType);
		assertNumVarnodes(locs[1], 1);
		assertVarnode(locs[1], 0, "a0", 0, 3);
		assertVarnode(locs[2], 0, "a1", 4, 4);
	}

	@Test
	public void testTwelveByteStructArgThenInt() {
		Structure s12 = struct("S12", IntegerDataType.dataType, IntegerDataType.dataType,
			IntegerDataType.dataType);
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, s12, IntegerDataType.dataType);
		assertNumVarnodes(locs[1], 2);
		assertVarnode(locs[1], 0, "a0", 0, 8);
		assertVarnode(locs[1], 1, "a1", 0, 4);
		assertVarnode(locs[2], 0, "a2", 4, 4);
	}

	@Test
	public void testTwentyFourByteStructArgThenInt() {
		Structure s24 = struct("S24", LongLongDataType.dataType, LongLongDataType.dataType,
			LongLongDataType.dataType);
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, s24, IntegerDataType.dataType);
		assertNumVarnodes(locs[1], 3);
		assertVarnode(locs[1], 0, "a0", 0, 8);
		assertVarnode(locs[1], 1, "a1", 0, 8);
		assertVarnode(locs[1], 2, "a2", 0, 8);
		assertVarnode(locs[2], 0, "a3", 4, 4);
	}

	@Test
	public void testFloatArgConsumesGeneralRegisterSlot() {
		// clang: f(float f, int i) passes f in f12 and i in a1 (not a0).
		// A 32-bit float occupies the low half of the 64-bit FPR (right-justified).
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, FloatDataType.dataType,
			IntegerDataType.dataType);
		assertVarnode(locs[1], 0, "f12", 4, 4);
		assertVarnode(locs[2], 0, "a1", 4, 4);
	}

	@Test
	public void testDoubleFieldStructArgGoesToFprSlot() {
		Structure sd = struct("SD", DoubleDataType.dataType);
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, sd, IntegerDataType.dataType);
		assertVarnode(locs[1], 0, "f12", 0, 8);
		assertVarnode(locs[2], 0, "a1", 4, 4);
	}

	@Test
	public void testDoubleFloatStructArgSplitsAcrossFprAndGpr() {
		Structure sdf = struct("SDF", DoubleDataType.dataType, FloatDataType.dataType);
		VariableStorage[] locs = storageOf(IntegerDataType.dataType, sdf, IntegerDataType.dataType);
		// chunk 0 (a whole double) in f12; chunk 1 (a float) left-justified in a1
		assertNumVarnodes(locs[1], 2);
		assertVarnode(locs[1], 0, "f12", 0, 8);
		assertVarnode(locs[1], 1, "a1", 0, 4);
		assertVarnode(locs[2], 0, "a2", 4, 4);
	}

	@Test
	public void testStructDoubleStructSlotOrdering() {
		Structure ii = struct("II", IntegerDataType.dataType, IntegerDataType.dataType);
		VariableStorage[] locs =
			storageOf(IntegerDataType.dataType, ii, DoubleDataType.dataType, ii);
		// clang: s1 in a0, d in f13 (slot 1), s2 in a2 (slot 2)
		assertVarnode(locs[1], 0, "a0", 0, 8);
		assertVarnode(locs[2], 0, "f13", 0, 8);
		assertVarnode(locs[3], 0, "a2", 0, 8);
	}

	@Test
	public void testVarargsFloatsPassedInIntegerRegisters() {
		// clang: use_va("%f %d %f", 1.5, 7, 2.5) passes the doubles in a1 and a3.
		DataType[] types = { IntegerDataType.dataType, PointerDataType.dataType,
			DoubleDataType.dataType, IntegerDataType.dataType, DoubleDataType.dataType };
		PrototypePieces pp = new PrototypePieces(model, types, null);
		pp.firstVarArgSlot = 1;
		ArrayList<ParameterPieces> res = new ArrayList<>();
		model.assignParameterStorage(pp, dtm, res, true);
		assertEquals(5, res.size());
		assertVarnode(res.get(2).getVariableStorage(builder.getProgram()), 0, "a1", 0, 8);
		assertVarnode(res.get(3).getVariableStorage(builder.getProgram()), 0, "a2", 4, 4);
		assertVarnode(res.get(4).getVariableStorage(builder.getProgram()), 0, "a3", 0, 8);
	}

	@Test
	public void testVarargsStructPassedInIntegerRegisters() {
		Structure s12 = struct("S12", IntegerDataType.dataType, IntegerDataType.dataType,
			IntegerDataType.dataType);
		DataType[] types = { IntegerDataType.dataType, PointerDataType.dataType, s12 };
		PrototypePieces pp = new PrototypePieces(model, types, null);
		pp.firstVarArgSlot = 1;
		ArrayList<ParameterPieces> res = new ArrayList<>();
		model.assignParameterStorage(pp, dtm, res, true);
		assertEquals(3, res.size());
		VariableStorage storage = res.get(2).getVariableStorage(builder.getProgram());
		assertNumVarnodes(storage, 2);
		assertVarnode(storage, 0, "a1", 0, 8);
		assertVarnode(storage, 1, "a2", 0, 4);
	}
}
