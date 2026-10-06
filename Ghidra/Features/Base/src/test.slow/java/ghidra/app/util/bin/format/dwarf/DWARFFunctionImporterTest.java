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

import static ghidra.app.util.bin.format.dwarf.DWARFSourceLanguage.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttributeId.*;
import static ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.*;

public class DWARFFunctionImporterTest extends DWARFTestBase {
	@Test
	public void testUnspecifiedAssemblySignatureRemainsUnlocked() throws Exception {
		DebugInfoEntry unspecified =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_unspecified_type).create();
		newSubprogram("asmfn", unspecified, 0x410, 10)
				.addBoolean(DW_AT_noreturn, true)
				.create();
		dwarfProg.getImportOptions().setCreateFuncSignatures(true);

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals("asmfn", function.getName());
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(Undefined.isUndefined(function.getReturnType()));
		assertFalse(function.hasCustomVariableStorage());
		assertTrue(function.hasNoReturn());
		assertEquals(new AddressSet(addr(0x410), addr(0x419)), function.getBody());
		assertNull(dataMgr.getDataType(uncatCP, "asmfn"));
	}

	@Test
	public void testMipsAssemblyWithoutReturnTypeRemainsUnlocked() throws Exception {
		addCompUnit(DW_LANG_Mips_Assembler);
		newUntypedSubprogram("asmfn").create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertTrue(Undefined.isUndefined(function.getReturnType()));
		assertFalse(function.hasCustomVariableStorage());
	}

	@Test
	public void testEmptyAssemblyDIEDoesNotOverwriteExistingSignature() throws Exception {
		Function existing = program.getListing()
				.createFunction("oldname", addr(0x410), new AddressSet(addr(0x410)),
					SourceType.ANALYSIS);
		existing.updateFunction(CompilerSpec.CALLING_CONVENTION_cdecl,
			new ReturnParameterImpl(IntegerDataType.dataType, program),
			List.of(new ParameterImpl("arg", IntegerDataType.dataType, program)),
			Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		existing.setNoReturn(true);
		existing.setVarArgs(true);
		addCompUnit(DW_LANG_Mips_Assembler);
		newUntypedSubprogram("asmfn").create();

		importFunctions();

		assertEquals("asmfn", existing.getName());
		assertEquals(SourceType.ANALYSIS, existing.getSignatureSource());
		assertEquals("int", existing.getReturnType().getName());
		assertEquals(1, existing.getParameterCount());
		assertEquals("arg", existing.getParameter(0).getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_cdecl, existing.getCallingConventionName());
		assertTrue(existing.hasNoReturn());
		assertTrue(existing.hasVarArgs());
	}

	@Test
	public void testPrototypedVoidSignatureStillImported() throws Exception {
		newUntypedSubprogram("foo").addBoolean(DW_AT_prototyped, true).create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertTrue(function.getReturnType() instanceof VoidDataType);
		assertEquals(0, function.getParameterCount());
	}

	@Test
	public void testPrototypedUnspecifiedReturnStillImported() throws Exception {
		DebugInfoEntry unspecified =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_unspecified_type).create();
		newSubprogram("foo", unspecified, 0x410, 10)
				.addBoolean(DW_AT_prototyped, true)
				.create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertTrue(function.getReturnType() instanceof VoidDataType);
	}

	@Test
	public void testAssemblyInheritsPrototypeFromSpecification() throws Exception {
		addCompUnit(DW_LANG_Mips_Assembler);
		DebugInfoEntry declaration = new DIECreator(dwarfProg, DWARFTag.DW_TAG_subprogram)
				.addString(DW_AT_name, "asmfn")
				.addBoolean(DW_AT_declaration, true)
				.addBoolean(DW_AT_prototyped, true)
				.create();
		newUntypedSubprogram("asmfn").addRef(DW_AT_specification, declaration).create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertTrue(function.getReturnType() instanceof VoidDataType);
	}

	@Test
	public void testUnprototypedCVoidSignatureStillImported() throws Exception {
		newUntypedSubprogram("foo").create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertTrue(function.getReturnType() instanceof VoidDataType);
	}

	@Test
	public void testAssemblyWithExplicitReturnTypeStillImported() throws Exception {
		addCompUnit(DW_LANG_Mips_Assembler);
		newSubprogram("asmfn", addInt(), 0x410, 10).create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertEquals("int", function.getReturnType().getName());
	}

	@Test
	public void testUnspecifiedReturnWithFormalParameterStillImported() throws Exception {
		DebugInfoEntry unspecified =
			new DIECreator(dwarfProg, DWARFTag.DW_TAG_unspecified_type).create();
		DebugInfoEntry functionDIE = newSubprogram("foo", unspecified, 0x410, 10).create();
		newFormalParam(functionDIE, "arg", addInt()).create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertEquals(1, function.getParameterCount());
	}

	@Test
	public void testAssemblyWithVarargsStillImported() throws Exception {
		addCompUnit(DW_LANG_Mips_Assembler);
		DebugInfoEntry functionDIE = newUntypedSubprogram("asmfn").create();
		new DIECreator(dwarfProg, DWARFTag.DW_TAG_unspecified_parameters)
				.setParent(functionDIE)
				.create();

		importFunctions();

		Function function = program.getListing().getFunctionAt(addr(0x410));
		assertEquals(SourceType.IMPORTED, function.getSignatureSource());
		assertTrue(function.hasVarArgs());
	}

	private DIECreator newUntypedSubprogram(String name) {
		ensureCompUnit();
		return new DIECreator(dwarfProg, DWARFTag.DW_TAG_subprogram)
				.addString(DW_AT_name, name)
				.addUInt(DW_AT_low_pc, 0x410)
				.addUInt(DW_AT_high_pc, 10);
	}

	@Test
	public void testRustMethod_HasParamDefs()
			throws CancelledException, IOException, DWARFException {
		// test that Ghidra functions in a Rust compilation unit do have their info set
		// if they look like they have normal param info

		addCompUnit(DW_LANG_Rust);

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE, instr(DW_OP_fbreg, 0x6c)).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());
	}

	@Test
	public void testNamespace_with_reserved_chars()
			throws CancelledException, IOException, DWARFException {
		// simulate what happens when a C++ operator/ or a templated classname
		// that contains a namespace template argument (templateclass<ns1::ns2::argclass>)
		// is encountered and a Ghidra namespace is created

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1DIE = newStruct("mystruct::operator/()", 100).create();
		DebugInfoEntry nestedStructPtrDIE = addFwdPtr(1);
		DebugInfoEntry nestedStructDIE =
			newStruct("nested_struct", 10).setParent(struct1DIE).create();
		newMember(nestedStructDIE, "blah1", intDIE, 0).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(nestedStructDIE).create();
		newFormalParam(fooDIE, "this", nestedStructPtrDIE, instr(DW_OP_fbreg, 0x6c)).create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();
		newMember(struct1DIE, "f3", nestedStructDIE, 20).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		List<Namespace> nsParts = NamespaceUtils.getNamespaceParts(fooFunc.getParentNamespace());

		assertEquals("foo", fooFunc.getName());
		assertEquals("nested_struct",
			((Pointer) fooFunc.getParameter(0).getDataType()).getDataType().getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
		assertEquals("nested_struct", nsParts.get(nsParts.size() - 1).getName());
		assertEquals("mystruct::operator/()", nsParts.get(nsParts.size() - 2).getName());

		// Test that VariableUtilities can find the structure for the this* pointer
		Structure nestedStructDT1 = (Structure) dataMgr
				.getDataType(new CategoryPath(uncatCP, "mystruct::operator/()"), "nested_struct");
		Structure nestedStructDT2 = VariableUtilities.findExistingClassStruct(fooFunc);
		assertTrue(nestedStructDT1 == nestedStructDT2);
	}

	@Test
	public void testNoReturnFlag_True() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.addBoolean(DW_AT_noreturn, true);
		func.create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		assertTrue(fooFunc.hasNoReturn());
	}

	@Test
	public void testNoReturnFlag_False() throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DIECreator func = newSubprogram("foo", intDIE, 0x410, 10);
		func.create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		assertFalse(fooFunc.hasNoReturn());
	}

	@Test
	public void testDetailParamLocation_Converted_to_spill()
			throws CancelledException, IOException, DWARFException {
		// Test that a parameter's storage info is ignored if it looks invalid.
		// In this case, it refers to a location in the function's local variable area, so
		// it should have been converted to a spill local variable.

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE, instr(DW_OP_fbreg, 0x6c)) // fbreg -14, func local variable area
				.create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());

		assertFalse(fooParams[0].isStackVariable());  // was converted to register storage via default calling convention
	}

	@Test
	public void testDetailParamLocation_Used()
			throws CancelledException, IOException, DWARFException {
		// Test that a parameter's storage info is used if it looks valid and is present at
		// the start of the function.

		// TODO: need to also test location info from a debug_loc sequence that specifies a lexical offset

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10)
				.addBlockBytes(DW_AT_frame_base, instr(DW_OP_call_frame_cfa))
				.create();
		newFormalParam(fooDIE, "param1", intDIE, instr(DW_OP_fbreg, 0x8)) // fbreg +8, caller stack area
				.create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		DataType returnType = fooFunc.getReturnType();
		assertNotNull(returnType);
		assertEquals("int", returnType.getName());

		Parameter[] fooParams = fooFunc.getParameters();
		assertEquals(fooParams.length, 1);
		assertEquals("param1", fooParams[0].getName());
		assertEquals("int", fooParams[0].getDataType().getName());
		assertTrue(fooParams[0].isStackVariable());
		assertEquals(16 /* x86-64 static cfa 8 + fbreg 8 */, fooParams[0].getStackOffset());
	}

	@Test
	public void testThisParamDetect_NamedThis()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, "this", struct1PtrDIE, instr(DW_OP_fbreg, 0x6c)).create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ArtificalUnNamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, null, struct1PtrDIE, instr(DW_OP_fbreg, 0x6c))
				.addBoolean(DW_AT_artificial, true)
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ObjectPointer()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		long formalParamDIEOffset = dieContainer.getRelativeDIEOffset(2);
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10)
				.addRef(DW_AT_object_pointer, formalParamDIEOffset)
				.setParent(struct1DIE)
				.create();

		// give the param a non-this name to defeat the logic in DWARFUtil.isThisParam()
		newFormalParam(fooDIE, "not_the_normal_this_name", struct1PtrDIE, instr(DW_OP_fbreg, 0x6c))
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_ObjectPointer_inverse()
			throws CancelledException, IOException, DWARFException {
		// Test that Ghidra doesn't mark foo()'s param as 'this' when we don't have a DW_AT_obj_ptr
		// This is to ensure that testThisParamDetect_ObjectPointer() is a strong test
		// The data in this test needs to mirror the data in testThisParamDetect_ObjectPointer(),
		// minus the DW_AT_object_pointer attribute.
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10)
				//.addRef(DWARFAttribute.DW_AT_object_pointer, ??) don't add this attribute
				.setParent(struct1DIE)
				.create();

		// give the param a non-this name to defeat the logic in DWARFUtil.isThisParam()
		newFormalParam(fooDIE, "not_the_normal_this_name", struct1PtrDIE, instr(DW_OP_fbreg, 0x6c))
				.create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertNotEquals(CompilerSpec.CALLING_CONVENTION_thiscall,
			fooFunc.getCallingConventionName());
	}

	@Test
	public void testThisParamDetect_Unnamed()
			throws CancelledException, IOException, DWARFException {
		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry floatDIE = addFloat();
		DebugInfoEntry struct1PtrDIE = addFwdPtr(1);
		DebugInfoEntry struct1DIE = newStruct("mystruct", 100).create();

		DebugInfoEntry fooDIE =
			newSubprogram("foo", intDIE, 0x410, 10).setParent(struct1DIE).create();
		newFormalParam(fooDIE, null, struct1PtrDIE, instr(DW_OP_fbreg, 0x6c)).create();

		newMember(struct1DIE, "f1", intDIE, 0).create();
		newMember(struct1DIE, "f2", floatDIE, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_thiscall, fooFunc.getCallingConventionName());
	}

	@Test
	public void testParamNameConflictsWithLocalVar()
			throws CancelledException, IOException, DWARFException, InvalidInputException,
			OverlappingFunctionException, DuplicateNameException {
		Function initialFoo = program.getListing()
				.createFunction("foo", addr(0x410), new AddressSet(addr(0x410), addr(0x411)),
					SourceType.DEFAULT);

		DataType intDT = IntegerDataType.getSignedDataType(4, program.getDataTypeManager());
		initialFoo.addLocalVariable(new LocalVariableImpl("testxyz", intDT, -16, program),
			SourceType.USER_DEFINED);

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param1", intDIE).create();
		newFormalParam(fooDIE, "param2", intDIE).create();
		newFormalParam(fooDIE, "testxyz" /* should collide with local var */, intDIE).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);
		Parameter[] parameters = fooFunc.getParameters();
		assertEquals("param1", parameters[0].getName());
		assertEquals("param2", parameters[1].getName());
		assertEquals("testxyz_1", parameters[2].getName());
	}

	@Test
	public void testParamNameBadChars() throws CancelledException, IOException, DWARFException {

		DebugInfoEntry intDIE = addInt();
		DebugInfoEntry fooDIE = newSubprogram("foo", intDIE, 0x410, 10).create();
		newFormalParam(fooDIE, "param 1", intDIE).create();
		newFormalParam(fooDIE, "param\t2", intDIE).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));

		assertNotNull(fooFunc);
		Parameter[] parameters = fooFunc.getParameters();
		assertEquals("param_1", parameters[0].getName());
		assertEquals("param_2", parameters[1].getName());
	}

	@Test
	public void testBodyFixupDemotesNestedThunkInsideDwarfRange() throws Exception {
		// kmiss regression: shared-return eret thunks nested inside the authoritative
		// DWARF range must be demoted to labels so the DWARF body applies whole.
		Function target = program.getListing().createFunction("eret_target", addr(0x500),
			new AddressSet(addr(0x500), addr(0x507)), SourceType.ANALYSIS);
		program.getFunctionManager().createThunkFunction("locore_eret_0",
			program.getGlobalNamespace(), addr(0x420), new AddressSet(addr(0x420), addr(0x427)),
			target, SourceType.ANALYSIS);
		program.getFunctionManager().createThunkFunction("locore_eret_1",
			program.getGlobalNamespace(), addr(0x430), new AddressSet(addr(0x430), addr(0x437)),
			target, SourceType.ANALYSIS);

		DebugInfoEntry intDIE = addInt();
		newSubprogram("kmiss", intDIE, 0x410, 0x40).create();
		importFunctions();

		assertNull(program.getFunctionManager().getFunctionAt(addr(0x420)));
		assertNull(program.getFunctionManager().getFunctionAt(addr(0x430)));
		Symbol label0 = program.getSymbolTable().getPrimarySymbol(addr(0x420));
		assertNotNull(label0);
		assertEquals("locore_eret_0", label0.getName());
		Symbol label1 = program.getSymbolTable().getPrimarySymbol(addr(0x430));
		assertNotNull(label1);
		assertEquals("locore_eret_1", label1.getName());
		// thunk target outside the DWARF range is preserved
		assertNotNull(program.getFunctionManager().getFunctionAt(addr(0x500)));
		Function kmiss = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(kmiss);
		assertEquals(new AddressSet(addr(0x410), addr(0x44f)), kmiss.getBody());
	}

	@Test
	public void testBodyFixupPreservesThunkOutsideDwarfRange() throws Exception {
		Function target = program.getListing().createFunction("eret_target", addr(0x500),
			new AddressSet(addr(0x500), addr(0x507)), SourceType.ANALYSIS);
		program.getFunctionManager().createThunkFunction("outside_thunk",
			program.getGlobalNamespace(), addr(0x480), new AddressSet(addr(0x480), addr(0x487)),
			target, SourceType.ANALYSIS);

		DebugInfoEntry intDIE = addInt();
		newSubprogram("kmiss", intDIE, 0x410, 0x40).create();
		importFunctions();

		Function kept = program.getFunctionManager().getFunctionAt(addr(0x480));
		assertNotNull(kept);
		assertTrue(kept.isThunk());
		assertEquals("outside_thunk", kept.getName());
		Function kmiss = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(kmiss);
		assertEquals(new AddressSet(addr(0x410), addr(0x44f)), kmiss.getBody());
	}

	@Test
	public void testBodyFixupPreservesDwarfEntryThunk() throws Exception {
		DebugInfoEntry intDIE = addInt();
		newSubprogram("kmiss", intDIE, 0x410, 0x40).create();
		importFunctions();

		Function target = program.getListing().createFunction("eret_target", addr(0x500),
			new AddressSet(addr(0x500), addr(0x507)), SourceType.ANALYSIS);
		Function kmiss = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(kmiss);
		kmiss.setThunkedFunction(target);
		assertTrue(kmiss.isThunk());

		List<DWARFFunctionBodyFixupAnalyzer.FunctionBodyInfo> infos = new ArrayList<>();
		infos.add(new DWARFFunctionBodyFixupAnalyzer.FunctionBodyInfo(addr(0x410),
			new AddressSet(addr(0x410), addr(0x44f)), "kmiss"));
		Set<Address> entries = new HashSet<>(List.of(addr(0x410)));
		List<String> warnings = new ArrayList<>();
		DWARFFunctionBodyFixupAnalyzer.apply(program, infos, entries, warnings::add);

		Function kept = program.getFunctionManager().getFunctionAt(addr(0x410));
		assertNotNull(kept);
		assertTrue(kept.isThunk());
		assertEquals(new AddressSet(addr(0x410), addr(0x44f)), kept.getBody());
		assertTrue(warnings.isEmpty());
	}

	@Test
	public void testBodyFixupKeepsExistingLabelWhenDemotingThunk() throws Exception {
		Function target = program.getListing().createFunction("eret_target", addr(0x500),
			new AddressSet(addr(0x500), addr(0x507)), SourceType.ANALYSIS);
		program.getFunctionManager().createThunkFunction("locore_eret_0",
			program.getGlobalNamespace(), addr(0x420), new AddressSet(addr(0x420), addr(0x427)),
			target, SourceType.ANALYSIS);
		// address-taken label at the same address (eg. from a DWARF DW_TAG_label)
		program.getSymbolTable().createLabel(addr(0x420), "taken_label",
			program.getGlobalNamespace(), SourceType.IMPORTED);

		DebugInfoEntry intDIE = addInt();
		newSubprogram("kmiss", intDIE, 0x410, 0x40).create();
		importFunctions();

		assertNull(program.getFunctionManager().getFunctionAt(addr(0x420)));
		boolean hasTaken = false;
		boolean hasEret = false;
		for (Symbol s : program.getSymbolTable().getSymbols(addr(0x420))) {
			if ("taken_label".equals(s.getName())) {
				hasTaken = true;
			}
			if ("locore_eret_0".equals(s.getName())) {
				hasEret = true;
			}
		}
		assertTrue(hasTaken);
		assertTrue(hasEret);
		Function kmiss = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(kmiss);
		assertEquals(new AddressSet(addr(0x410), addr(0x44f)), kmiss.getBody());
	}
}
