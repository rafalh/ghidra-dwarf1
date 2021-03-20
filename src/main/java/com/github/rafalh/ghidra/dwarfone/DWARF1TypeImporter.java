package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.AttributeUtils;
import com.github.rafalh.ghidra.dwarfone.model.AttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.ConstAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.Format;
import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;
import com.github.rafalh.ghidra.dwarfone.model.LocationAtomOp;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;

public class DWARF1TypeImporter {
	
	private final DWARF1Program program;
	private final MessageLog log;
	private final CategoryPath categoryPath;
	private final DWARF1TypeManager dwarfTypeManager;
	private final DWARF1TypeExtractor typeExtractor;
	
	public DWARF1TypeImporter(DWARF1Program program, MessageLog log, DWARF1TypeManager dwarfTypeManager, DWARF1TypeExtractor typeExtractor) {
		this.program = program;
		this.log = log;
		this.dwarfTypeManager = dwarfTypeManager;
		this.typeExtractor = typeExtractor;
		this.categoryPath = new CategoryPath("/DWARF");
	}
	
	Optional<DataType> processTypeDebugInfoEntry(DebugInfoEntry die) {
		try {
			switch (die.getTag()) {
			case CLASS_TYPE:
			case STRUCTURE_TYPE:
				return processClassType(die);
			case UNION_TYPE:
				return processUnionType(die);
			case ENUMERATION_TYPE:
				return processEnumType(die);
			case ARRAY_TYPE:
				return processArrayType(die);
			case SUBROUTINE_TYPE:
				return processSubrountineType(die);
			case TYPEDEF:
			case STRING_TYPE:
			case POINTER_TYPE:
			case PTR_TO_MEMBER_TYPE:
			case SET_TYPE:
			case SUBRANGE_TYPE:
				// TODO
				log.appendMsg("Skipping type: " + die);
				return Optional.empty();
			default:
				// skip other tags
				return Optional.empty();
			}
		} catch (Exception e) {
			throw new RuntimeException("Failed to process type debug info entry " + die, e);
		}
	}
	
	private Optional<DataType> processSubrountineType(DebugInfoEntry die) {
		// Note: this is a function type, not a pointer to function type
		var dt = DataType.DEFAULT;
		dwarfTypeManager.registerType(die.getRef(), dt); // TODO
		return Optional.of(dt);
	}

	private Optional<DataType> processArrayType(DebugInfoEntry die) throws IOException {
		byte[] subscrData = die.<BlockAttributeValue>getAttribute(AttributeName.SUBSCR_DATA)
				.map(av -> av.get())
				.orElseThrow(() -> new IllegalArgumentException("array type without subscr_data " + die));
		var bp = new ByteArrayProvider(subscrData);
		List<Integer> dims = new ArrayList<>();
		DataType baseDt = null;
		BinaryReader br = new BinaryReader(bp, program.isLittleEndian());
		while (br.getPointerIndex() < bp.length()) {
			Format fmt = Format.decode(br.readNextByte());
			if (fmt == Format.ET) {
				Map.Entry<Integer, AttributeValue> attributeEntry = AttributeUtils.readAttribute(br);
				var at = AttributeName.decode(attributeEntry.getKey());
				var av = attributeEntry.getValue();
				baseDt = typeExtractor.extractDataType(at, av);
			} else if (fmt == Format.FT_C_C) {
				// type of index - unused
				FundamentalType.fromValue(br.readNextUnsignedShort());
				int minIndex = br.readNextInt();
				int maxIndex = br.readNextInt();
				int numElements = maxIndex - minIndex + 1;
				dims.add(numElements);
			} else {
				log.appendMsg("Unsupported format " + fmt + " in " + die);
				break;
			}
		}
		if (baseDt == null) {
			return Optional.empty();
		}
		DataType dt = baseDt;
		Collections.reverse(dims);
		for (int dim : dims) {
			if (dim <= 0) {
				log.appendMsg("Bad array dim " + dim + " in " + die);
				return Optional.empty();
			}
			dt = new ArrayDataType(dt, dim, -1);
		}
		dwarfTypeManager.registerType(die.getRef(), dt);
		return Optional.of(dt);
	}

	private Optional<DataType> processClassType(DebugInfoEntry die) {
		Optional<Number> byteSizeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.BYTE_SIZE).map(av -> av.get());
		if (byteSizeOpt.isEmpty()) {
			log.appendMsg("Skipping structure without size " + die);
			return Optional.empty();
		}
		String name = DWARF1ImportUtils.extractName(die)
				// FIXME: anonymous class?
				.filter(n -> !n.equals("@class"))
				.orElseGet(() -> "anon_" + die.getRef());
		int size = byteSizeOpt.get().intValue();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingDt = dataTypeManager.getDataType(categoryPath, name);
		if (existingDt != null) {
			// already imported
			dwarfTypeManager.registerType(die.getRef(), existingDt);
			return Optional.of(existingDt);
		}
		StructureDataType sdt = new StructureDataType(categoryPath, name, size, dataTypeManager);
		Structure newDt = (Structure) dataTypeManager.addDataType(sdt, DataTypeConflictHandler.DEFAULT_HANDLER);
		dwarfTypeManager.registerType(die.getRef(), newDt);
		//log.appendMsg("Struct " + name);
		for (DebugInfoEntry childDie : die.getChildren()) {
			switch (childDie.getTag()) {
			case MEMBER:
				processClassTypeMember(newDt, childDie);
				break;
			case INHERITANCE:
				processClassTypeInheritance(newDt, childDie);
				break;
			default:
				log.appendMsg("Unexpected child of class type: " + childDie.getTag());
			}
		}
		return Optional.of(newDt);
	}
	
	private void processClassTypeInheritance(Structure sdt, DebugInfoEntry die) {
		DataType baseDt = typeExtractor.extractDataType(die);
		sdt.replaceAtOffset(0, baseDt, -1, "__base", null);
	}

	private void processClassTypeMember(Structure sdt, DebugInfoEntry die) {
		String memberName = DWARF1ImportUtils.extractName(die).orElse(null);
		//log.appendMsg("Member " + memberName);
		DataType memberDt = typeExtractor.extractDataType(die);
		int memberOffset = extractMemberOffset(die);
		assert memberDt != null;
		if (memberOffset >= sdt.getLength()) {
			// TODO: memberDt.isDynamicallySized()
			return;
		}
		sdt.replaceAtOffset(memberOffset, memberDt, -1, memberName, null);
	}
	
	private Optional<DataType> processUnionType(DebugInfoEntry die) {
		String name = DWARF1ImportUtils.extractName(die).orElseGet(() -> "anon_" + die.getRef());
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingDt = dataTypeManager.getDataType(categoryPath, name);
		if (existingDt != null) {
			// already imported
			dwarfTypeManager.registerType(die.getRef(), existingDt);
			return Optional.of(existingDt);
		}
		UnionDataType udt = new UnionDataType(categoryPath, name, dataTypeManager);
		Union newDt = (Union) dataTypeManager.addDataType(udt, DataTypeConflictHandler.DEFAULT_HANDLER);
		dwarfTypeManager.registerType(die.getRef(), newDt);
		//log.appendMsg("Struct " + name);
		for (DebugInfoEntry childDie : die.getChildren()) {
			switch (childDie.getTag()) {
			case MEMBER:
				processUnionTypeMember(newDt, childDie);
				break;
			default:
				log.appendMsg("Unexpected child of union type: " + childDie.getTag());
			}
		}
		return Optional.of(newDt);
	}

	private void processUnionTypeMember(Union union, DebugInfoEntry die) {
		String memberName = DWARF1ImportUtils.extractName(die).orElse(null);
		//log.appendMsg("Member " + childNameOpt);
		DataType memberDt = typeExtractor.extractDataType(die);
		union.add(memberDt, memberName, null);
	}
	
	private Optional<DataType> processEnumType(DebugInfoEntry die) throws IOException {
		Optional<Number> byteSizeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.BYTE_SIZE).map(av -> av.get());
		Optional<byte[]> elementListOpt = die.<BlockAttributeValue>getAttribute(AttributeName.ELEMENT_LIST).map(av -> av.get());
		
		String name = DWARF1ImportUtils.extractName(die).orElseGet(() -> "anon_" + die.getRef());
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingDt = dataTypeManager.getDataType(categoryPath, name);
		if (existingDt != null) {
			// already imported?
			dwarfTypeManager.registerType(die.getRef(), existingDt);
			return Optional.of(existingDt);
		}
		
		int size = byteSizeOpt.orElse(4).intValue();
		var edt = new EnumDataType(categoryPath, name, size);
		if (elementListOpt.isPresent()) {
			processEnumElementList(edt, elementListOpt.get(), size);
		}

		DataType newDt = dataTypeManager.addDataType(edt, DataTypeConflictHandler.DEFAULT_HANDLER);
		dwarfTypeManager.registerType(die.getRef(), newDt);
		return Optional.of(newDt);
	}
	
	private void processEnumElementList(EnumDataType edt, byte[] encodedElementList, int size) throws IOException {
		var bp = new ByteArrayProvider(encodedElementList);
		BinaryReader br = new BinaryReader(bp, program.isLittleEndian());
		while (br.getPointerIndex() < bp.length()) {
			long value = br.readNextInt(); // FIXME: should use machine specific FT_long size
			String name = br.readNextAsciiString();
			edt.add(name, value);
		}
	}
	
	private int extractMemberOffset(DebugInfoEntry die) {
		LocationDescription location = DWARF1ImportUtils.extractLocation(die, program)
				.orElseThrow(() -> new IllegalArgumentException("expected location in " + die));
		var atoms = location.getAtoms();
		if (atoms.size() == 2 && atoms.get(0).getOp() == LocationAtomOp.CONST && atoms.get(1).getOp() == LocationAtomOp.ADD) {
			return atoms.get(0).getArg().intValue();
		}
		throw new IllegalArgumentException("unparsable member location " + atoms);
	}
}
