package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AddrAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.ConstAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;
import com.github.rafalh.ghidra.dwarfone.model.LocationAtomOp;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.StringAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.ElfSectionProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DWARF1ProgramAnalyzer {
	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;
	private final Map<Long, DataType> userDataTypeMap = new HashMap<>();
	private final CategoryPath categoryPath;
	private final List<DebugInfoEntry> dieList = new ArrayList<>();
	private final Map<Long, DebugInfoEntry> dieMap = new HashMap<>();
	
	public DWARF1ProgramAnalyzer(Program program, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.categoryPath = new CategoryPath("/DWARF");
	}
	
	public boolean process() {
		var sectionProvider = ElfSectionProvider.createSectionProviderFor(program);
		try {
			var debug = sectionProvider.getSectionAsByteProvider(SectionNames.DEBUG);
			processDebugSection(debug);
			//log.appendMsg("Finished parsing DWARF1");
			return true;
		} catch (IOException e) {
			log.appendException(e);
			return false;
		}
	}
	
	private boolean isLittleEndian() {
		return !program.getLanguage().isBigEndian();
	}
	
	private void processDebugSection(ByteProvider bp) throws IOException {
		BinaryReader br = new BinaryReader(bp, isLittleEndian());
		DebugInfoEntry parent = null;
		DebugInfoEntry prev = null;
		
		while (br.getPointerIndex() < bp.length() && !monitor.isCancelled()) {
			long offset = br.getPointerIndex();
			Optional<RefAttributeValue> parentSiblingOpt = Optional.ofNullable(parent)
					.flatMap(die -> die.<RefAttributeValue>getAttribute(AttributeName.SIBLING));
			Optional<RefAttributeValue> prevSiblingOpt = Optional.ofNullable(prev)
					.flatMap(die -> die.<RefAttributeValue>getAttribute(AttributeName.SIBLING));
			//log.appendMsg("prev " + prevSiblingOpt + " parent " + parentSiblingOpt + " off " + offset);
			if (parentSiblingOpt.isPresent() && parentSiblingOpt.get().get() == offset) {
				parent = parent.getParent();
			} else if (prevSiblingOpt.isPresent() && prevSiblingOpt.get().get() != offset) {
				parent = prev;
			}
			var die = new DebugInfoEntry(br, parent);
			if (die.getTag() != Tag.NULL) {
				dieList.add(die);
				dieMap.put(offset, die);
			}
			prev = die;
		}
		for (DebugInfoEntry die : dieList) {
			processDebugInfoEntry(die);
		}
	}
	
	private void processDebugInfoEntry(DebugInfoEntry die) throws IOException {
		//log.appendMsg(die.toString());
		switch (die.getTag()) {
		case GLOBAL_VARIABLE:
			processGlobalVariable(die);
			break;
		case GLOBAL_SUBROUTINE:
			processGlobalSubrountine(die);
			break;
		case CLASS_TYPE:
			processClassType(die);
			break;
		case ENUMERATION_TYPE:
			processEnumType(die);
			break;
		case ARRAY_TYPE:
			// TODO
			break;
		case TYPEDEF:
			// TODO
			break;
		default:
			// skip other tags
		}
	}
	
	private void processClassType(DebugInfoEntry die) throws IOException {
		Optional<String> nameOpt = die.<StringAttributeValue>getAttribute(AttributeName.NAME).map(av -> av.get());
		Optional<Number> byteSizeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.BYTE_SIZE).map(av -> av.get());
		if (byteSizeOpt.isEmpty()) {
			return;
		}
		String name = nameOpt.orElseGet(() -> "anon_" + die.getRef());
		if (name.equals("@class")) {
			// FIXME: anonymous class?
			return;
		}
		int size = byteSizeOpt.get().intValue();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingDt = dataTypeManager.getDataType(categoryPath, name);
		if (existingDt != null) {
			// already imported
			userDataTypeMap.put(die.getRef(), existingDt);
			return;
		}
		StructureDataType sdt = new StructureDataType(categoryPath, name, size, dataTypeManager);
		//log.appendMsg("Struct " + name);
		for (DebugInfoEntry childDie : die.getChildren()) {
			switch (childDie.getTag()) {
			case MEMBER:
				processClassTypeMember(sdt, childDie);
				break;
			case INHERITANCE:
				processClassTypeInheritance(sdt, childDie);
				break;
			default:
				log.appendMsg("Unexpected child of class type: " + childDie.getTag());
			}
		}
		//sdt.realign();
		DataType newDt = dataTypeManager.addDataType(sdt, DataTypeConflictHandler.DEFAULT_HANDLER);
		userDataTypeMap.put(die.getRef(), newDt);
	}
	
	private void processClassTypeInheritance(StructureDataType sdt, DebugInfoEntry die) {
		DataType baseDt = extractDataType(die);
		sdt.replaceAtOffset(0, baseDt, -1, "__base", null);
	}

	private void processClassTypeMember(StructureDataType sdt, DebugInfoEntry die) throws IOException {
		String memberName = die.<StringAttributeValue>getAttribute(AttributeName.NAME)
				.map(StringAttributeValue::get)
				.orElse(null);
		//log.appendMsg("Member " + childNameOpt);
		DataType memberDt = extractDataType(die);
		int memberOffset = extractMemberOffset(die);
		assert memberDt != null;
		if (memberOffset >= sdt.getLength()) {
			// TODO: memberDt.isDynamicallySized()
			return;
		}
		sdt.replaceAtOffset(memberOffset, memberDt, -1, memberName, null);
	}
	
	private void processEnumType(DebugInfoEntry die) throws IOException {
		Optional<String> nameOpt = die.<StringAttributeValue>getAttribute(AttributeName.NAME).map(av -> av.get());
		Optional<Number> byteSizeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.BYTE_SIZE).map(av -> av.get());
		Optional<byte[]> elementListOpt = die.<BlockAttributeValue>getAttribute(AttributeName.ELEMENT_LIST).map(av -> av.get());
		
		String name = nameOpt.orElseGet(() -> "anon_" + die.getRef());
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType existingDt = dataTypeManager.getDataType(categoryPath, name);
		if (existingDt != null) {
			// already imported
			userDataTypeMap.put(die.getRef(), existingDt);
			return;
		}
		
		int size = byteSizeOpt.orElse(4).intValue();
		var edt = new EnumDataType(categoryPath, name, size);
		if (elementListOpt.isPresent()) {
			processEnumElementList(edt, elementListOpt.get(), size);
		}
		
		DataType newDt = dataTypeManager.addDataType(edt, DataTypeConflictHandler.DEFAULT_HANDLER);
		userDataTypeMap.put(die.getRef(), newDt);
	}
	
	private void processEnumElementList(EnumDataType edt, byte[] encodedElementList, int size) throws IOException {
		var bp = new ByteArrayProvider(encodedElementList);
		BinaryReader br = new BinaryReader(bp, isLittleEndian());
		while (br.getPointerIndex() < bp.length()) {
			long value;
			if (size == 1) {
				value = br.readNextByte();
			} else if (size == 2) {
				value = br.readNextShort();
			} else if (size == 4) {
				value = br.readNextInt();
			} else if (size == 8) {
				value = br.readNextLong();
			} else {
				throw new IllegalArgumentException("Unsupported enum size " + size);
			}
			String name = br.readNextAsciiString();
			edt.add(name, value);
		}
	}
	
	private int extractMemberOffset(DebugInfoEntry die) throws IOException {
		Optional<BlockAttributeValue> locationAttributeOptional = die.getAttribute(AttributeName.LOCATION);
		byte[] encodedLocation = locationAttributeOptional
				.orElseThrow(() -> new IllegalArgumentException("expected location in " + die))
				.get();
		LocationDescription location = decodeLocation(encodedLocation);
		var atoms = location.getAtoms();
		if (atoms.size() == 2 && atoms.get(0).getOp() == LocationAtomOp.CONST && atoms.get(1).getOp() == LocationAtomOp.ADD) {
			return atoms.get(0).getArg().intValue();
		}
		throw new IllegalArgumentException("unparsable member location " + atoms);
	}
	
	private DataType extractDataType(DebugInfoEntry die) {
		Optional<FundamentalType> fundTypeOpt = die.<ConstAttributeValue>getAttribute(AttributeName.FUND_TYPE)
				.map(ConstAttributeValue::get)
				.map(Number::intValue)
				.map(FundamentalType::fromValue);
		Optional<RefAttributeValue> userDefTypeOpt = die.<RefAttributeValue>getAttribute(AttributeName.USER_DEF_TYPE);
		if (fundTypeOpt.isPresent()) {
			var ftDt = dataTypeFromFundamentalType(fundTypeOpt.get());
			if (ftDt == null) {
				log.appendMsg("failed to map ft to dt: " + fundTypeOpt.get());
			}
			return Optional.ofNullable(ftDt).orElse(DataType.DEFAULT);
		}
		if (userDefTypeOpt.isPresent()) {
			return getUserDataType(userDefTypeOpt.get());
		}
		log.appendMsg("Unknown type " + die);
		return DataType.DEFAULT;
	}
	
	private DataType getUserDataType(RefAttributeValue ref) {
		var dtOpt = Optional.ofNullable(userDataTypeMap.get(ref.get()));
		if (dtOpt.isEmpty()) {
			// FIXME: dirty fix, may cause infinite recursion...
			Optional.ofNullable(dieMap.get(ref.get()))
					.ifPresent(die -> {
						try {
							processDebugInfoEntry(die);
						} catch (IOException e) {
							log.appendException(e);
						}
					});
			// try again...
			dtOpt = Optional.ofNullable(userDataTypeMap.get(ref.get()));
		}
		if (dtOpt.isEmpty()) {
			log.appendMsg("Cannot find user type " + ref);
		}
		return dtOpt.orElse(DataType.DEFAULT);
	}
	
	private DataType dataTypeFromFundamentalType(FundamentalType ft) {
		DataTypeManager dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
		switch (ft) {
		case CHAR:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "char");
		case SIGNED_CHAR:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "schar");
		case UNSIGNED_CHAR:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "uchar");
		case SHORT:
		case SIGNED_SHORT:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "short");
		case UNSIGNED_SHORT:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "ushort");
		case INTEGER:
		case SIGNED_INTEGER:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "int");
		case UNSIGNED_INTEGER:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "uint");
		case LONG:
		case SIGNED_LONG:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "long");
		case UNSIGNED_LONG:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "ulong");
		case POINTER:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "pointer");
		case FLOAT:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "float");
		case DBL_PREC_FLOAT:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "double");
		case EXT_PREC_FLOAT:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "longdouble");
		case VOID:
			return DataType.VOID;
		case BOOLEAN:
			return dataTypeManager.getDataType(CategoryPath.ROOT, "bool");
		default:
			return DataType.DEFAULT;
		}
	}

	private LocationDescription decodeLocation(byte[] encodedLocation) throws IOException {
		var bp = new ByteArrayProvider(encodedLocation);
		return LocationDescription.read(bp, isLittleEndian());
	}
	
	private Long offsetFromLocation(LocationDescription location) {
		var locationAtoms = location.getAtoms();
		if (locationAtoms.size() == 1 && locationAtoms.get(0).getOp() == LocationAtomOp.ADDR) {
			return locationAtoms.get(0).getArg();
		}
		log.appendMsg("Complex location not supported: " + locationAtoms);
		return null;
	}
	
	private void processGlobalVariable(DebugInfoEntry die) throws IOException {
		Optional<StringAttributeValue> nameAttributeOptional = die.getAttribute(AttributeName.NAME);
		Optional<BlockAttributeValue> locationAttributeOptional = die.getAttribute(AttributeName.LOCATION);
		if (nameAttributeOptional.isEmpty() || locationAttributeOptional.isEmpty()) {
			return;
		}
		String name = nameAttributeOptional.get().get();
		byte[] encodedLocation = locationAttributeOptional.get().get();
		LocationDescription location = decodeLocation(encodedLocation);
		Long offset = offsetFromLocation(location);
		//log.appendMsg(name + " " + Long.toHexString(offset));
		Address addr = toAddr(offset);
		try {
			program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
		
		DataType dt = extractDataType(die);
//		try {
//			DataUtilities.createData(program, addr, dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
//		} catch (CodeUnitInsertionException e) {
//			log.appendException(e);
//		}
		
		try {
			// a bit brutal... there should be an option for clearing
			program.getListing().clearCodeUnits(addr, addr.add(dt.getLength()), false);
			program.getListing().createData(addr, dt);
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			log.appendException(e);
		}
	}

	private void processGlobalSubrountine(DebugInfoEntry die) {
		Optional<StringAttributeValue> nameAttributeOptional = die.getAttribute(AttributeName.NAME);
		Optional<AddrAttributeValue> lowPcAttributeOptional = die.getAttribute(AttributeName.LOW_PC);
		Optional<AddrAttributeValue> highPcAttributeOptional = die.getAttribute(AttributeName.HIGH_PC);
		if (nameAttributeOptional.isEmpty() || lowPcAttributeOptional.isEmpty() || highPcAttributeOptional.isEmpty()) {
			return;
		}
		String name = nameAttributeOptional.get().get();
		long lowPc = lowPcAttributeOptional.get().get();
		//long highPc = highPcAttributeOptional.get().get();
		//log.appendMsg(name + " " + Long.toHexString(lowPc.longValue()));
		
		//program.getFunctionManager().createFunction(name, addr, null, null)
		
		Address addr = toAddr(lowPc);
		try {
			program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	private final Address toAddr(Number offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(
			offset.longValue(), true);
	}
}
