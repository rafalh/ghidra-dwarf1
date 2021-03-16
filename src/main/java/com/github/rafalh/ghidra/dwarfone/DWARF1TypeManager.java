package com.github.rafalh.ghidra.dwarfone;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.FundamentalType;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

public class DWARF1TypeManager {

	private final DWARF1Program program;
	private final MessageLog log;
	private DWARF1TypeImporter dwarfTypeImporter;

	private final Map<Long, DataType> userDataTypeMap = new HashMap<>();
	
	public DWARF1TypeManager(DWARF1Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}
	
	DataType getUserDataType(long ref) {
		var dtOpt = Optional.ofNullable(userDataTypeMap.get(ref));
		if (dtOpt.isEmpty()) {
			// FIXME: dirty fix, may cause infinite recursion...
			Optional.ofNullable(program.getDebugInfoEntry(ref))
					.ifPresent(die -> {
						dwarfTypeImporter.processTypeDebugInfoEntry(die);
					});
			// try again...
			dtOpt = Optional.ofNullable(userDataTypeMap.get(ref));
		}
		if (dtOpt.isEmpty()) {
			log.appendMsg("Cannot find user type " + Long.toHexString(ref));
		}
		return dtOpt.orElse(DataType.DEFAULT);
	}
	
	DataType convertFundamentalTypeToDataType(FundamentalType ft) {
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

	public void registerType(long ref, DataType dt) {
		userDataTypeMap.put(ref, dt);
	}
	
	public void setTypeImporter(DWARF1TypeImporter dwarfTypeImporter) {
		this.dwarfTypeImporter = dwarfTypeImporter;
	}
	
}
