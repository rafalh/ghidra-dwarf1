package com.github.rafalh.ghidra.dwarfone;

import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.LocationAtomOp;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

public class DWARF1VariableImporter {
	private final DWARF1Program dwarfProgram;
	private final MessageLog log;
	private final DWARF1TypeExtractor typeExtractor;
	
	DWARF1VariableImporter(DWARF1Program dwarfProgram, MessageLog log, DWARF1TypeExtractor typeExtractor) {
		this.dwarfProgram = dwarfProgram;
		this.log = log;
		this.typeExtractor = typeExtractor;
	}
	
	void processGlobalVariable(DebugInfoEntry die) {
		Optional<String> nameOptional = DWARF1ImportUtils.extractName(die);
		Optional<LocationDescription> locationOptional = DWARF1ImportUtils.extractLocation(die, dwarfProgram);
		if (nameOptional.isEmpty() || locationOptional.isEmpty()) {
			return;
		}
		String name = nameOptional.get();
		LocationDescription location = locationOptional.get();
		Long offset = offsetFromLocation(location);
		//log.appendMsg(name + " " + Long.toHexString(offset));
		if (offset == 0) {
			log.appendMsg("Skipping variable with null address: " + name);
			return;
		}
		Address addr = dwarfProgram.toAddr(offset);
		try {
			dwarfProgram.getProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
		
		DataType dt = typeExtractor.extractDataType(die);
		
		if (!dt.isDynamicallySized() && dt.getLength() > 0) {
			try {
				// a bit brutal... there should be an option for clearing
				dwarfProgram.getProgram().getListing().clearCodeUnits(addr, addr.add(dt.getLength()), false);
				dwarfProgram.getProgram().getListing().createData(addr, dt);
			} catch (CodeUnitInsertionException | DataTypeConflictException e) {
				log.appendException(e);
			}
		}
	}

	void processLocalVariable(DebugInfoEntry die) {
		if (die.getParent().getTag() != Tag.COMPILE_UNIT) {
			// ignore parameters and local variables
			// we are only interested in static variables
			return;
		}
		processGlobalVariable(die);
	}
	
	private Long offsetFromLocation(LocationDescription location) {
		var locationAtoms = location.getAtoms();
		if (locationAtoms.size() == 1 && locationAtoms.get(0).getOp() == LocationAtomOp.ADDR) {
			return locationAtoms.get(0).getArg();
		}
		log.appendMsg("Complex location not supported: " + locationAtoms);
		return null;
	}
}
