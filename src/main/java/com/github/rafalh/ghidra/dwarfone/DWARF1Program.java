package com.github.rafalh.ghidra.dwarfone;

import java.util.HashMap;
import java.util.Map;

import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

public class DWARF1Program {

	private final Program program;
	private final AddressSetView set;
	private final Map<Long, DebugInfoEntry> dieMap = new HashMap<>();
	
	DWARF1Program(Program program, AddressSetView set) {
		this.program = program;
		this.set = set;
	}
	
	public Program getProgram() {
		return program;
	}
	
	public boolean isLittleEndian() {
		return !program.getLanguage().isBigEndian();
	}

	public DataTypeManager getDataTypeManager() {
		return program.getDataTypeManager();
	}
	
	public DebugInfoEntry getDebugInfoEntry(long ref) {
		return dieMap.get(ref);
	}

	public void addEntry(DebugInfoEntry die) {
		dieMap.put(die.getRef(), die);
	}
	
	public AddressSetView getSet() {
		return set;
	}
	
	public final Address toAddr(Number offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(
			offset.longValue(), true);
	}
}
