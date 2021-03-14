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
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DWARF1ProgramAnalyzer {
	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;
	
	public DWARF1ProgramAnalyzer(Program program, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
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
		List<DebugInfoEntry> dieList = new ArrayList<>();
		Map<Long, DebugInfoEntry> dieMap = new HashMap<>();
		while (br.getPointerIndex() < bp.length() && !monitor.isCancelled()) {
			long offset = br.getPointerIndex();
			Optional<RefAttributeValue> parentSiblingOpt = Optional.ofNullable(parent)
					.flatMap(die -> die.<RefAttributeValue>getAttribute(AttributeName.SIBLING));
			Optional<RefAttributeValue> prevSiblingOpt = Optional.ofNullable(prev)
					.flatMap(die -> die.<RefAttributeValue>getAttribute(AttributeName.SIBLING));
			if (parentSiblingOpt.isPresent() && parentSiblingOpt.get().get() == offset) {
				parent = parent.getParent();
			} else if (prevSiblingOpt.isPresent() && prevSiblingOpt.get().get() != offset) {
				parent = prev;
			}
			var die = new DebugInfoEntry(br, parent);
			dieList.add(die);
			dieMap.put(offset, die);
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
		default:
			// skip other tags
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
