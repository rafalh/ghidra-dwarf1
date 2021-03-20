package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.Tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.ElfSectionProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DWARF1ProgramAnalyzer {
	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;
	private final DWARF1Program dwarfProgram;
	private final DWARF1TypeManager dwarfTypeManager;
	private final DWARF1TypeExtractor typeExtractor;
	private final DWARF1TypeImporter dwarfTypeImporter;
	private final DWARF1FunctionImporter dwarfFunctionImporter;
	private final DWARF1VariableImporter dwarfVariableImporter;
	
	public DWARF1ProgramAnalyzer(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		dwarfProgram = new DWARF1Program(program, set);
		dwarfTypeManager = new DWARF1TypeManager(dwarfProgram, log);
		typeExtractor = new DWARF1TypeExtractor(dwarfProgram, log, dwarfTypeManager);
		dwarfTypeImporter = new DWARF1TypeImporter(dwarfProgram, log, dwarfTypeManager, typeExtractor);
		dwarfFunctionImporter = new DWARF1FunctionImporter(dwarfProgram, log, dwarfTypeManager, typeExtractor);
		dwarfVariableImporter = new DWARF1VariableImporter(dwarfProgram, log, typeExtractor);
		dwarfTypeManager.setTypeImporter(dwarfTypeImporter);
	}
	
	public boolean process() {
		var sectionProvider = ElfSectionProvider.createSectionProviderFor(program);
		try {
			var debug = sectionProvider.getSectionAsByteProvider(DWARF1SectionNames.DEBUG);
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
				dwarfProgram.addEntry(die);
				dieList.add(die);
			}
			prev = die;
		}
		
		
		for (DebugInfoEntry die : dieList) {
			processDebugInfoEntry(die);
		}
	}
	
	private void processDebugInfoEntry(DebugInfoEntry die) {
		//log.appendMsg(die.toString());
		try {
			switch (die.getTag()) {
			case GLOBAL_VARIABLE:
			case LOCAL_VARIABLE:
				dwarfVariableImporter.processVariable(die);
				break;
			case GLOBAL_SUBROUTINE:
			case SUBROUTINE:
				dwarfFunctionImporter.processSubrountine(die);
				break;
			case CLASS_TYPE:
			case ENUMERATION_TYPE:
				dwarfTypeImporter.processTypeDebugInfoEntry(die);
				break;
			case TYPEDEF:
				// TODO
				break;
			default:
				// skip other tags
			}
		} catch (Exception e) {
			throw new RuntimeException("Failed to process debug info entry " + die, e);
		}
	}
}
