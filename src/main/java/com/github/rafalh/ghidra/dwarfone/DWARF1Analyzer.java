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
package com.github.rafalh.ghidra.dwarfone;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.ElfSectionProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer of DWARF1 debug information.
 */
public class DWARF1Analyzer extends AbstractAnalyzer {

	public DWARF1Analyzer() {
		super("DWARF1", "Analyzer of DWARF debug data in version 1", AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		var sectionProvider = ElfSectionProvider.createSectionProviderFor(program);
		return sectionProvider.hasSection(SectionNames.DEBUG);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		var programAnalyzer = new DWARF1ProgramAnalyzer(program, monitor, log);
		programAnalyzer.process();
		return true;
	}
}
