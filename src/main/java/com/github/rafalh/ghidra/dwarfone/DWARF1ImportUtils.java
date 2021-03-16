package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;
import java.util.Optional;

import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.BlockAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.LocationDescription;
import com.github.rafalh.ghidra.dwarfone.model.StringAttributeValue;

import ghidra.app.util.bin.ByteArrayProvider;

public class DWARF1ImportUtils {
	private DWARF1ImportUtils() {
		// empty
	}
	
	static Optional<String> extractName(DebugInfoEntry die) {
		return die.<StringAttributeValue>getAttribute(AttributeName.NAME)
				.map(StringAttributeValue::get);
	}
	
	static Optional<LocationDescription> extractLocation(DebugInfoEntry die, DWARF1Program dwarfProgram) {
		return die.<BlockAttributeValue>getAttribute(AttributeName.LOCATION)
				.map(av -> decodeLocation(av.get(), dwarfProgram.isLittleEndian()));
		
	}
	
	private static LocationDescription decodeLocation(byte[] encodedLocation, boolean isLittleEndian) {
		var bp = new ByteArrayProvider(encodedLocation);
		try {
			return LocationDescription.read(bp, isLittleEndian);
		} catch (IOException e) {
			throw new IllegalArgumentException("Failed to parse location", e);
		}
	}
}
