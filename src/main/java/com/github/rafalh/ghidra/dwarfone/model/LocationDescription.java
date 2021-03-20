package com.github.rafalh.ghidra.dwarfone.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class LocationDescription {
	private final List<LocationAtom> atoms;
	
	public LocationDescription(List<LocationAtom> atoms) {
		this.atoms = List.copyOf(atoms);
	}
	
	public List<LocationAtom> getAtoms() {
		return atoms;
	}
	
	public static LocationDescription read(ByteProvider bp, boolean isLittleEndian) throws IOException {
		BinaryReader br = new BinaryReader(bp, isLittleEndian);
		List<LocationAtom> atoms = new ArrayList<>();
		while (br.getPointerIndex() < bp.length()) {
			int id = br.readNextUnsignedByte();
			var op = LocationAtomOp.decode(id);
			Long arg;
			switch (op) {
			case REG:
			case BASEREG:
			case ADDR: 
			case CONST: 
				arg = (long) br.readNextInt();
				break;
			default:
				arg = null;
				break;
			}
			atoms.add(new LocationAtom(op, arg));
			if (op == LocationAtomOp.USER) {
				break;
			}
		}
		return new LocationDescription(atoms);
	}
	
	
}
