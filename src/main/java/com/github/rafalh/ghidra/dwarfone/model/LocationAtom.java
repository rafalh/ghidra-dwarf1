package com.github.rafalh.ghidra.dwarfone.model;

public class LocationAtom {
	private final LocationAtomOp op;
	private final Long arg;
	
	public LocationAtom(LocationAtomOp op, Long arg) {
		this.op = op;
		this.arg = arg;
	}

	public LocationAtomOp getOp() {
		return op;
	}

	public Long getArg() {
		return arg;
	}
	
	@Override
	public String toString() {
		return op.toString() + (arg != null ? "(" + arg.toString() + ")" : "");
	}
}
