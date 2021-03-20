package com.github.rafalh.ghidra.dwarfone.model;

public class RefAttributeValue implements AttributeValue {
	private final long offset;
	
	public RefAttributeValue(long offset) {
		this.offset = offset;
	}

	public long get() {
		return offset;
	}
	
	@Override
	public String toString() {
		return "ref(" + Long.toHexString(offset) + ")";
	}
}
