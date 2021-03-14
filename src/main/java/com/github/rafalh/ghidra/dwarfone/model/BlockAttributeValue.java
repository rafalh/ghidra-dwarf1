package com.github.rafalh.ghidra.dwarfone.model;

public class BlockAttributeValue implements AttributeValue {
	private final byte[] block;
	
	public BlockAttributeValue(byte[] block) {
		this.block = block;
	}

	public byte[] get() {
		return block;
	}
}
