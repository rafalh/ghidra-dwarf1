package com.github.rafalh.ghidra.dwarfone.model;

public class AddrAttributeValue implements AttributeValue {
	private final long addr;
	
	public AddrAttributeValue(long addr) {
		this.addr = addr;
	}

	public long get() {
		return addr;
	}
	
	@Override
	public String toString() {
		return "addr(" + Long.toHexString(addr) + ")";
	}
}
