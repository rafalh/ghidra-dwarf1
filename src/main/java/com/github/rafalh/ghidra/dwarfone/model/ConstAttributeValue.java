package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Objects;

public class ConstAttributeValue implements AttributeValue {
	private final Number value;
	
	public ConstAttributeValue(Number value) {
		this.value = value;
	}

	public Number get() {
		return value;
	}
	
	@Override
	public String toString() {
		return Objects.toString(value);
	}
}
