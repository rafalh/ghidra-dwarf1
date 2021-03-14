package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Objects;

public class StringAttributeValue implements AttributeValue {
	private final String string;
	
	public StringAttributeValue(String string) {
		this.string = string;
	}

	public String get() {
		return string;
	}
	
	@Override
	public String toString() {
		return "\"" + Objects.toString(string) + "\"";
	}
}
