package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum TypeModifier {
	POINTER_TO(0x01),
	REFERENCE_TO(0x02),
	CONST(0x03),
	VOLATILE(0x04),
	USER(null);
	
	private static final int LO_USER = 0x80;
	private static final int HI_USER = 0xFF;
	private static final Map<Integer, TypeModifier> VALUE_MAP;
	
	private Integer value;

	static {
		VALUE_MAP = Stream.of(TypeModifier.values())
				.filter(mod -> mod.value != null)
				.collect(Collectors.toUnmodifiableMap(mod -> mod.value, Function.identity()));
	}
	
	TypeModifier(Integer value) {
		this.value = value;
	}
	
	public static TypeModifier fromValue(int value) {
		if (value >= LO_USER && value <= HI_USER) {
			return USER;
		}
		TypeModifier mod = VALUE_MAP.get(value);
		if (mod == null) {
			throw new IllegalArgumentException("invalid mod value " + value);
		}
		return mod;
	}
}
