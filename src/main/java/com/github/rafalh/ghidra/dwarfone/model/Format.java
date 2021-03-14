package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Format {
	FT_C_C(0x0),
	FT_C_X(0x1),
	FT_X_C(0x2),
	FT_X_X(0x3),
	UT_C_C(0x4),
	UT_C_X(0x5),
	UT_X_C(0x6),
	UT_X_X(0x7),
	ET(0x8);
	
	private static final Map<Integer, Format> VALUE_MAP;
	
	private int value;
	
	static {
		VALUE_MAP = Stream.of(Format.values())
				.collect(Collectors.toUnmodifiableMap(fmt -> fmt.value, Function.identity()));
	}
	
	Format(int value) {
		this.value = value;
	}
	
	public static Format decode(int value) {
		return Optional.ofNullable(VALUE_MAP.get(value))
				.orElseThrow(() -> new IllegalArgumentException("invalid format value " + value));
	}
}
