package com.github.rafalh.ghidra.dwarfone.model;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum FundamentalType {
	CHAR(0x0001),
	SIGNED_CHAR(0x0002),
	UNSIGNED_CHAR(0x0003),
	SHORT(0x0004),
	SIGNED_SHORT(0x0005),
	UNSIGNED_SHORT(0x0006),
	INTEGER(0x0007),
	SIGNED_INTEGER(0x0008),
	UNSIGNED_INTEGER(0x0009),
	LONG(0x000A),
	SIGNED_LONG(0x000B),
	UNSIGNED_LONG(0x000C),
	POINTER(0x000D),
	FLOAT(0x000E),
	DBL_PREC_FLOAT(0x000F),
	EXT_PREC_FLOAT(0x0010),
	COMPLEX(0x0011),
	DBL_PREC_COMPLEX(0x0012),
	VOID(0x0014),
	BOOLEAN(0x0015),
	EXT_PREC_COMPLEX(0x0016),
	LABEL(0x0017),
	USER(null);

	private static final int LO_USER = 0x8000;
	private static final int HI_USER = 0xFFFF;
	private static final Map<Integer, FundamentalType> VALUE_MAP;
	
	private Integer value;
	
	static {
		VALUE_MAP = Stream.of(FundamentalType.values())
				.filter(at -> at.value != null)
				.collect(Collectors.toUnmodifiableMap(ft -> ft.value, Function.identity()));
	}
	
	FundamentalType(Integer value) {
		this.value = value;
	}
	
	public static FundamentalType fromValue(int value) {
		if (value >= LO_USER && value <= HI_USER) {
			return USER;
		}
		FundamentalType ft = VALUE_MAP.get(value);
		if (ft == null) {
			throw new IllegalArgumentException("invalid fundamental type " + value);
		}
		return ft;
	}
}
