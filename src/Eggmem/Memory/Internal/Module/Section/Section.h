#pragma once
#include "../../../../Util/winapi.h"
#include "../../../../Util/Util.h"
#include "../../PE/PE.h"
//class Section
//{
//public:
//	Section(std::string name, uintptr_t baseAddress, size_t sectionSize, ULONG sectionFlags)
//		: sectionName(name), baseAddress(baseAddress), sectionSize(sectionSize), sectionFlags(sectionFlags) {};
//
//	std::string name() { return sectionName;}
//	uintptr_t base() { return baseAddress; }
//	size_t size() { return sectionSize; }
//	ULONG flags() { return sectionFlags; }
//
//private:
//	std::string sectionName;
//	uintptr_t baseAddress;
//	size_t sectionSize;
//	ULONG sectionFlags;
//	PE& pe = PE::get();
//};

class Section
{
public:
    Section(const IMAGE_SECTION_HEADER& header)
        : _name(header.Name, header.Name + IMAGE_SIZEOF_SHORT_NAME),
        _base(header.VirtualAddress),
        _size(header.Misc.VirtualSize),
        _flags(header.Characteristics),
        _virtualAddress(header.VirtualAddress),
        _virtualSize(header.Misc.VirtualSize),
        _pointerToRawData(header.PointerToRawData),
        _sizeOfRawData(header.SizeOfRawData),
        _characteristics(header.Characteristics),
        _physicalAddress(header.Misc.PhysicalAddress) {};

    std::string name() const { return _name; }
    uintptr_t base() const { return _base; }
    size_t size() const { return _size; }
    ULONG flags() const { return _flags; }
    uintptr_t virtualAddress() const { return _virtualAddress; }
    size_t virtualSize() const { return _virtualSize; }
    ULONG pointerToRawData() const { return _pointerToRawData; }
    size_t sizeOfRawData() const { return _sizeOfRawData; }
    ULONG characteristics() const { return _characteristics; }
    uintptr_t physicalAddress() const { return _physicalAddress; }

private:
    std::string _name;
    uintptr_t _base;
    size_t _size;
    ULONG _flags;
    uintptr_t _virtualAddress;
    size_t _virtualSize;
    ULONG _pointerToRawData;
    size_t _sizeOfRawData;
    ULONG _characteristics;
    uintptr_t _physicalAddress;
};

