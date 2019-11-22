#pragma once
// File: vm_declarations.h

typedef unsigned long PageNum;
typedef unsigned long VirtualAddress;
typedef void* PhysicalAddress;
typedef unsigned long Time;

enum Status { OK, PAGE_FAULT, TRAP };

enum AccessType { READ, WRITE, READ_WRITE, EXECUTE };

typedef unsigned ProcessId;

#define PAGE_SIZE 1024 



#define offw 10
#define offpg1 8
#define offpg2 6

const VirtualAddress maskpg2 = ~(~(PageNum)0 << offpg2);
const VirtualAddress outmask = 0xFF000000;
const VirtualAddress wordmask = 0x3FF;
const PageNum sizeofpmt2 = 64;
const PageNum sizeofpmt1 = 256;

