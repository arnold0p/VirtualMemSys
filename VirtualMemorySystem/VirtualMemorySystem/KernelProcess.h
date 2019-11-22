#pragma once
#include "Process.h"
#include "KernelSystem.h"

struct Descriptor {
	unsigned int v : 1;
	unsigned int d : 1;
	unsigned int r : 1;
	unsigned int w : 1;
	unsigned int x : 1;
	unsigned int s : 1;
	unsigned int ss : 1;
	unsigned int ref : 1;
	unsigned int shared : 1;
	unsigned int trueshared : 1;
	unsigned int clone : 1;
	unsigned int trueclone : 1;
	PhysicalAddress block;
	ClusterNo disk;
	Descriptor *next;
};

struct SegList {
	SSList *seg;
	const char *name;
	VirtualAddress start;
	PageNum size;
	SegList *next;
	SegList(SSList *ss,const char *nam, VirtualAddress s,PageNum siz, SegList *n = nullptr) {
		seg = ss;
		name = nam;
		start = s;
		size = siz;
		next = n;

	}

};

class KernelProcess {
public:

	KernelProcess(ProcessId pid,Process *p);

	~KernelProcess();

	ProcessId getProcessId() const;

	Status createSegment(VirtualAddress startAddress, PageNum segmentSize,
		AccessType flags);

	Status loadSegment(VirtualAddress startAddress, PageNum segmentSize,
		AccessType flags, void* content);

	Status deleteSegment(VirtualAddress startAddress);
	Status pageFault(VirtualAddress address);
	PhysicalAddress getPhysicalAddress(VirtualAddress address);

	void setPMT1(int *pmt);

	void setSystem(KernelSystem *sys);

	Status access(VirtualAddress address, AccessType type);

	KernelProcess* clone(KernelProcess *father);

	Status createSharedSegment(VirtualAddress startAddress,
		PageNum segmentSize, const char* name, AccessType flags);
	Status disconnectSharedSegment(const char* name);
	Status deleteSharedSegment(const char* name);

	void deleteseg(const char *name);


	void countchildren(KernelProcess *p, PageNum *cnt, VirtualAddress address);

	void unclonechildren(KernelProcess *p, VirtualAddress address);


	Status copyonwrite(VirtualAddress addr);
	

	void blockIfThrashing();

private:

	friend class KernelSystem;
	friend class Process;
	Process *myproc;
	ProcessId id;
	Descriptor **pmt;
	KernelSystem *mySystem;

	SegList *headS, *tailS;

	KernelProcess *father;
	ProcList *headchildren, *tailchildren;

	std::mutex thrashmutex;

	bool blocked;

	PageNum pfcnt, acscnt;
};