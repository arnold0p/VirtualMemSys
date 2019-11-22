#pragma once

#include "System.h"
#include "Process.h"
#include "part.h"
#include <mutex>


struct Descriptor;

struct Allocator {
	Allocator *next;
};

struct ProcList {
	KernelProcess *proc;
	ProcList *next;
	ProcList(KernelProcess *p, ProcList *n = nullptr) {
		proc = p;
		next = n;
	}
};

struct Fat {
	PageNum page;
	Fat* next;
	Fat(PageNum p, Fat *n = nullptr) {
		page = p;
		next = n;
	}
};

struct DescList {
	Descriptor *desc;
	KernelProcess *proc;
	VirtualAddress address;
	DescList *next;
	DescList(Descriptor* d, KernelProcess *p, VirtualAddress a, DescList *n = nullptr) {
		desc = d;
		proc = p;
		address = a;
		next = n;
	}
};

struct SProcList {
	KernelProcess *proc;
	VirtualAddress start;
	SProcList *next;
	SProcList(KernelProcess *p, VirtualAddress s, SProcList *n = nullptr) {
		proc = p;
		start = s;
		next = n;
	}
};
struct SSList {
	const char *name;
	bool first;
	PageNum pages;
	Descriptor **pmt;
	AccessType flags;
	ClusterNo *disks;
	SProcList *head, *tail;
	SSList *next;
	SSList (const char *nam, PageNum p, AccessType f, SSList *n=nullptr) {
		name = nam;
		disks = 0;
		pages = p;
		flags = f;
		next = n;
		head = tail = nullptr;
		first = true;
	}

};

class KernelSystem {
public:
	KernelSystem(PhysicalAddress processVMSpace, PageNum processVMSpaceSize,
		PhysicalAddress pmtSpace, PageNum pmtSpaceSize,
		Partition* partition);
	~KernelSystem();

	Process* createProcess();

	Time periodicJob();

	// Hardware job
	Status access(ProcessId pid, VirtualAddress address, AccessType type);


	Process* cloneProcess(ProcessId pid);


	Descriptor* getVictim();

	PhysicalAddress searchforVM();
	PhysicalAddress searchforPMT();
	PageNum searchForCluster();

	void releaseVM(PhysicalAddress free);
	void releasePMT(PhysicalAddress free);
	void releaseCluster(PageNum i);


	void putProc(KernelProcess *p);
	KernelProcess* getProc(ProcessId id);
	void deleteProc(ProcessId id);

	void putDesc(Descriptor *d, KernelProcess *p, VirtualAddress a);
	void deleteDesc(Descriptor *d);

	SSList* putSS(KernelProcess *p, const char* name, PageNum size, AccessType flags);
	void deleteSS(const char* name);
	SSList* findSeg(const char *name);

private:
	friend class KernelProcess;
	friend class Process;
	ProcessId ID;
	PhysicalAddress vmSpace;
	PageNum vmSize;
	PhysicalAddress pmtSpace;
	PageNum pmtSize;
	Allocator *headVM,*headPMT,*tailVM,*tailPMT;

	Fat *headFat, *tailFat;

	PageNum vmpagecounter,pmtpagecounter,fatpagecounter;

	ProcList *headProc, *tailProc;

	DescList *headDesc, *tailDesc;

	SSList *headSS, *tailSS;

	Partition *part;

	Descriptor* headclock, *tailclock;

	unsigned long long descnum=0;

	std::mutex mymutex,lmut;

	PageNum syspfcnt, sysacscnt;
};