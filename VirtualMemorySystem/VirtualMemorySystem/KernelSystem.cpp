#include "KernelSystem.h"
#include "KernelProcess.h"
#include<iostream>


unsigned long long pf;

unsigned long long acs;

KernelSystem::KernelSystem(PhysicalAddress processVMSpace, PageNum processVMSpaceSize,
	PhysicalAddress pmtSpace, PageNum pmtSpaceSize,
	Partition* partition) : mymutex(), lmut() {

	headclock = tailclock = nullptr;

	ID = 0;
	vmSpace = processVMSpace;
	vmSize = processVMSpaceSize;
	this->pmtSpace = pmtSpace; 
	pmtSize = pmtSpaceSize;
	part = partition;

	headVM = tailVM = nullptr;
	PageNum i, j = 0;
	Allocator *pom;

	headSS = tailSS = nullptr;

	headProc = tailProc = nullptr;

	headFat = tailFat = nullptr;

	for (i = 0; i < part->getNumOfClusters(); i++)
		tailFat = (!headFat ? headFat : tailFat->next) = new Fat(i);



	for (i = 0; i < processVMSpaceSize; i++) {
		
		pom = (Allocator*)((char*)processVMSpace + i*PAGE_SIZE/sizeof(char));

		pom->next = nullptr;

		tailVM = (!headVM?headVM:tailVM->next) = pom;
	}


	headPMT = tailPMT = nullptr;

	
	
	for (i = 0; i < pmtSpaceSize ; i++) {
		pom = (Allocator*)((char*)pmtSpace + i*PAGE_SIZE/sizeof(char));

		pom->next = nullptr;

		tailPMT = (!headPMT ? headPMT : tailPMT->next) = pom;
	}

	vmpagecounter = processVMSpaceSize;
	pmtpagecounter = pmtSpaceSize;
	fatpagecounter = part->getNumOfClusters();


	syspfcnt = sysacscnt = 0;
}

KernelSystem::~KernelSystem() {
	
	ProcList *tek=headProc, *stari = nullptr;

	while (tek) {
		stari = tek;
		tek = tek->next;
		delete stari;
	}

	SSList *tek1 = headSS, *stari1 = nullptr;

	while (tek1) {
		stari1 = tek1;
		tek1 = tek1->next;
		delete stari1;
		if (!tek1)
			continue;
		SProcList *tek11 = tek1->head,*stari11= nullptr;
		while (tek11) {
			stari11 = tek11;
			tek11 = tek11->next;
			delete stari11;

		}
	}

	DescList *tek2 = headDesc, *stari2 = nullptr;

	while (tek2) {
		stari2 = tek2;
		tek2 = tek2->next;
		delete stari2;
	}

	Fat *tek3 = headFat, *stari3 = nullptr;

	while (tek3) {
		stari3 = tek3;
		tek3 = tek3->next;
		delete stari3;
	}

}

Process* KernelSystem::createProcess() {
	std::lock_guard<std::mutex> lock(mymutex);

	Process *proc = new Process(ID++);
		
	proc->pProcess->setSystem(this);

	putProc(proc->pProcess);
	
	return proc;
}

Time KernelSystem::periodicJob() {

	std::lock_guard<std::mutex> lock(mymutex);

	std::lock_guard<std::mutex> lock1(lmut);

	Descriptor *tek = headclock, *pret = nullptr;
	Descriptor *refered = nullptr, *pomtail=tailclock,*pom,*pomhead;

	/*
	
	while (tek){
		tek->desc->refcounter >>= 1;
		tek->desc->refcounter |= tek->desc->ref << 31;
		tek->desc->ref = 0;												//klasican refcounter


		tek = tek->next;
	}
	*/

	pomtail = pomhead = nullptr;

	if (tek) {
		while (tek) {
			if (tek->ref) {
				tek->ref = 0;

				if (!pret)
					headclock = headclock->next;
				else
					pret->next = tek->next;


				if (!headclock)
					tailclock = nullptr;

				if (tek == tailclock)
					tailclock = pret;

				pomtail = (!pomhead ? pomhead : pomtail->next) = tek;

				tek = tek->next;
			}
			else {
				pret = tek;
				tek = tek->next;
			}

			
		}

		if (pomtail) {
			pomtail->next = nullptr;

			tailclock = (!headclock ? headclock : tailclock->next) = pomhead;

			tailclock = pomtail;
		}
	}



	/*
	if (tek) {
		while (tek != tailclock) {

			if (tek->ref) {
				tek->ref = 0;
				if (!pret)
					headclock = headclock->next;
				else
					pret->next = tek->next;


				pomtail = pomtail->next = tek;

				pom = tek->next;
				tek->next = nullptr;
				tek = pom;

			}
			else {
				pret = tek;
				tek = tek->next;
			}
		}
		//optimizovano
		if (tailclock->ref) {

			tailclock->ref = 0;

			if (!pret)
				headclock = headclock->next;
			else
				pret->next = tek->next;

			if (!headclock)
				headclock = tailclock;
			else {
				pomtail = pomtail->next = tailclock;
				tailclock = pomtail;
				tailclock->next = nullptr;
			}

		}
		else
			tailclock = pomtail;
	}
	*/





	ProcList *ptek = headProc;
	
	while (ptek) {
		if (ptek->proc->acscnt) {
			double thrper = (ptek->proc->pfcnt / (double)ptek->proc->acscnt) * 100.0;
			
			if (thrper > 80.0 && !ptek->proc->blocked) {
				ptek->proc->thrashmutex.lock();
				ptek->proc->blocked = true;
			}
		}

		ptek->proc->acscnt = ptek->proc->pfcnt = 0;

		ptek = ptek->next;
	}

	ptek = headProc;

	double systhrper = 0;

	if (sysacscnt)
		systhrper = (syspfcnt / (double)sysacscnt) * 100.0;


	while (ptek) {
				
		if (systhrper < 40.0) {
			if (ptek->proc->blocked) {
				ptek->proc->blocked = false;
				ptek->proc->thrashmutex.unlock();
				break;
			}
			
		}

		ptek = ptek->next;

	}

	syspfcnt = sysacscnt = 0;

	
	
	return 2000;
}

Status KernelSystem::access(ProcessId pid, VirtualAddress address, AccessType type) {
	std::lock_guard<std::mutex> lock(mymutex);
	KernelProcess *p;
	p = getProc(pid);
	if (!p)
		return TRAP;

	acs++;
	return p->access(address, type);
}

Process* KernelSystem::cloneProcess(ProcessId pid){
	std::lock_guard<std::mutex> lock(mymutex);

	KernelProcess *father = getProc(pid);
	if (!father)
		return nullptr;


	Process *clone = father->myproc->clone(ID++);

	if (!clone)
		ID--;
	else
		putProc(clone->pProcess);


	/*

	PageNum i;
	PageNum numofpmt = 1;

	for (i = 0; i < sizeofpmt1; i++) {
		if (father->pmt[i])
			numofpmt++;
	}

	if (numofpmt > pmtpagecounter)
		return nullptr;


	
	Process *clone = new Process(ID++);

	int *procpmt = (int*)headPMT;
	headPMT = headPMT->next;;
	if (!headPMT)
		tailPMT = nullptr;

	pmtpagecounter--;

	clone->pProcess->setSystem(this);
	clone->pProcess->setPMT1(procpmt);

	putProc(clone->pProcess);

	PageNum j;

	Descriptor *cpmt2,*fpmt2;

	for (i = 0; i < sizeofpmt1; i++) {
		if (father->pmt[i]) {

			fpmt2 = father->pmt[i];
			clone->pProcess->pmt[i] = (Descriptor*)searchforPMT();
			cpmt2 = clone->pProcess->pmt[i];
			for (j = 0; j < sizeofpmt2; j++) {
				cpmt2[j].s = fpmt2[j].s;
				cpmt2[j].ss = fpmt2[j].ss;

				cpmt2[j].clone = fpmt2[j].clone = 1;
				cpmt2[j].shared = fpmt2[j].shared;
				cpmt2[j].trueshared = fpmt2[j].trueshared;
				cpmt2[j].r = fpmt2[j].r;
				cpmt2[j].w = fpmt2[j].w;
				cpmt2[j].x = fpmt2[j].x;		

				cpmt2[j].v = cpmt2[j].d = cpmt2[j].ref = 0;

				cpmt2[j].block = (PhysicalAddress)&fpmt2[j];
	
			}
		}
			
	}

	clone->pProcess->father = father;

	father->tailchildren = (!father->headchildren ? father->headchildren : father->tailchildren->next) = new ProcList(clone->pProcess);


	SegList *tek = father->headS;

	while (tek) {
		clone->pProcess->tailS = (!clone->pProcess->headS ? clone->pProcess->headS : clone->pProcess->tailS->next) = new SegList(tek->seg, tek->name, tek->start, tek->size);
		tek = tek->next;
	}

	*/

	return clone;

}



Descriptor* KernelSystem::getVictim() {
//	std::lock_guard<std::mutex> lock(mymutex);

	std::lock_guard<std::mutex> lock(lmut);

	descnum--;

	Descriptor* ret;

	ret = headclock;
	headclock = headclock->next;

	if (!headclock)
		tailclock = nullptr;

	ret->next = nullptr;
	

	return ret;
	/*
	DescList *tek = headDesc, *pret = nullptr, *pompret = nullptr;
	DescList *pomtek = headDesc;

	PageNum min;
	Descriptor *ret = nullptr;

	if (!tek)
		return nullptr;
	
	headDesc = headDesc->next;

	if (!headDesc)													//optimizovano
		tailDesc = nullptr;

	return tek;
	
	/*
	min = tek->desc->refcounter;
	ret = tek->desc;

	while (pomtek) {
		if (tek->desc->refcounter < min) {
			ret = tek->desc;
			min = tek->desc->refcounter;
			pret = pompret;
			tek = pomtek;
		}
		
		pompret = pomtek;
		pomtek = pomtek->next;
	}
																// klasican brojac refcounter
	if (!tek)
		return nullptr;

	if (!pret)
		headDesc = headDesc->next;
	else
		pret->next = tek->next;

	if (!headDesc)
		tailDesc = nullptr;

	if (tek == tailDesc)
		tailDesc = pret;	
	
	return tek;
	*/

}

PhysicalAddress KernelSystem::searchforVM() {
//	std::lock_guard<std::mutex> lock(mymutex);
	PhysicalAddress ret = nullptr;
	if (!headVM)
		return nullptr;

	vmpagecounter--;
	ret = (PhysicalAddress)headVM;
	headVM = headVM->next;
	if (!headVM)
		tailVM = nullptr;

	return ret;
}


PhysicalAddress KernelSystem::searchforPMT() {
	PhysicalAddress ret=nullptr;
	if (!headPMT)
		return ret;

	pmtpagecounter--;
	ret = (PhysicalAddress)headPMT;
	headPMT = headPMT->next;
	if (!headPMT)
		tailPMT = nullptr;

	return ret;

}

void KernelSystem::releaseVM(PhysicalAddress free) {
//	std::lock_guard<std::mutex> lock(mymutex);
	Allocator *pom;
	pom = (Allocator*)(free);

	pom->next = nullptr;

	tailVM = (!headVM ? headVM : tailVM->next) = pom;

	vmpagecounter++;

}
void KernelSystem::releasePMT(PhysicalAddress free) {
//	std::lock_guard<std::mutex> lock(mymutex);
	Allocator *pom;
	pom = (Allocator*)(free);

	pom->next = nullptr;

	tailPMT = (!headPMT ? headPMT : tailPMT->next) = pom;

	pmtpagecounter++;
}


void KernelSystem::putProc(KernelProcess *p) {
//	std::lock_guard<std::mutex> lock(mymutex);
	tailProc = (!headProc ? headProc : tailProc->next) = new ProcList(p);

}
KernelProcess* KernelSystem::getProc(ProcessId id) {
//	std::lock_guard<std::mutex> lock(mymutex);
	ProcList *tek = headProc;

	while (tek) {
		if (tek->proc->getProcessId() == id)
			return tek->proc;
		tek = tek->next;
	}

	return nullptr;
}
void KernelSystem::deleteProc(ProcessId id) {
//	std::lock_guard<std::mutex> lock(mymutex);

	ProcList *tek = headProc,*pret=nullptr;

	while (tek) {
		if (tek->proc->getProcessId() == id)
			break;
		pret = tek;
		tek = tek->next;
	}

	if (!tek)
		return;

	if (!pret)
		headProc = headProc->next;
	else
		pret->next = tek->next;

	if (!headProc)
		tailProc = nullptr;

	if (tek == tailProc)
		tailProc = pret;
	
	delete tek;
}


PageNum KernelSystem::searchForCluster() {
//	std::lock_guard<std::mutex> lock(mymutex);


	Fat *stari;
	PageNum i;
	stari = headFat;
	
	headFat = headFat->next;
	if (!headFat)
		tailFat = nullptr;

	i = stari->page;

	delete stari;


	fatpagecounter--;

	return i;
}

void KernelSystem::releaseCluster(PageNum i) {
//	std::lock_guard<std::mutex> lock(mymutex);
	tailFat = (!headFat ? headFat : tailFat->next) = new Fat(i);
	fatpagecounter++;
}

void KernelSystem::putDesc(Descriptor *d, KernelProcess *p, VirtualAddress a) {
//	std::lock_guard<std::mutex> lock(mymutex);
	//tailDesc = (!headDesc ? headDesc: tailDesc->next) = new DescList(d,p,a);

	std::lock_guard<std::mutex> lock(lmut);

	tailclock = (!headclock ? headclock : tailclock->next) = d;
	d->next = nullptr;
	descnum++;
}

void KernelSystem::deleteDesc(Descriptor *d) {
//	std::lock_guard<std::mutex> lock(mymutex);

	std::lock_guard<std::mutex> lock(lmut);

	descnum--;
	Descriptor *tek = headclock, *pret = nullptr;

	while (tek) {
		if (tek == d)
			break;
		pret = tek;
		tek = tek->next;
	}

	if (!tek)
		return;

	if (!pret)
		headclock = headclock->next;
	else
		pret->next = tek->next;

	if (!headclock)
		tailclock = nullptr;

	if (tek == tailclock)
		tailclock = pret;

	tek->next = nullptr;
	
	/*
	DescList *tek = headDesc, *pret = nullptr;

	while (tek) {
		if (tek->desc==d)
			break;
		pret = tek;
		tek = tek->next;
	}

	if (!tek)
		return;

	if (!pret)
		headDesc = headDesc->next;
	else
		pret->next = tek->next;

	if (!headDesc)
		tailDesc = nullptr;

	if (tek == tailDesc)
		tailDesc = pret;

	delete tek;
	*/
}


SSList* KernelSystem::putSS(KernelProcess *p, const char* name,PageNum size, AccessType flags) {
//	std::lock_guard<std::mutex> lock(mymutex);
	SSList *tek = headSS, *pret = nullptr;
	
	while (tek) {
		if (!strcmp(name, tek->name)) {

			if (tek->pages != size)
				return nullptr;

			if (tek->flags != flags)
				return nullptr;

			return tek;
		}

		tek = tek->next;

	}

	tailSS = (!headSS ? headSS: tailSS->next) = new SSList(name, size, flags);

	return tailSS;
}

void KernelSystem::deleteSS(const char* name) {
//	std::lock_guard<std::mutex> lock(mymutex);

	SSList *tek = headSS, *pret = nullptr;


	while (tek) {
		if (!strcmp(tek->name,name))
			break;
		pret = tek;
		tek = tek->next;
	}

	if (!tek)
		return;

	if (!pret)
		headSS = headSS->next;
	else
		pret->next = tek->next;

	if (!headSS)
		tailSS = nullptr;

	if (tek == tailSS)
		tailSS = pret;


	delete tek;


}

SSList* KernelSystem::findSeg(const char *name) {
	SSList *tek = headSS;

	while (tek) {
		if (!strcmp(tek->name, name))
			return tek;
		tek = tek->next;
	}

	return tek;
}