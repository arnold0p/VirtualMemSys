#include "KernelProcess.h"


extern unsigned long long pf;


KernelProcess::KernelProcess(ProcessId pid,Process *p):thrashmutex() {
	id = pid;
	myproc = p;
	pmt = nullptr;
	mySystem = nullptr;
	headS = tailS = nullptr;

	father = nullptr;
	tailchildren = headchildren = nullptr;
	blocked = false;
	pfcnt = acscnt = 0;
}

KernelProcess::~KernelProcess() {

	
		

	SegList *tek = headS,*stari;

	while (tek) {
		/*
		SSList *sseg = mySystem->findSeg(tek->name);

		SProcList *ptek = sseg->head, *pret = nullptr;

		ptek->proc->deleteSegment(tek->start);

		while (ptek) {
			if (ptek->proc->id == id)
				break;

			pret = ptek;
			ptek = ptek->next;

		}

		if (ptek) {


			if (!pret)
				sseg->head = sseg->head->next;
			else
				pret->next = ptek->next;

			if (!sseg->head)
				sseg->tail = nullptr;

			if (ptek == sseg->tail)
				sseg->tail = pret;




			ptek->proc->deleteseg(sseg->name);

			delete ptek;
		}

		*/
		stari = tek->next;
		this->disconnectSharedSegment(tek->name);
		tek = stari;

	}

	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	ProcList *ptek = headchildren,*pret=nullptr,*pstari;

	while (ptek) {

		if (pmt) {
			for (PageNum i = 0; i < sizeofpmt2; i++) {
				if (!pmt[i])
					continue;
				Descriptor* pmt2 = pmt[i];
				for (PageNum j = 0; j < sizeofpmt2; j++) {
					VirtualAddress addr = (i << (offw + offpg2)) | (j << offw);
					if (pmt2[j].s && pmt2[j].trueclone)
						unclonechildren(ptek->proc, addr);

				}
			}
		}
		ptek->proc->father = nullptr;

		pstari = ptek;	
		ptek = ptek->next;
		delete pstari;
	}

	if (father) {
		ptek = father->headchildren;
		while (ptek) {
			if (ptek->proc->getProcessId() == this->id)
				break;
			pret = ptek;
			ptek = ptek->next;
		}

		if (!ptek)
			return;

		if (!pret)
			father->headchildren = father->headchildren->next;
		else
			pret->next = ptek->next;

		if (!father->headchildren)
			father->tailchildren = nullptr;

		if (ptek == father->tailchildren)
			father->tailchildren = pret;

		delete ptek;
	}



	for (PageNum i = 0; i < sizeofpmt2; i++) {
		if (!pmt[i])
			continue;
		Descriptor* pmt2=pmt[i];
		for (PageNum j = 0; j < sizeofpmt2; j++) {
			if (!pmt2[j].s)
				continue;

			if (pmt2[j].shared)
				continue;
				

			if (pmt2[j].v) {
				mySystem->releaseVM(pmt2[j].block);
				mySystem->deleteDesc(&pmt2[j]);
			}

		
			mySystem->releaseCluster(pmt2[j].disk);
			

			/*
			if ((pmt2[j].trueshared && pmt2[j].shared) || !pmt2[j].shared)		//mozda ne treba
				mySystem->releaseCluster(pmt2[j].disk);
			*/

		}

		mySystem->releasePMT((PhysicalAddress)pmt2);
	}


	mySystem->releasePMT((PhysicalAddress)pmt);
	mySystem->deleteProc(id);

}

ProcessId KernelProcess::getProcessId() const {
	return id;

}

Status KernelProcess::createSegment(VirtualAddress startAddress, PageNum segmentSize,
	AccessType flags) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	if (startAddress & outmask)
		return TRAP;

	if (startAddress & wordmask)
		return TRAP;

	if (segmentSize > mySystem->fatpagecounter)
		return TRAP;

	PageNum pg1 = startAddress >> (offw + offpg2);
	PageNum pg2 = (startAddress >> offw) & maskpg2;

	Descriptor *pmt2;

	PageNum i = 0 , pmt2counter = 0;

	if (!pmt) {
		if (mySystem->pmtpagecounter == 0)
			return TRAP;

		setPMT1((int*)mySystem->searchforPMT());
	}

	while (i < segmentSize) {
		if (pg1 >= sizeofpmt1)
			return TRAP;

		if (pmt[pg1]) {
			pmt2 = pmt[pg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {
				if (pmt2[pg2].s)
					return TRAP;
				i++;
				pg2++;
			}
		}
		else {
			pmt2counter++;
			i += sizeofpmt2 - pg2;
		}

		pg1++;
		pg2 = 0;

	}

	if (mySystem->pmtpagecounter < pmt2counter)
		return TRAP;


	pg1 = startAddress >> (offw + offpg2);
	pg2 = (startAddress >> offw) & maskpg2;
	bool stseg = true;
	i = 0;


	while (i < segmentSize) {
		if (!pmt[pg1]) {
			pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
			pmt2 = pmt[pg1];
			for (int j = 0; j < sizeofpmt2; j++) {
				pmt2[j].r = pmt2[j].w = pmt2[j].x = 0;
				pmt2[j].s = 0;
				pmt2[j].ss = 0;
				pmt2[j].v = 0;
				pmt2[j].ref = 0;
				pmt2[j].shared = 0;
				pmt2[j].trueshared = 0;
				pmt2[j].clone = 0;
				pmt2[j].trueclone = 0;
	
			}
		}
		pmt2 = pmt[pg1];
		while (i < segmentSize && pg2 < sizeofpmt2) {
			pmt2[pg2].s = 1;
			if (stseg) {
				pmt2[pg2].ss = 1;
				stseg = false;
			}
			else
				pmt2[pg2].ss = 0;

			pmt2[pg2].v = 0;
			pmt2[pg2].d = 0;


			pmt2[pg2].r = pmt2[pg2].w = pmt2[pg2].x = 0;

			switch (flags) {
			case READ:
				pmt2[pg2].r = 1;
				break;
			case WRITE:
				pmt2[pg2].w = 1;			
				break;
			case READ_WRITE:
				pmt2[pg2].r = 1;
				pmt2[pg2].w = 1;
				break;
			case EXECUTE:
				pmt2[pg2].x = 1;
				break;

			}

			pmt2[pg2].ref = 0;
			pmt2[pg2].next = nullptr;

			
			pmt2[pg2].disk = mySystem->searchForCluster();
			

			i++;
			pg2++;
		}
		pg1++;
		pg2 = 0;

	}


	return OK;

}

Status KernelProcess::loadSegment(VirtualAddress startAddress, PageNum segmentSize,
	AccessType flags, void* content) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	if (startAddress & outmask)
		return TRAP;

	if (startAddress & wordmask)
		return TRAP;

	if (segmentSize > mySystem->fatpagecounter)
		return TRAP;

	PageNum pg1 = startAddress >> (offw + offpg2);
	PageNum pg2 = (startAddress >> offw) & maskpg2;

	Descriptor *pmt2;

	PageNum i = 0, pmt2counter = 0;;

	if (!pmt) {
		if (mySystem->pmtpagecounter == 0)
			return TRAP;
		setPMT1((int*)mySystem->searchforPMT());
	}

	while (i < segmentSize) {
		if (pg1 >= sizeofpmt1)
			return TRAP;

		if (pmt[pg1]) {
			pmt2 = pmt[pg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {
				if (pmt2[pg2].s)
					return TRAP;
				i++;
				pg2++;
			}
		}
		else {
			pmt2counter++;
			i += sizeofpmt2 - pg2;
		}

		pg1++;
		pg2 = 0;

	}

	if (mySystem->pmtpagecounter < pmt2counter)
		return TRAP;


	pg1 = startAddress >> (offw + offpg2);
	pg2 = (startAddress >> offw) & maskpg2;
	bool stseg = true;
	i = 0;

	char* cont = (char*)content;

	while (i < segmentSize) {
		if (!pmt[pg1]) {
			pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
			pmt2 = pmt[pg1];
			for (int j = 0; j < sizeofpmt2; j++) {
				pmt2[j].r = pmt2[j].w = pmt2[j].x = 0;
				pmt2[j].s = 0;
				pmt2[j].ss = 0;
				pmt2[j].v = 0;
				pmt2[j].ref = 0;
				pmt2[j].shared = 0;
				pmt2[j].trueshared = 0;
				pmt2[j].clone = 0;
				pmt2[j].trueclone = 0;
			
			}
		}
		pmt2 = pmt[pg1];
		while (i < segmentSize && pg2 < sizeofpmt2) {
			pmt2[pg2].s = 1;
			if (stseg) {
				pmt2[pg2].ss = 1;
				stseg = false;
			}
			else
				pmt2[pg2].ss = 0;

			pmt2[pg2].shared = 0;

			pmt2[pg2].v = 0;
			pmt2[pg2].d = 0;

			pmt2[pg2].r = pmt2[pg2].w = pmt2[pg2].x = 0;
			switch (flags) {
			case READ:
				pmt2[pg2].r = 1;
				break;
			case WRITE:
				pmt2[pg2].w = 1;
				break;
			case READ_WRITE:
				pmt2[pg2].r = 1;
				pmt2[pg2].w = 1;
				break;
			case EXECUTE:
				pmt2[pg2].x = 1;
				break;
			}

			pmt2[pg2].ref = 0;
			pmt2[pg2].next  = nullptr;

			pmt2[pg2].disk = mySystem->searchForCluster();
			

			mySystem->part->writeCluster(pmt2[pg2].disk, cont);

			cont += PAGE_SIZE;

			i++;
			pg2++;
		}
		pg1++;
		pg2 = 0;

	}


	return OK;


}

Status KernelProcess::deleteSegment(VirtualAddress startAddress) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	if (startAddress & outmask)
		return TRAP;

	if (startAddress & wordmask)
		return TRAP;


	PageNum pg1 = startAddress >> (offw + offpg2);
	PageNum pg2 = (startAddress >> offw) & maskpg2;

	Descriptor *pmt2 = pmt[pg1];

	if (!pmt2)
		return TRAP;

	if (!pmt2[pg2].ss || !pmt2[pg2].s)
		return TRAP;

	bool first = true;
	bool empty;

	while (first || (!pmt2[pg2].ss && pmt2[pg2].s)) {
		first = false;

		if (pmt2[pg2].trueclone && !pmt2[pg2].shared) {
			ProcList *tek = headchildren;

			VirtualAddress addr= (pg1 << (offw + offpg2) | (pg2 << offw));
			while (tek) {
				unclonechildren(tek->proc,addr );
				tek = tek->next;
			}
		}

		if (pmt2[pg2].v && !pmt2[pg2].shared && !pmt2[pg2].clone) {
			mySystem->releaseVM(pmt2[pg2].block);
			mySystem->deleteDesc(&pmt2[pg2]);
		}

		//if ((pmt2[pg2].trueshared && pmt2[pg2].shared) || !pmt2[pg2].shared)		//mozda ne treba
		//	mySystem->releaseCluster(pmt2[pg2].disk);

		
		if (!pmt2[pg2].shared && !pmt2[pg2].clone)
			mySystem->releaseCluster(pmt2[pg2].disk);
		

		pmt2[pg2].s = 0;
		pmt2[pg2].ss = 0;
		pmt2[pg2].v = 0;

		pg2++;

		if (pg2 >= sizeofpmt2) {
			empty = true;
			for (int j = 0; j < sizeofpmt2; j++)
				if (pmt2[j].s) {
					empty = false;
					break;
				}

			if (empty) {
				mySystem->releasePMT((PhysicalAddress)pmt2);
				pmt[pg1] = nullptr;
			}



			pg1++;
			pg2 = 0;

			if (pg1 >= sizeofpmt1)
				break;

			pmt2 = pmt[pg1];

			if (!pmt2)
				break;

		}

	}

	return OK;
}

Status KernelProcess::pageFault(VirtualAddress address) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);
	if (address & outmask)
		return TRAP;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;

	if (!pmt)
		return TRAP;

	if (!pmt[pg1])
		return TRAP;

	Descriptor *pmt2 = pmt[pg1];

	if (!pmt2[pg2].s)
		return TRAP;

	if (pmt2[pg2].shared) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}
	else
	if (pmt2[pg2].clone) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}

	if (pmt2[pg2].v)
		return TRAP;

	VirtualAddress addr;

	PhysicalAddress pomblo;

	Descriptor *victim = nullptr;
	
	if (mySystem->vmpagecounter > 0) {
		pomblo = mySystem->searchforVM();
	}
	else {
		pfcnt++;
		pf++;
		mySystem->syspfcnt++;
		victim = mySystem->getVictim();
		if (victim->d)
			mySystem->part->writeCluster(victim->disk, (char*)victim->block);

		victim->v = 0;
		victim->d = 0;
		victim->ref = 0;
		victim->next = nullptr;

		pomblo = victim->block;

	//	delete victim;
	}


	addr = (address >> offw) << offw;

	pmt2[pg2].block = pomblo;
	mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

	pmt2[pg2].v = 1;
	pmt2[pg2].ref = 0;
	pmt2[pg2].next=nullptr;


	mySystem->putDesc(&pmt2[pg2], this, addr);

	return OK;
}

PhysicalAddress KernelProcess::getPhysicalAddress(VirtualAddress address) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);
	if (address & outmask)
		return nullptr;

	if (!pmt)
		return nullptr;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;
	if (!pmt[pg1])
		return nullptr;

	Descriptor *pmt2=pmt[pg1];

	if (pmt2[pg2].shared) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}
	else
	if (pmt2[pg2].clone) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}

	if (!(pmt2[pg2].v))
		return nullptr;


	return (PhysicalAddress)((char*)pmt2[pg2].block + (address & wordmask));
}


void KernelProcess::setPMT1(int *pmt) {
	this->pmt =(Descriptor**) pmt;

	for (int i = 0; i < sizeofpmt1; i++)
		this->pmt[i] = nullptr;
}

void KernelProcess::setSystem(KernelSystem *sys) {
	mySystem = sys;
}

void KernelProcess::countchildren(KernelProcess *p,PageNum *cnt,VirtualAddress address) {

	if (!p->headchildren)
		return;
	
	ProcList *tek=p->headchildren;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;

	while (tek) {
		if (tek->proc->pmt[pg1][pg2].clone)	
			(*cnt)++;
		countchildren(tek->proc,cnt,address);
		tek = tek->next;

	}

}

void KernelProcess::unclonechildren(KernelProcess *p, VirtualAddress address) {

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;

	Descriptor *cpmt2, *fpmt2;

	ProcList *tek = p->headchildren;

	char blo[1024];

	cpmt2 = p->pmt[pg1];

	if (cpmt2[pg2].clone && !cpmt2[pg2].shared) {

		fpmt2 = (Descriptor*)cpmt2[pg2].block;

		cpmt2[pg2].disk = mySystem->searchForCluster();

		if (fpmt2->v)
			mySystem->part->writeCluster(cpmt2[pg2].disk, (char*)fpmt2->block);
		else {
			mySystem->part->readCluster(fpmt2->disk, blo);
			mySystem->part->writeCluster(cpmt2[pg2].disk, blo);
		}

		cpmt2[pg2].clone = 0;
		cpmt2[pg2].v = 0;
		cpmt2[pg2].block = nullptr;

		while (tek) {
			unclonechildren(tek->proc, address);
			tek = tek->next;
		}

	}


}

Status KernelProcess::copyonwrite(VirtualAddress address) {

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;

	Descriptor *pmt2, *fpmt2;

	char blo[1024];

	if (!headchildren) {

		if (mySystem->fatpagecounter == 0)
			return TRAP;

		pmt2 = pmt[pg1];

		fpmt2 =(Descriptor*)pmt2[pg2].block;

		pmt2[pg2].disk = mySystem->searchForCluster();

		if (fpmt2->v)
			mySystem->part->writeCluster(pmt2[pg2].disk,(char*) fpmt2->block);
		else {
			mySystem->part->readCluster(fpmt2->disk, blo);
			mySystem->part->writeCluster(pmt2[pg2].disk, blo);
		}

		pmt2[pg2].clone = 0;
		pmt2[pg2].v = 0;
		pmt2[pg2].block = nullptr;
		return PAGE_FAULT;
	}

	ProcList *tek;

	PageNum *cnt;

	cnt = new PageNum;

	

	if (headchildren) {

		pmt2 = pmt[pg1];

		if (pmt2[pg2].clone)
			*cnt = 1;
		else
			*cnt = 0;

		countchildren(this, cnt, address);
		
		if (*cnt > mySystem->fatpagecounter)
			return TRAP;
		
		tek = headchildren;

		while (tek) {
			unclonechildren(tek->proc, address);
			tek = tek->next;
		}

		pmt2 = pmt[pg1];

		if (pmt2[pg2].clone) {

			fpmt2 = (Descriptor*)pmt2[pg2].block;

			pmt2[pg2].disk = mySystem->searchForCluster();

			if (fpmt2->v)
				mySystem->part->writeCluster(pmt2[pg2].disk, (char*)fpmt2->block);
			else {
				mySystem->part->readCluster(fpmt2->disk, blo);
				mySystem->part->writeCluster(pmt2[pg2].disk, blo);
			}

			pmt2[pg2].clone = 0;
			pmt2[pg2].v = 0;
			pmt2[pg2].block = nullptr;
		}

		pmt2[pg2].trueclone = 0;

	}

	return PAGE_FAULT;

}
Status KernelProcess::access(VirtualAddress address, AccessType type) {

	if (address & outmask)
		return TRAP;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;


	if (!pmt)
		return TRAP;

	if (!pmt[pg1])
		return TRAP;

	Descriptor *pmt2 = pmt[pg1];



	if (!pmt2[pg2].s)
		return TRAP;

	switch (type) {
	case READ:
		if (!pmt2[pg2].r)
			return TRAP;
		break;
	case WRITE:
		if (!pmt2[pg2].w)
			return TRAP;
		break;
	case READ_WRITE:
		if (!pmt2[pg2].r || !pmt2[pg2].w)
			return TRAP;
		break;
	case EXECUTE:
		if (!pmt2[pg2].x)
			return TRAP;
		break;
	}


	if (pmt2[pg2].shared) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}
	else {
		if (headchildren && pmt2[pg2].trueclone && ((type == WRITE && pmt2[pg2].w) || (type == READ_WRITE && pmt2[pg2].w && pmt2[pg2].r ))) {
			acscnt++;
			mySystem->sysacscnt++;
			pmt2[pg2].d = 1;
			return copyonwrite(address);
		}
		if (pmt2[pg2].clone) {

			if ((type == WRITE && pmt2[pg2].w) || (type == READ_WRITE && pmt2[pg2].w && pmt2[pg2].r)) {
				acscnt++;
				mySystem->sysacscnt++;
				pmt2[pg2].d = 1;
				return copyonwrite(address);
			}
			else {
				pmt2 = (Descriptor*)pmt2[pg2].block;
				pg2 = 0;
			}

		}
	}

	if (type == WRITE || type == READ_WRITE)
		pmt2[pg2].d = 1;
	

	if (!(pmt2[pg2].v) && (pmt2[pg2].s)) {
		acscnt++;
		mySystem->sysacscnt++;
		return PAGE_FAULT;
	}

	switch (type) {
	case READ:
		if (!pmt2[pg2].r)
			return TRAP;
		break;
	case WRITE:
		if (!pmt2[pg2].w)
			return TRAP;
	
		pmt2[pg2].d = 1;
		break;
	case READ_WRITE:
		if (!pmt2[pg2].r || !pmt2[pg2].w)
			return TRAP;

		pmt2[pg2].d = 1;	
		break;
	case EXECUTE:
		if (!pmt2[pg2].x)
			return TRAP;
		break;

	}

	acscnt++;
	mySystem->sysacscnt++;
	pmt2[pg2].ref = 1;

	return OK;

}


KernelProcess* KernelProcess::clone(KernelProcess *father) {

	PageNum i;
	PageNum numofpmt = 1;

	if (father->pmt) {
		for (i = 0; i < sizeofpmt1; i++) {
			if (father->pmt[i])
				numofpmt++;
		}

		if (numofpmt > mySystem->pmtpagecounter)
			return nullptr;



		setPMT1((int*)mySystem->searchforPMT());


		PageNum j;

		Descriptor *cpmt2, *fpmt2;

		for (i = 0; i < sizeofpmt1; i++) {
			if (father->pmt[i]) {

				fpmt2 = father->pmt[i];
				pmt[i] = (Descriptor*)mySystem->searchforPMT();
				cpmt2 = pmt[i];


				for (j = 0; j < sizeofpmt2; j++) {
					cpmt2[j].s = fpmt2[j].s;
					cpmt2[j].ss = fpmt2[j].ss;

					if (!fpmt2[j].shared)
						cpmt2[j].clone = 1;
					else
						cpmt2[j].clone = 0;


					fpmt2[j].trueclone = 1;									// otac postaje otac...

					cpmt2[j].shared = fpmt2[j].shared;
					cpmt2[j].trueshared = fpmt2[j].trueshared;
					cpmt2[j].r = fpmt2[j].r;
					cpmt2[j].w = fpmt2[j].w;
					cpmt2[j].x = fpmt2[j].x;

					cpmt2[j].v = cpmt2[j].d = cpmt2[j].ref = 0;

					if (fpmt2[j].shared) {
						cpmt2[j].block = fpmt2[j].block;					// ako je otac sherovan, pokazuje na pravi za shared
						continue;
					}

					if (fpmt2[j].clone) {
						cpmt2[j].block = fpmt2[j].block;					// ako je otac clone, pokazuje je na ocevog klona tj ocevog oca
						continue;
					}

					cpmt2[j].block = (PhysicalAddress)&fpmt2[j];			// inace pokazuje na oca



				}
			}

		}
	}

	this->father = father;

	father->tailchildren = (!father->headchildren ? father->headchildren : father->tailchildren->next) = new ProcList(this);


	SegList *tek = father->headS;
	SSList *seg;

	while (tek) {
		tailS = (!headS ? headS : tailS->next) = new SegList(tek->seg, tek->name, tek->start, tek->size);
		seg = mySystem->findSeg(tek->name);
		seg->tail = (!seg->head ? seg->head : seg->tail->next) = new SProcList(this, tek->start);

		tek = tek->next;
	}

	return this;

}

void KernelProcess::deleteseg(const char *name) {

	SegList *tek = headS,*pret = nullptr;

	
	while (tek) {
		if (!strcmp(tek->name, name))
			break;
		pret = tek;
		tek = tek->next;
	}

	if (!tek)
		return;

	if (!pret)
		headS = headS->next;
	else
		pret->next = tek->next;

	if (!headS)
		tailS = nullptr;

	if (tek == tailS)
		tailS = pret;


	delete tek;
	

}


Status KernelProcess::createSharedSegment(VirtualAddress startAddress,
	PageNum segmentSize, const char* name, AccessType flags) {
	std::lock_guard<std::mutex> lock(mySystem->mymutex);
	if (startAddress & outmask)
		return TRAP;

	if (startAddress & wordmask)
		return TRAP;

	if (segmentSize > mySystem->fatpagecounter)
		return TRAP;

	PageNum pg1 = startAddress >> (offw + offpg2);
	PageNum pg2 = (startAddress >> offw) & maskpg2;

	Descriptor *pmt2,*spmt2;

	PageNum i = 0, pmt2counter = 0;

	if (!pmt) {
		if (mySystem->pmtpagecounter == 0)
			return TRAP;
		setPMT1((int*)mySystem->searchforPMT());
	}

	while (i < segmentSize) {
		if (pg1 >= sizeofpmt1)
			return TRAP;

		if (pmt[pg1]) {
			pmt2 = pmt[pg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {
				if (pmt2[pg2].s)
					return TRAP;
				i++;
				pg2++;
			}
		}
		else {
			pmt2counter++;
			i += sizeofpmt2 - pg2;
		}

		pg1++;
		pg2 = 0;

	}

	if (mySystem->pmtpagecounter < pmt2counter)
		return TRAP;


	pg1 = startAddress >> (offw + offpg2);
	pg2 = (startAddress >> offw) & maskpg2;
	bool stseg = true;
	i = 0;

	SSList *seg = mySystem->putSS(this,name,segmentSize,flags);

	if (!seg)
		return TRAP;

	PageNum spg1 = 0;
	PageNum spg2 = 0;

	
	if (seg->first) {

		if (mySystem->pmtpagecounter < 2 * pmt2counter + 1)
			return TRAP;

		seg->first = false;
		seg->pmt =(Descriptor**) mySystem->searchforPMT();

		for (PageNum j = 0; j < sizeofpmt1; j++) {
			seg->pmt[j] = nullptr;
		}



		while (i < segmentSize) {
			if (!pmt[pg1]) {
				pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
				pmt2 = pmt[pg1];
				for (int j = 0; j < sizeofpmt2; j++) {
					pmt2[j].s = 0;
					pmt2[j].ss = 0;
					pmt2[j].v = 0;
					pmt2[j].ref = 0;
					pmt2[j].shared = 0;
					pmt2[j].trueshared = 0;
					pmt2[j].clone = 0;
				}
			} 
			if (!seg->pmt[spg1]) {
				seg->pmt[spg1] = (Descriptor*)mySystem->searchforPMT();
				spmt2 = seg->pmt[spg1];
				for (PageNum j = 0; j < sizeofpmt2; j++) {
					spmt2[j].s = 0;
					spmt2[j].ss = 0;
					spmt2[j].v = 0;
					spmt2[j].ref = 0;
					spmt2[j].shared = 0;
					spmt2[j].trueshared = 0;
					spmt2[j].clone = 0;
				}
			}

			pmt2 = pmt[pg1];
			spmt2 = seg->pmt[spg1];

			while (i < segmentSize && pg2 < sizeofpmt2) {
				spmt2[spg2].s=pmt2[pg2].s = 1;

				if (stseg) {		
					spmt2[spg2].ss=pmt2[pg2].ss = 1;				// izmenio sam sve sa ***seg->desc[i].? = pmt2[pg2].?***
					stseg = false;
				}
				else
					spmt2[spg2].ss=pmt2[pg2].ss = 0;

				spmt2[spg2].shared=pmt2[pg2].shared = 1;
		//		pmt2[pg2].trueshared = 1;								//ludilo
				spmt2[spg2].v = pmt2[pg2].v = 0;
				spmt2[spg2].d = pmt2[pg2].d = 0;

				switch (flags) {
				case READ:
					spmt2[spg2].r = pmt2[pg2].r = 1;
					break;
				case WRITE:
					spmt2[spg2].w = pmt2[pg2].w = 1;
					break;
				case READ_WRITE:
					spmt2[spg2].r = pmt2[pg2].r = 1;
					spmt2[spg2].w = pmt2[pg2].w = 1;
					break;
				case EXECUTE:
					spmt2[spg2].x = pmt2[pg2].x = 1;
					break;

				}
				spmt2[spg2].ref = pmt2[pg2].ref = 0;
				spmt2[spg2].next = pmt2[pg2].next = nullptr;

				spmt2[spg2].disk = mySystem->searchForCluster();

				pmt2[pg2].block= (PhysicalAddress)&spmt2[spg2];



				i++;
				pg2++;

				spg2++;
				if (spg2 >= sizeofpmt2) {
					spg1++;
					spg2 = 0;
					if (!seg->pmt[spg1]) {
						seg->pmt[spg1] = (Descriptor*)mySystem->searchforPMT();
						spmt2 = seg->pmt[spg1];
						for (PageNum j = 0; j < sizeofpmt2; j++) {
							spmt2[j].s = 0;
							spmt2[j].ss = 0;
							spmt2[j].v = 0;
							spmt2[j].ref = 0;
							spmt2[j].shared = 0;
							spmt2[j].trueshared = 0;
							spmt2[j].clone = 0;
						}
					}
					spmt2 = seg->pmt[spg1]; 
				}

			}
			pg1++;
			pg2 = 0;

		}

	}
	else {	
		while (i < segmentSize) {
			if (!pmt[pg1]) {
				pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
				pmt2 = pmt[pg1];
				for (int j = 0; j < sizeofpmt2; j++) {
					pmt2[j].s = 0;
					pmt2[j].ss = 0;
					pmt2[j].v = 0;
					pmt2[j].ref = 0;
					pmt2[j].shared = 0;
					pmt2[j].trueshared = 0;
					pmt2[j].clone = 0;
				}
			}
			pmt2 = pmt[pg1];
			spmt2 = seg->pmt[spg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {

				pmt2[pg2].s = spmt2[spg2].s;
				pmt2[pg2].ss = spmt2[spg2].ss;
				pmt2[pg2].shared = 1;

				pmt2[pg2].v = spmt2[spg2].v;
				pmt2[pg2].d = spmt2[spg2].d;


				switch (flags) {
				case READ:
					pmt2[pg2].r = 1;
					break;
				case WRITE:
					pmt2[pg2].w = 1;
					break;
				case READ_WRITE:
					pmt2[pg2].r = 1;
					pmt2[pg2].w = 1;
					break;
				case EXECUTE:
					pmt2[pg2].x = 1;
					break;

				}
				pmt2[pg2].ref = spmt2[spg2].ref;
				pmt2[pg2].next = nullptr;

				pmt2[pg2].disk = spmt2[spg2].disk;

				pmt2[pg2].block = (PhysicalAddress)&spmt2[spg2];


				i++;
				pg2++;
				spg2++;

				if (spg2 >= sizeofpmt2) {
					spg1++;
					spg2 = 0;
					spmt2 = seg->pmt[spg1];
				}
	
			}
			pg1++;
			pg2 = 0;

		}
		
	}
	
	tailS = (!headS ? headS : tailS->next) = new SegList(seg,name, startAddress,segmentSize);

	seg->tail = (!seg->head ? seg->head : seg->tail->next) = new SProcList(this, startAddress);
	return OK;

}
Status KernelProcess::disconnectSharedSegment(const char* name) {
	
	SSList *sseg = mySystem->findSeg(name);

	if (!sseg)
		return TRAP;

	SProcList *tek = sseg->head, *pret = nullptr;



	while (tek) {
		if (tek->proc->id == id)
			break;

		pret = tek;
		tek = tek->next;

	}

	if (!tek)
		return TRAP;

	tek->proc->deleteSegment(tek->start);

	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	if (!pret)
		sseg->head = sseg->head->next;
	else
		pret->next = tek->next;

	if (!sseg->head)
		sseg->tail = nullptr;

	if (tek == sseg->tail)
		sseg->tail = pret;

	


	tek->proc->deleteseg(sseg->name);

	delete tek;

	return OK;
}

Status KernelProcess::deleteSharedSegment(const char* name) {

	SSList *seg = mySystem->findSeg(name);

	if (!seg)
		return TRAP;
	SProcList *tek = seg->head,*stari;
	/*
	for (PageNum i = 0; i < seg->pages; i++) {
		if (seg->descs[i].v) {
			seg->descs[i].v = 0;
			mySystem->releaseVM(seg->descs[i].block);
			mySystem->deleteDesc(&seg->descs[i]);
		}
		mySystem->releaseCluster(seg->descs[i].disk);

	}
	*/

	Descriptor *pmt2;
	/*
	if (seg->pmt) {
		for (PageNum j = 0; j < sizeofpmt1; j++) {
			if (seg->pmt[j]) {
				pmt2 = seg->pmt[j];
				for (PageNum k = 0; k < sizeofpmt2; k++) {

					if (!pmt2[k].s)
					continue;

					if (pmt2[j].v) {
						mySystem->releaseVM(pmt2[k].block);
						mySystem->deleteDesc(&pmt2[k]);
					}


					mySystem->releaseCluster(pmt2[k].disk);

				}


				mySystem->releasePMT(seg->pmt[j]);
			}
		}
		mySystem->releasePMT(seg->pmt);
	}
	*/

	

	while (tek) {
		tek->proc->deleteSegment(tek->start);
		tek = tek->next;	
	}

	std::lock_guard<std::mutex> lock(mySystem->mymutex);

	PageNum pg1 = 0, pg2 = 0;

	if (seg->pmt) {
		pmt2 = seg->pmt[pg1];
		for (PageNum i = 0; i< seg->pages; i++) {
			if (!pmt2)
				continue;

			if (!pmt2[pg2].s)
				continue;

			if (pmt2[pg2].v) {
				mySystem->releaseVM(pmt2[pg2].block);
				mySystem->deleteDesc(&pmt2[pg2]);
			}


			mySystem->releaseCluster(pmt2[pg2].disk);

			pg2++;

			if (pg2 >= sizeofpmt2) {
				mySystem->releasePMT(seg->pmt[pg1]);
				pg1++;
				pg2 = 0;
				pmt2 = seg->pmt[pg1];
			}
		}
		mySystem->releasePMT(seg->pmt);
	}

	tek = seg->head;

	while (tek) {
		stari = tek;
		tek->proc->deleteseg(seg->name);
		tek = tek->next;
		delete stari;
	}

	mySystem->deleteSS(name);


	return OK;
}


void KernelProcess::blockIfThrashing() {
	thrashmutex.lock();
	thrashmutex.unlock();
}



/*
************************************************************************************************************
drugi nacin




************************************************************************************************************
*/
/*
Status KernelProcess::createSharedSegment(VirtualAddress startAddress,
	PageNum segmentSize, const char* name, AccessType flags) {
	if (startAddress & outmask)
		return TRAP;

	if (startAddress & wordmask)
		return TRAP;

	if (segmentSize > mySystem->fatpagecounter)
		return TRAP;

	PageNum pg1 = startAddress >> (offw + offpg2);
	PageNum pg2 = (startAddress >> offw) & maskpg2;

	Descriptor *pmt2;

	PageNum i = 0, pmt2counter = 0;;

	while (i < segmentSize) {
		if (pg1 >= sizeofpmt1)
			return TRAP;

		if (pmt[pg1]) {
			pmt2 = pmt[pg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {
				if (pmt2[pg2].s)
					return TRAP;
				i++;
				pg2++;
			}
		}
		else {
			pmt2counter++;
			i += sizeofpmt2 - pg2;
		}

		pg1++;
		pg2 = 0;

	}

	if (mySystem->pmtpagecounter < pmt2counter)
		return TRAP;


	pg1 = startAddress >> (offw + offpg2);
	pg2 = (startAddress >> offw) & maskpg2;
	bool stseg = true;
	i = 0;

	SSList *seg = mySystem->putSS(this, name, segmentSize, flags);

	if (!seg)
		return TRAP;

	if (seg->first) {
		seg->first = false;
		while (i < segmentSize) {
			if (!pmt[pg1]) {
				pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
				pmt2 = pmt[pg1];
				for (int j = 0; j < sizeofpmt2; j++) {
					pmt2[j].s = 0;
					pmt2[j].ss = 0;
					pmt2[j].v = 0;
					pmt2[j].ref = 0;
					pmt2[j].trueshared = 0;
				}
			}
			pmt2 = pmt[pg1];
			while (i < segmentSize && pg2 < sizeofpmt2) {
				pmt2[pg2].s = 1;
				if (stseg) {
					pmt2[pg2].ss = 1;				// izmenio sam sve sa ***seg->desc[i].? = pmt2[pg2].?***
					stseg = false;
				}
				else
					pmt2[pg2].ss = 0;

				pmt2[pg2].shared = 1;
				pmt2[pg2].trueshared = 1;								//ludilo
				pmt2[pg2].v = 0;
				pmt2[pg2].d = 0;

				switch (flags) {
				case READ:
					pmt2[pg2].r = 1;
					break;
				case WRITE:
					pmt2[pg2].w = 1;
					break;
				case READ_WRITE:
					pmt2[pg2].r = 1;
					pmt2[pg2].w = 1;
					break;
				case EXECUTE:
					pmt2[pg2].x = 1;
					break;

				}
				pmt2[pg2].ref = 0;
				pmt2[pg2].next = nullptr;

				pmt2[pg2].disk = mySystem->searchForCluster();


				i++;
				pg2++;
			}
			pg1++;
			pg2 = 0;

		}

	}
	else { 
		if (seg->head) {
			SProcList *pom = seg->head;
			VirtualAddress pomstart = seg->head->start;
			PageNum pompg1 = pomstart >> (offw + offpg2);
			PageNum pompg2 = (pomstart >> offw) & maskpg2;
			Descriptor *pompmt2 = seg->head->proc->pmt[pompg1];

			while (i < segmentSize) {
				if (!pmt[pg1]) {
					pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
					pmt2 = pmt[pg1];
					for (int j = 0; j < sizeofpmt2; j++) {
						pmt2[j].s = 0;
						pmt2[j].ss = 0;
						pmt2[j].v = 0;
						pmt2[j].ref = 0;
						pmt2[j].trueshared = 0;
					}
				}
				pmt2 = pmt[pg1];
				while (i < segmentSize && pg2 < sizeofpmt2) {
					
					pmt2[pg2].s = pompmt2[pompg2].s;
					pmt2[pg2].ss = pompmt2[pompg2].ss;
					pmt2[pg2].shared = pompmt2[pompg2].shared;

					pmt2[pg2].trueshared = 0;											// ludiloo

					pmt2[pg2].v = pompmt2[pompg2].v;
					pmt2[pg2].d = pompmt2[pompg2].d;
					

					pmt2[pg2].s = pompmt2[pompg2].s;
					pmt2[pg2].ss = pompmt2[pompg2].ss;
					pmt2[pg2].shared = 1;

					pmt2[pg2].v = pompmt2[pompg2].v;
					pmt2[pg2].d = pompmt2[pompg2].d;


					switch (flags) {
					case READ:
						pmt2[pg2].r = 1;
						break;
					case WRITE:
						pmt2[pg2].w = 1;
						break;
					case READ_WRITE:
						pmt2[pg2].r = 1;
						pmt2[pg2].w = 1;
						break;
					case EXECUTE:
						pmt2[pg2].x = 1;
						break;

					}
					
					pmt2[pg2].ref = pompmt2[pompg2].ref;
					pmt2[pg2].next = pompmt2[pompg2].next;

					pmt2[pg2].disk = pompmt2[pompg2].disk;
					
					pmt2[pg2].block = (PhysicalAddress) &pompmt2[pompg2];                //ludilo


					pmt2[pg2].ref = pompmt2[pompg2].ref;
					pmt2[pg2].next = pompmt2[pompg2].next;

					pmt2[pg2].disk = pompmt2[pompg2].disk;

					pompg2++;
					i++;
					pg2++;

					if (pompg2 >= sizeofpmt2) {
						pompg1++;
						pompg2 = 0;
						pompmt2 = seg->head->proc->pmt[pompg1];
					}
				}
				pg1++;
				pg2 = 0;

			}
		}
		else {

			pg1 = startAddress >> (offw + offpg2);
			pg2 = (startAddress >> offw) & maskpg2;

			while (i < segmentSize) {
				if (!pmt[pg1]) {
					pmt[pg1] = (Descriptor*)mySystem->searchforPMT();
					pmt2 = pmt[pg1];
					for (int j = 0; j < sizeofpmt2; j++) {
						pmt2[j].s = 0;
						pmt2[j].ss = 0;
						pmt2[j].v = 0;
						pmt2[j].ref = 0;
						pmt2[j].trueshared = 0;
					}
				}
				pmt2 = pmt[pg1];
				while (i < segmentSize && pg2 < sizeofpmt2) {
					pmt2[pg2].s = 1;
					if (stseg) {
						pmt2[pg2].ss = 1;				// izmenio sam sve sa ***seg->desc[i].? = pmt2[pg2].?***
						stseg = false;
					}
					else
						pmt2[pg2].ss = 0;

					pmt2[pg2].shared = 1;
					pmt2[pg2].trueshared = 1;								//ludilo
					pmt2[pg2].v = 0;
					pmt2[pg2].d = 0;

					switch (flags) {
					case READ:
						pmt2[pg2].r = 1;
						break;
					case WRITE:
						pmt2[pg2].w = 1;
						break;
					case READ_WRITE:
						pmt2[pg2].r = 1;
						pmt2[pg2].w = 1;
						break;
					case EXECUTE:
						pmt2[pg2].x = 1;
						break;

					}
					pmt2[pg2].ref = 0;
					pmt2[pg2].next = nullptr;

					pmt2[pg2].disk = seg->disks[i];
					i++;
					pg2++;
				}
				pg1++;
				pg2 = 0;

			}

			delete seg->disks;

		}


	}

	tailS = (!headS ? headS : tailS->next) = new SegList(seg, name, startAddress, segmentSize);

	seg->tail = (!seg->head ? seg->head : seg->tail->next) = new SProcList(this, startAddress);
	return OK;
}


Status KernelProcess::disconnectSharedSegment(const char* name) {
	SSList *seg = mySystem->findSeg(name);

	if (!seg)
		return TRAP;

	SProcList *tek = seg->head, *pret = nullptr, *pomhead, *pomtek;

	while (tek) {
		if (tek->proc->id == id)
			break;

		pret = tek;
		tek = tek->next;

	}

	if (!tek)
		return TRAP;



	if (seg->pages > mySystem->fatpagecounter)
		return TRAP;


	PageNum i= 0 ;
	VirtualAddress pomstart;
	PageNum pompg1;
	PageNum pompg2;
	Descriptor *pompmt2;
	VirtualAddress start;
	PageNum pg1;
	PageNum pg2;
	Descriptor *pmt2;
	char blo[1024];

	if (seg->head->proc->id == tek->proc->id) {
		if (seg->head->next) {
			start = tek->start;
			pg1 = start >> (offw + offpg2);
			pg2 = (start >> offw) & maskpg2;

			pomhead = seg->head->next;
			pomstart = pomhead->start;
			pompg1 = pomstart >> (offw + offpg2);
			pompg2 = (pomstart >> offw) & maskpg2;

			pmt2 = pmt[pg1];
			pompmt2 = pomhead->proc->pmt[pompg1];
			i = 0;

			while (i < seg->pages) {
				pmt2 = pmt[pg1];
				pompmt2 = pomhead->proc->pmt[pompg1];
				while (i < seg->pages && pg2 < sizeofpmt2) {
					pmt2[pg2].shared = 0;

					pmt2[pg2].trueshared = 0;											// ludiloo


					pompmt2[pompg2].trueshared = 1;

					pompmt2[pompg2].disk = pmt2[pg2].disk;
																						// sledeci postaje glavni shared
					pompmt2[pompg2].v = 0;
					pompmt2[pompg2].d = 0;
					pompmt2[pompg2].ref = 0;
					pompmt2[pompg2].next = nullptr;

					pompmt2[pompg2].disk = mySystem->searchForCluster();

					if (pmt2[pg2].v)
						mySystem->part->writeCluster(pompmt2[pompg2].disk, (char*)pmt2[pg2].block);
					else {

						mySystem->part->readCluster(pmt2[pg2].disk, blo);
						mySystem->part->writeCluster(pompmt2[pompg2].disk, blo);
					}

					pompg2++;
					i++;
					pg2++;

					if (pompg2 >= sizeofpmt2) {
						pompg1++;
						pompg2 = 0;
						pompmt2 = pomhead->proc->pmt[pompg1];
					}
				}
				pg1++;
				pg2 = 0;

			}

			pomtek = pomhead->next;

			while (pomtek) {
				start = pomtek->start;
				pg1 = start >> (offw + offpg2);
				pg2 = (start >> offw) & maskpg2;

				pomstart = pomhead->start;
				pompg1 = pomstart >> (offw + offpg2);
				pompg2 = (pomstart >> offw) & maskpg2;

				i = 0;
				while (i < seg->pages) {

					pmt2 = pomtek->proc->pmt[pg1];
					pompmt2 = pomhead->proc->pmt[pompg1];
					while (i < seg->pages && pg2 < sizeofpmt2) {

						pmt2[pg2].block = (PhysicalAddress)&pompmt2[pompg2];

						pompg2++;
						i++;
						pg2++;

						if (pompg2 >= sizeofpmt2) {
							pompg1++;
							pompg2 = 0;
							pompmt2 = pomhead->proc->pmt[pompg1];
						}
					}
					pg1++;
					pg2 = 0;

				}

			}


		}
		else {

			seg->disks = new ClusterNo[seg->pages];
			i = 0;

			start = tek->start;
			pg1 = start >> (offw + offpg2);
			pg2 = (start >> offw) & maskpg2;

			while (i < seg->pages) {
				pmt2 = pmt[pg1];
				while (i < seg->pages && pg2 < sizeofpmt2) {
					pmt2[pg2].shared = 0;

					pmt2[pg2].trueshared = 0;											// ludiloo

					seg->disks[i] = mySystem->searchForCluster();


					if (pmt2[pg2].v)
						mySystem->part->writeCluster(seg->disks[i], (char*)pmt2[pg2].block);
					else {

						mySystem->part->readCluster(pmt2[pg2].disk, blo);
						mySystem->part->writeCluster(seg->disks[i], blo);
					}


					i++;
					pg2++;
					
				}
				pg1++;
				pg2 = 0;

			}

			

		}


	}

	else {

		start = tek->start;
		pg1 = start >> (offw + offpg2);
		pg2 = (start >> offw) & maskpg2;

		i = 0;

		Descriptor *fir;

		while (i < seg->pages) {
			pmt2 = pmt[pg1];
			while (i < seg->pages && pg2 < sizeofpmt2) {

				pmt2[pg2].shared = 0;

				pmt2[pg2].trueshared = 0;											// ludiloo

				pmt2[pg2].disk = mySystem->searchForCluster();

				fir = (Descriptor*)pmt2[pg2].block;

				if (fir->v)
					mySystem->part->writeCluster(pmt2[pg2].disk, (char*)fir->block);
				else {

					mySystem->part->readCluster(fir->disk, blo);
					mySystem->part->writeCluster(pmt2[pg2].disk, blo);
				}

				i++;
				pg2++;



			}
			pg1++;
			pg2 = 0;

		}



	}
	if (!pret)
		seg->head = seg->head->next;
	else
		pret->next = tek->next;

	if (!seg->head)
		seg->tail = nullptr;

	if (tek == seg->tail)
		seg->tail = pret;

	delete tek;

	return OK;
}
*/
/*
Status KernelProcess::pageFault(VirtualAddress address) {

	if (address & outmask)
		return TRAP;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;

	if (!pmt[pg1])
		return TRAP;

	Descriptor *pmt2 = pmt[pg1];

	if (!pmt2[pg2].s)
		return TRAP;

	if (pmt2[pg2].shared) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}

	if (pmt2[pg2].v)
		return TRAP;

	VirtualAddress addr;

	PhysicalAddress pomblo;

	DescList *victim = nullptr;

	if (mySystem->vmpagecounter > 0) {
		pomblo = mySystem->searchforVM();
	}
	else {
		victim = mySystem->getVictim();
		if (victim->desc->d)
			mySystem->part->writeCluster(victim->desc->disk, (char*)victim->desc->block);
		/*
		if (victim->desc->shared) {

		//
		SegList *seg = victim->proc->findSeg(victim->address);
		SSList *sseg = victim->proc->mySystem->findSeg(seg->name);

		addr = sseg->head->start;
		addr >>= offw;
		addr += (victim->address >> offw) - (seg->start >> offw);
		addr <<= offw;
		pg1 = addr >> (offw + offpg2);
		pg2 = (addr >> offw) & maskpg2;														// novo
		pmt2 = sseg->head->proc->pmt[pg1];
		pmt2[pg2].v = 0;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;
		//

		//
		SProcList *tek = sseg->head;

		while (tek) {
		addr = tek->start;
		addr >>= offw;
		addr += (victim->address>> offw) - (seg->start >> offw);
		addr <<= offw;
		pg1 = addr >> (offw + offpg2);
		pg2 = (addr >> offw) & maskpg2;
		pmt2 = tek->proc->pmt[pg1];
		pmt2[pg2].v = 0;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;

		tek = tek->next;

		mySystem->deleteDesc(&pmt2[pg2]);

		}

		}
		else {
		victim->desc->v = 0;
		victim->desc->d = 0;
		victim->desc->ref = 0;
		victim->desc->refcounter = 0;
		}
		//
		victim->desc->v = 0;
		victim->desc->d = 0;
		victim->desc->ref = 0;
		victim->desc->refcounter = 0;

		pomblo = victim->desc->block;

	}

	pg1 = address >> (offw + offpg2);
	pg2 = (address >> offw) & maskpg2;

	pmt2 = pmt[pg1];
	//
	PhysicalAddress blo = pmt2[pg2].block;

	mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

	pmt2[pg2].v = 1;
	pmt2[pg2].d = 0;
	pmt2[pg2].ref = 0;
	pmt2[pg2].refcounter = 0;
	//

	if (pmt2[pg2].shared) {

		if (pmt2[pg2].shared) {
			pmt2 = (Descriptor*)pmt2[pg2].block;
			pg2 = 0;
		}

		addr = (address >> offw) << offw;
		pmt2[pg2].block = pomblo;
		mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

		pmt2[pg2].v = 1;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;

		mySystem->putDesc(&pmt2[pg2], this, addr);


		/*
		if (pmt2[pg2].trueshared) {
		addr = (address >> offw) << offw;
		pmt2[pg2].block = pomblo;
		mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

		pmt2[pg2].v = 1;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;

		mySystem->putDesc(&pmt2[pg2],this , addr);

		}
		else {
		SegList *seg = findSeg(address);
		SSList *sseg = mySystem->findSeg(seg->name);


		addr = sseg->head->start;
		addr >>= offw;
		addr += (address >> offw) - (seg->start >> offw);
		addr <<= offw;
		pg1 = addr >> (offw + offpg2);
		pg2 = (addr >> offw) & maskpg2;														// novo
		pmt2 = sseg->head->proc->pmt[pg1];
		pmt2[pg2].v = 1;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;

		pmt2[pg2].block = pomblo;

		mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

		mySystem->putDesc(&pmt2[pg2], sseg->head->proc, addr);

		delete victim;
		//
		SProcList *tek = sseg->head;

		while (tek) {
		addr = tek->start;
		addr >>= offw;
		addr += (address >> offw) - (seg->start >> offw);
		addr <<= offw;
		pg1 = addr >> (offw + offpg2);
		pg2 = (addr >> offw) & maskpg2;
		pmt2 = tek->proc->pmt[pg1];
		pmt2[pg2].v = 1;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;
		pmt2[pg2].block = blo;

		mySystem->putDesc(&pmt2[pg2], tek->proc, addr);

		tek = tek->next;
		}//
		//	}
	}
	else {
		pmt2[pg2].block = pomblo;
		mySystem->part->readCluster(pmt2[pg2].disk, (char*)pmt2[pg2].block);

		pmt2[pg2].v = 1;
		pmt2[pg2].d = 0;
		pmt2[pg2].ref = 0;
		pmt2[pg2].refcounter = 0;
		addr = (address >> offw) << offw;
		mySystem->putDesc(&pmt2[pg2], this, addr);
	}

	return OK;
}

PhysicalAddress KernelProcess::getPhysicalAddress(VirtualAddress address) {

	if (address & outmask)
		return nullptr;

	PageNum pg1 = address >> (offw + offpg2);
	PageNum pg2 = (address >> offw) & maskpg2;
	if (!pmt[pg1])
		return nullptr;

	Descriptor *pmt2 = pmt[pg1];

	if (pmt2[pg2].shared) {
		pmt2 = (Descriptor*)pmt2[pg2].block;
		pg2 = 0;
	}
	//
	if (pmt2[pg2].shared && !pmt2[pg2].trueshared) {
	pmt2 = (Descriptor*)pmt2[pg2].block;
	pg2 = 0;
	}
	//
	if (!(pmt2[pg2].v))
		return nullptr;


	return (PhysicalAddress)((char*)pmt2[pg2].block + (address & wordmask));
}
*/


/*

******************************************
petljica
*****************************************


SegList *seg = findSeg(address);
SSList *sseg = mySystem->findSeg(seg->name);

SProcList *tek = sseg->head;

while (tek) {
VirtualAddress addr = tek->start;
addr >>= offw;
addr += (address >> offw) - (seg->start >> offw);
addr <<= offw;
pg1 = addr >> (offw + offpg2);
pg2 = (addr >> offw) & maskpg2;
Descriptor *pmt2 = tek->proc->pmt[pg1];
pmt2[pg2].d = 1;

tek = tek->next;
}
*/

