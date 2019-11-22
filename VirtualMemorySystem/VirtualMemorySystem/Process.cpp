#include "Process.h"
#include "KernelProcess.h"

Process::Process(ProcessId pid) {
	pProcess = new KernelProcess(pid,this);

}

Process::~Process() {
	delete pProcess;
			
}

ProcessId Process::getProcessId() const {
	return pProcess->getProcessId();

}

Status Process::createSegment(VirtualAddress startAddress, PageNum segmentSize,
	AccessType flags) {
	
	return pProcess->createSegment(startAddress, segmentSize, flags);
}

Status Process::loadSegment(VirtualAddress startAddress, PageNum segmentSize,
	AccessType flags, void* content) {
	
	return pProcess->loadSegment(startAddress, segmentSize, flags, content);
}

Status Process::deleteSegment(VirtualAddress startAddress) {
	return pProcess->deleteSegment(startAddress);
}

Status Process::pageFault(VirtualAddress address) {
	return pProcess->pageFault(address);
}

PhysicalAddress Process::getPhysicalAddress(VirtualAddress address) {
	return pProcess->getPhysicalAddress(address);
}


Process* Process::clone(ProcessId pid) {
	Process *tmp = new Process(pid);
	KernelProcess *pom;

	tmp->pProcess->setSystem(pProcess->mySystem);
	
	pom=tmp->pProcess->clone(pProcess);

	if (!pom) {
		delete tmp;
		tmp = nullptr;
	}
	return tmp;
}


Status Process::createSharedSegment(VirtualAddress startAddress,
	PageNum segmentSize, const char* name, AccessType flags) {
	return pProcess->createSharedSegment(startAddress, segmentSize, name, flags);
}
Status Process::disconnectSharedSegment(const char* name) {
	return pProcess->disconnectSharedSegment(name);
}
Status Process::deleteSharedSegment(const char* name) {
	return pProcess->deleteSharedSegment(name);
}

void Process::blockIfThrashing() {
	pProcess->blockIfThrashing();
}
