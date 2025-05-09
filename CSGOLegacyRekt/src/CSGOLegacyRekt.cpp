// CSGOLegacyRekt.cpp
#include <locale.h>
#include "CSGOLegacyRekt.h"
#include <ISmmAPI.h>

CSGOLegacyRekt g_CSGOLegacyRekt;
PLUGIN_EXPOSE(CSGOLegacyRekt, g_CSGOLegacyRekt);
IServerGameDLL* server = nullptr;

bool CSGOLegacyRekt::Load(PluginId id, ISmmAPI* ismm, char* error, size_t maxlen, bool late) {
	PLUGIN_SAVEVARS();
	GET_V_IFACE_ANY(GetServerFactory, server, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
	
	SetConsoleOutputCP(65001);
	SetConsoleCP(65001);
	setlocale(LC_ALL, ".UTF-8");

	ApplyEnginePatches();
	return true;
}

bool CSGOLegacyRekt::Unload(char* error, size_t maxlen) {
	RestorePatches();
	return true;
}

uintptr_t CSGOLegacyRekt::FindPattern(HMODULE module, const char* pattern, const char* mask) {
	if (!module) return 0;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)module + dosHeader->e_lfanew);
	size_t size = ntHeaders->OptionalHeader.SizeOfImage;
	
	uintptr_t base = (uintptr_t)module;
	for (uintptr_t i = 0; i < size - strlen(mask); ++i) {
		bool found = true;
		for (size_t j = 0; j < strlen(mask); ++j) {
			if (mask[j] == 'x' && *(BYTE*)(base + i + j) != (BYTE)pattern[j]) {
				found = false;
				break;
			}
		}
		if (found) return base + i;
	}
	return 0;
}

void CSGOLegacyRekt::ApplyEnginePatches() {
	HMODULE hEngine = GetModuleHandleA("engine.dll");
	if (!hEngine) {
		printf("[engine.dll] Module not found!\n");
		return;
	}

	struct {
		const char* name;
		const char* signature;
		const char* mask;
		std::vector<std::pair<size_t, std::vector<uint8_t>>> patches;
	} targets[] = {
		{
			"CBaseServer::IsExclusiveToLobbyConnections",
			"\x8B\x01\x8B\x40\x00\xFF\xD0\x84\xC0\x75\x00\xC3\xA1",
			"xxxx?xxxxx?xx",
			{
				{7,		{0x30, 0xC0}},	// XOR AL, AL
			}
		},
		{
			"CSteam3Server::OnValidateAuthTicketResponse",
			"\x55\x8B\xEC\x83\xE4\x00\x81\xEC\x00\x00\x00\x00\x53\x56\x8B\xF1\x57\x83\x7E",
			"xxxxx?xx????xxxxxxx",
			{
				{141,	{0xEB}},		// JMP
			}
		},
		{
			"CBaseServer::ReplyChallenge",
			"\x55\x8B\xEC\x83\xE4\x00\x81\xEC\x00\x00\x00\x00\x53\x8B\x5D\x00\x56\x57\x53",
			"xxxxx?xx????xxx?xxx",
			{
				{994,	{0x30, 0xC0}},	// XOR AL, AL
				{1507,	{0x30, 0xC0}},	// XOR AL, AL
				{1613,	{0x00}},		// NOP
				{1627,	{0x00}},		// NOP
			}
		}
	};

	for (auto& target : targets) {
		uintptr_t address = FindPattern(hEngine, target.signature, target.mask);
		printf("[engine.dll] %s: %s (0x%08X)\n", 
			  target.name, 
			  address ? "Found" : "Not found", 
			  address);

		if (!address) continue;

		for (auto& [offset, patch] : target.patches) {
			MemoryPatch mp;
			mp.address = address + offset;
			mp.patch = patch;

			DWORD oldProtect;
			if (VirtualProtect((LPVOID)mp.address, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
				mp.original.resize(patch.size());
				memcpy(mp.original.data(), (void*)mp.address, patch.size());
				memcpy((void*)mp.address, patch.data(), patch.size());
				VirtualProtect((LPVOID)mp.address, patch.size(), oldProtect, &oldProtect);
				m_patches.push_back(mp);
				printf("|-- 0x%08X: %zu bytes patched\n", mp.address, patch.size());
			} else {
				printf("|-- 0x%08X: Patch failed!\n", mp.address);
			}
		}
	}
}

void CSGOLegacyRekt::RestorePatches() {
	for (auto& mp : m_patches) {
		DWORD oldProtect;
		if (VirtualProtect((LPVOID)mp.address, mp.original.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			memcpy((void*)mp.address, mp.original.data(), mp.original.size());
			VirtualProtect((LPVOID)mp.address, mp.original.size(), oldProtect, &oldProtect);
			printf("[Restore] 0x%08X (%zu bytes)\n", mp.address, mp.original.size());
		}
	}
	m_patches.clear();
}