// CSGOLegacyRekt.h
#pragma once
#include <ISmmPlugin.h>
#include <Windows.h>
#include <vector>

class CSGOLegacyRekt : public ISmmPlugin {
public:
	bool Load(PluginId id, ISmmAPI* ismm, char* error, size_t maxlen, bool late) override;
	bool Unload(char* error, size_t maxlen) override;

	const char* GetAuthor() override { return "Ambr0se"; }
	const char* GetName() override { return "CSGOLegacyRekt"; }
	const char* GetDescription() override { return "CSGOLegacyRekt"; }
	const char* GetURL() override { return "https://github.com/ELDment"; }
	const char* GetLicense() override { return ""; }
	const char* GetVersion() override { return "Internal"; }
	const char* GetDate() override { return __DATE__; }
	const char* GetLogTag() override { return "CSGOLegacyRekt"; }

private:
	struct MemoryPatch {
		uintptr_t address;
		std::vector<uint8_t> original;
		std::vector<uint8_t> patch;
	};

	std::vector<MemoryPatch> m_patches;

	void ApplyEnginePatches();
	void RestorePatches();
	uintptr_t FindPattern(HMODULE module, const char* pattern, const char* mask);
};

extern CSGOLegacyRekt g_CSGOLegacyRekt;