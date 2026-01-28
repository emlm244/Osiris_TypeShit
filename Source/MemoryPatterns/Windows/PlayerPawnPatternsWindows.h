#pragma once

#include <MemoryPatterns/PatternTypes/PlayerPawnPatternTypes.h>
#include <MemorySearch/CodePattern.h>

struct PlayerPawnPatterns {
    [[nodiscard]] static consteval auto addClientPatterns(auto clientPatterns) noexcept
    {
        return clientPatterns
            .template addPattern<OffsetToPlayerPawnImmunity, CodePattern{"0F B6 83 ? ? ? ? 84 C0 75 ? ? 80"}.add(3).read()>()
            .template addPattern<OffsetToWeaponServices, CodePattern{"48 8B 88 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48"}.add(3).read()>()
            .template addPattern<OffsetToPlayerController, CodePattern{"8B 8B ? ? ? ? 44 88 7C"}.add(2).read()>()
            .template addPattern<OffsetToIsDefusing, CodePattern{"75 ? 80 BF ? ? ? ? 00 75 ? 48 8B CF E8 ? ? ? ? 85 C0"}.add(4).read()>()
            .template addPattern<OffsetToIsPickingUpHostage, CodePattern{"86 ? ? ? ? ? ? ? ? 80 BF ? ? ? ?"}.add(11).read()>()
            .template addPattern<OffsetToHostageServices, CodePattern{"0F 87 ? ? ? ? 48 8B 87 ? ? ? ?"}.add(9).read()>()
            .template addPattern<OffsetToFlashBangEndTime, CodePattern{"10 87 ? ? ? ? 0F 2F ? ? 0F 86"}.add(2).read()>()
            .template addPattern<OffsetToPlayerPawnSceneObjectUpdaterHandle, CodePattern{"48 89 83 ? ? ? ? 48 8B 8B ? ? ? ? ? ? ? FF 50 ? 48 85 DB 48 8D 93 ? ? ? ? 48 8B C8 48 0F 44 D6 E8 ? ? ? ? 48 8B 8B ? ? ? ? ? ? ? FF 50 ? 48 85 DB 48 8D 93 ? ? ? ? 48 8B C8 48 0F 44 D6 E8 ? ? ? ? 48 8B 8B ? ? ? ? ? ? ? FF 50 ? 48 85 DB 48 8D 93 ? ? ? ? 48 8B C8 48 0F 44 D6 E8 ? ? ? ? 48 8B CB 48 8B 5C 24"}.add(3).read()>()
            .template addPattern<OffsetToIsScoped, CodePattern{"88 B0 ? ? ? ? 0F 57 DB"}.add(2).read()>();
    }
};
