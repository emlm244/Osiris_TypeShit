#pragma once

#include <MemoryPatterns/PatternTypes/SceneObjectPatternTypes.h>
#include <MemorySearch/CodePattern.h>

struct SceneObjectPatterns {
    [[nodiscard]] static consteval auto addSceneSystemPatterns(auto sceneSystemPatterns) noexcept
    {
        return sceneSystemPatterns
            .template addPattern<OffsetToSceneObjectFlags, CodePattern{"50 C0 ? ? 0F 85 ? ? ? ? 48 8B 93 88"}.add(2).read()>()
            .template addPattern<OffsetToSceneObjectClass, CodePattern{"B6 48 ? 48 05"}.add(2).read()>()
            .template addPattern<OffsetToSceneObjectAttributes, CodePattern{"89 9C 24 ? ? ? ? 48 83"}.add(3).read()>()
            .template addPattern<OffsetToSceneObjectRenderableFlags, CodePattern{"10 48 89 93 ? ? ? ?"}.add(4).read()>();
    }
};
