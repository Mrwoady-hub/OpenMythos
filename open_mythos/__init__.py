from open_mythos.mind_home import (
    LearnedSource,
    MindHome,
    MindState,
    experience_for_level,
    level_from_experience,
)
from open_mythos.personal_ai import (
    BootstrapMindGenerator,
    JsonMemoryStore,
    Memory,
    OllamaGenerator,
    OpenMythosTextGenerator,
    PersonalAI,
    PersonalAIProfile,
    PersonalAIResponse,
    TextGenerator,
)

__all__ = [
    "Memory",
    "JsonMemoryStore",
    "BootstrapMindGenerator",
    "OllamaGenerator",
    "PersonalAIProfile",
    "PersonalAIResponse",
    "PersonalAI",
    "TextGenerator",
    "OpenMythosTextGenerator",
    "LearnedSource",
    "MindHome",
    "MindState",
    "experience_for_level",
    "level_from_experience",
]

try:
    from open_mythos.tokenizer import MythosTokenizer
except ModuleNotFoundError as exc:
    if exc.name != "transformers":
        raise
else:
    __all__.append("MythosTokenizer")

try:
    from open_mythos.main import (
        ACTHalting,
        Expert,
        GQAttention,
        LoRAAdapter,
        LTIInjection,
        MLAttention,
        MoEFFN,
        MythosConfig,
        OpenMythos,
        RecurrentBlock,
        RMSNorm,
        TransformerBlock,
        apply_rope,
        loop_index_embedding,
        precompute_rope_freqs,
    )
    from open_mythos.variants import (
        mythos_1b,
        mythos_1t,
        mythos_3b,
        mythos_10b,
        mythos_50b,
        mythos_100b,
        mythos_500b,
    )
except ModuleNotFoundError as exc:
    if exc.name != "torch":
        raise
else:
    __all__.extend(
        [
            "MythosConfig",
            "RMSNorm",
            "GQAttention",
            "MLAttention",
            "Expert",
            "MoEFFN",
            "LoRAAdapter",
            "TransformerBlock",
            "LTIInjection",
            "ACTHalting",
            "RecurrentBlock",
            "OpenMythos",
            "precompute_rope_freqs",
            "apply_rope",
            "loop_index_embedding",
            "mythos_1b",
            "mythos_3b",
            "mythos_10b",
            "mythos_50b",
            "mythos_100b",
            "mythos_500b",
            "mythos_1t",
        ]
    )
