#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

class ElfTextSection {
public:
    static ElfTextSection fromFile(std::string_view path)
    {
        ElfTextSection result;

        if (std::endian::native != std::endian::little) {
            result.error_ = "Unsupported host endianness (expected little-endian)";
            return result;
        }

        result.path_ = std::string{path};
        if (!readFile(result.path_, result.data_, result.error_))
            return result;

        if (!result.parseElf())
            return result;

        return result;
    }

    [[nodiscard]] bool ok() const noexcept
    {
        return error_.empty() && !text_.empty();
    }

    [[nodiscard]] std::span<const std::byte> text() const noexcept
    {
        return text_;
    }

    [[nodiscard]] std::size_t textFileOffset() const noexcept
    {
        return textFileOffset_;
    }

    [[nodiscard]] const std::string& error() const noexcept
    {
        return error_;
    }

    [[nodiscard]] std::optional<std::size_t> findSymbolFileOffset(std::string_view symbolName) const noexcept
    {
        if (!ok())
            return std::nullopt;

        const auto symSectionIndex = findSectionByName(".dynsym").value_or(findSectionByName(".symtab").value_or(kInvalidIndex));
        if (symSectionIndex == kInvalidIndex)
            return std::nullopt;

        const auto& symSection = sections_[symSectionIndex].header;
        if (symSection.sh_entsize < sizeof(Elf64_Sym))
            return std::nullopt;

        if (symSection.sh_link >= sections_.size())
            return std::nullopt;

        const auto& strSection = sections_[symSection.sh_link].header;
        if (!rangeWithinFile(strSection.sh_offset, strSection.sh_size))
            return std::nullopt;

        const auto* strTab = reinterpret_cast<const char*>(data_.data() + strSection.sh_offset);
        const std::size_t strTabSize = static_cast<std::size_t>(strSection.sh_size);

        const std::size_t symCount = static_cast<std::size_t>(symSection.sh_size / symSection.sh_entsize);
        for (std::size_t i = 0; i < symCount; ++i) {
            Elf64_Sym sym{};
            if (!readStruct(symSection.sh_offset + i * symSection.sh_entsize, sym))
                return std::nullopt;

            if (sym.st_name >= strTabSize)
                continue;

            const auto* name = strTab + sym.st_name;
            if (*name == '\0')
                continue;

            if (symbolName != name)
                continue;

            if (sym.st_shndx == 0)
                continue;

            const auto fileOffset = fileOffsetFromVirtualAddress(sym.st_value);
            if (!fileOffset)
                return std::nullopt;

            return fileOffset;
        }

        return std::nullopt;
    }

    [[nodiscard]] std::optional<const std::byte*> textPointerFromFileOffset(std::size_t fileOffset) const noexcept
    {
        if (fileOffset < textFileOffset_ || fileOffset >= textFileOffset_ + text_.size())
            return std::nullopt;

        const auto offsetInText = fileOffset - textFileOffset_;
        return text_.data() + offsetInText;
    }

private:
    struct Elf64_Ehdr {
        unsigned char e_ident[16];
        std::uint16_t e_type;
        std::uint16_t e_machine;
        std::uint32_t e_version;
        std::uint64_t e_entry;
        std::uint64_t e_phoff;
        std::uint64_t e_shoff;
        std::uint32_t e_flags;
        std::uint16_t e_ehsize;
        std::uint16_t e_phentsize;
        std::uint16_t e_phnum;
        std::uint16_t e_shentsize;
        std::uint16_t e_shnum;
        std::uint16_t e_shstrndx;
    };

    struct Elf64_Shdr {
        std::uint32_t sh_name;
        std::uint32_t sh_type;
        std::uint64_t sh_flags;
        std::uint64_t sh_addr;
        std::uint64_t sh_offset;
        std::uint64_t sh_size;
        std::uint32_t sh_link;
        std::uint32_t sh_info;
        std::uint64_t sh_addralign;
        std::uint64_t sh_entsize;
    };

    struct Elf64_Sym {
        std::uint32_t st_name;
        unsigned char st_info;
        unsigned char st_other;
        std::uint16_t st_shndx;
        std::uint64_t st_value;
        std::uint64_t st_size;
    };

    struct SectionInfo {
        std::string_view name;
        Elf64_Shdr header{};
    };

    static constexpr unsigned char kElfMagic[4]{0x7f, 'E', 'L', 'F'};
    static constexpr std::size_t kInvalidIndex = static_cast<std::size_t>(-1);
    static constexpr unsigned char kElfClass64 = 2;
    static constexpr unsigned char kElfData2Lsb = 1;
    static constexpr std::size_t kEiClass = 4;
    static constexpr std::size_t kEiData = 5;

    [[nodiscard]] static bool readFile(const std::string& path, std::vector<std::byte>& out, std::string& error)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            error = "Failed to open file";
            return false;
        }

        const auto size = file.tellg();
        if (size <= 0) {
            error = "File is empty";
            return false;
        }

        out.resize(static_cast<std::size_t>(size));
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        if (!file) {
            error = "Failed to read file";
            return false;
        }

        return true;
    }

    [[nodiscard]] bool parseElf() noexcept
    {
        if (data_.size() < sizeof(Elf64_Ehdr)) {
            error_ = "File too small for ELF header";
            return false;
        }

        Elf64_Ehdr header{};
        if (!readStruct(0, header)) {
            error_ = "Failed to read ELF header";
            return false;
        }

        if (std::memcmp(header.e_ident, kElfMagic, sizeof(kElfMagic)) != 0) {
            error_ = "Invalid ELF magic";
            return false;
        }

        if (header.e_ident[kEiClass] != kElfClass64) {
            error_ = "Unsupported ELF class (expected 64-bit)";
            return false;
        }

        if (header.e_ident[kEiData] != kElfData2Lsb) {
            error_ = "Unsupported ELF endianness (expected little-endian)";
            return false;
        }

        if (header.e_shoff == 0 || header.e_shnum == 0) {
            error_ = "Missing section headers";
            return false;
        }

        if (header.e_shentsize < sizeof(Elf64_Shdr)) {
            error_ = "Unsupported section header entry size";
            return false;
        }

        const auto sectionTableSize = static_cast<std::size_t>(header.e_shentsize) * header.e_shnum;
        if (!rangeWithinFile(header.e_shoff, sectionTableSize)) {
            error_ = "Section headers out of file bounds";
            return false;
        }

        if (header.e_shstrndx >= header.e_shnum) {
            error_ = "Invalid section name table index";
            return false;
        }

        Elf64_Shdr shstrHeader{};
        if (!readSectionHeader(header, header.e_shstrndx, shstrHeader)) {
            error_ = "Failed to read section name table header";
            return false;
        }

        if (!rangeWithinFile(shstrHeader.sh_offset, shstrHeader.sh_size)) {
            error_ = "Section name table out of file bounds";
            return false;
        }

        const auto* shStrTab = reinterpret_cast<const char*>(data_.data() + shstrHeader.sh_offset);
        const auto shStrTabSize = static_cast<std::size_t>(shstrHeader.sh_size);

        sections_.clear();
        sections_.reserve(header.e_shnum);

        for (std::size_t i = 0; i < header.e_shnum; ++i) {
            Elf64_Shdr shdr{};
            if (!readSectionHeader(header, i, shdr)) {
                error_ = "Failed to read section header";
                return false;
            }

            std::string_view name;
            if (shdr.sh_name < shStrTabSize)
                name = std::string_view{shStrTab + shdr.sh_name};

            sections_.push_back(SectionInfo{name, shdr});
        }

        const auto textIndex = findSectionByName(".text");
        if (!textIndex || *textIndex >= sections_.size()) {
            error_ = "Missing .text section";
            return false;
        }

        const auto& textHeader = sections_[*textIndex].header;
        if (!rangeWithinFile(textHeader.sh_offset, textHeader.sh_size)) {
            error_ = ".text section out of file bounds";
            return false;
        }

        textFileOffset_ = static_cast<std::size_t>(textHeader.sh_offset);
        text_ = std::span<const std::byte>{data_.data() + textFileOffset_, static_cast<std::size_t>(textHeader.sh_size)};
        return true;
    }

    [[nodiscard]] bool rangeWithinFile(std::uint64_t offset, std::uint64_t size) const noexcept
    {
        return offset <= data_.size() && size <= data_.size() - offset;
    }

    [[nodiscard]] bool readSectionHeader(const Elf64_Ehdr& header, std::size_t index, Elf64_Shdr& out) const noexcept
    {
        const auto offset = static_cast<std::size_t>(header.e_shoff) + index * header.e_shentsize;
        return readStruct(offset, out);
    }

    template <typename T>
    [[nodiscard]] bool readStruct(std::size_t offset, T& out) const noexcept
    {
        if (offset + sizeof(T) > data_.size())
            return false;
        std::memcpy(&out, data_.data() + offset, sizeof(T));
        return true;
    }

    [[nodiscard]] std::optional<std::size_t> findSectionByName(std::string_view name) const noexcept
    {
        for (std::size_t i = 0; i < sections_.size(); ++i) {
            if (sections_[i].name == name)
                return i;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::size_t> fileOffsetFromVirtualAddress(std::uint64_t address) const noexcept
    {
        for (const auto& section : sections_) {
            const auto& header = section.header;
            if (address >= header.sh_addr && address < header.sh_addr + header.sh_size) {
                const auto offset = header.sh_offset + (address - header.sh_addr);
                if (rangeWithinFile(offset, 1))
                    return static_cast<std::size_t>(offset);
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::string path_;
    std::vector<std::byte> data_;
    std::vector<SectionInfo> sections_;
    std::span<const std::byte> text_{};
    std::size_t textFileOffset_{0};
    std::string error_;
};
