#!/usr/bin/env bash
# Apply this fork's Java changes to a writable Ghidra 12.1.2 distribution.
set -euo pipefail
shopt -s globstar nullglob

if [[ $# != 1 ]]; then
    printf 'Usage: bash %s <writable-ghidra-12.1.2-directory>\n' "$0" >&2
    exit 2
fi
REPO=$(dirname "$(realpath "$0")")
DIST=$(realpath "$1")
if [[ ! -f "$DIST/Ghidra/application.properties" ]] ||
    ! grep -qx 'application.version=12.1.2' "$DIST/Ghidra/application.properties"; then
    printf 'Expected a Ghidra 12.1.2 distribution, not the source checkout.\n' >&2
    exit 2
fi
JAVAC=${JAVA_HOME:+$JAVA_HOME/bin/}javac
if ! command -v "$JAVAC" >/dev/null; then
    # Fall back to the pinned Nix JDK when javac is not on PATH.
    JAVAC=/nix/store/p3ckxs1gmqir4m2b6yknbbka33da1y4m-openjdk-21.0.12.1+1/bin/javac
fi
JARS=("$DIST"/**/*.jar)
CP=$(IFS=:; printf '%s' "${JARS[*]}")
BASE="$REPO/Ghidra/Features/Base"
MIPS="$REPO/Ghidra/Processors/MIPS"
PATCH="$DIST/Ghidra/patch"
mkdir -p "$PATCH"
"$JAVAC" -proc:none -cp "$CP" -d "$PATCH" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFAbbreviation.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFImportOptions.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunction.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunctionImporter.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunctionBodyFixupAnalyzer.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFVariable.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFRegisterMappings.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFRegisterMappingsManager.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/dwarf/expression/DWARFExpressionEvaluator.java" \
    "$BASE/src/main/java/ghidra/app/util/bin/format/ecoff/EcoffDebug.java" \
    "$BASE/src/main/java/ghidra/app/plugin/core/analysis/EcoffAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/util/bin/format/elf/extend/MIPS_ElfExtension.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsInlineDispatchAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsIndirectTailCallAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsGpAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsStubsAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsGotAnalyzer.java"
cp "$BASE/data/noReturnFunctionConstraints.xml" "$BASE/data/MipsFunctionsThatDoNotReturn" \
    "$DIST/Ghidra/Features/Base/data/"
cp "$MIPS/data/languages/mips.dwarf" "$DIST/Ghidra/Processors/MIPS/data/languages/"
cp "$MIPS/data/languages/mips64_32_n32.cspec" "$DIST/Ghidra/Processors/MIPS/data/languages/"
cp "$MIPS/data/languages/mips64_32_o32.cspec" "$DIST/Ghidra/Processors/MIPS/data/languages/"
printf 'IRIX patch compiled into %s\n' "$PATCH"
