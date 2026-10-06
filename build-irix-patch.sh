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
    "$BASE/src/main/java/ghidra/app/util/bin/format/ecoff/EcoffDebug.java" \
    "$BASE/src/main/java/ghidra/app/plugin/core/analysis/EcoffAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/util/bin/format/elf/extend/MIPS_ElfExtension.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsInlineDispatchAnalyzer.java" \
    "$MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsIndirectTailCallAnalyzer.java"
cp "$BASE/data/noReturnFunctionConstraints.xml" "$BASE/data/MipsFunctionsThatDoNotReturn" \
    "$DIST/Ghidra/Features/Base/data/"
printf 'IRIX patch compiled into %s\n' "$PATCH"
