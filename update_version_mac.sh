#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <file> <old_version> <new_version>"
    exit 1
fi

# Parameters
file=$1
old_version=$2
new_version=$3

# Check if the file exists
if [ ! -f "$file" ]; then
    echo "File $file not found!"
    exit 1
fi

# Escape special characters in old and new versions
escaped_old_version=$(printf '%s\n' "$old_version" | sed -e 's/[\/&]/\\&/g')
escaped_new_version=$(printf '%s\n' "$new_version" | sed -e 's/[\/&]/\\&/g')

# Replace the old version with the new version (macOS version)
sed -i '' "s/$escaped_old_version/$escaped_new_version/g" "$file"

echo "Version '$old_version' replaced with '$new_version' in file $file."
