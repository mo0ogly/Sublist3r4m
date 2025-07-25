#!/bin/bash
# Quick fix script for variable resolution issues

echo "🔧 QUICK FIX FOR VARIABLE RESOLUTION ISSUES"
echo "============================================"

# Set common variables that might be missing
export FILE=""
export file=""
export FILENAME=""
export filename=""

# Check if we're in the right directory
if [ ! -f "sublist3r.py" ]; then
    echo "❌ Not in Sublist3r directory. Changing to correct location..."
    cd /home/fpizzi/Sublist3r4m
fi

echo "✅ Current directory: $(pwd)"
echo "✅ Files available:"
ls -la *.py | head -5

# Common fixes for variable issues
echo ""
echo "🔧 Applying common fixes..."

# If you're trying to use a file variable, here are some examples:
echo "💡 Example usage patterns:"
echo "   For Python: python3 sublist3r_enhanced.py -d example.com"
echo "   For file input: python3 sublist3r_enhanced.py -d example.com -o results.txt"
echo "   For owner research: python3 owner_research_engine.py"

echo ""
echo "✅ Ready to run commands. What specific operation do you need?"