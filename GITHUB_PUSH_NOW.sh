#!/bin/bash

echo "🚀 GitHub Push Script"
echo "===================="
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI not found. Installing..."
    brew install gh
fi

echo "📝 Step 1: Login to GitHub CLI with raghavx03 account"
echo ""
echo "Run this command:"
echo "  gh auth login"
echo ""
echo "Then select:"
echo "  - GitHub.com"
echo "  - HTTPS"
echo "  - Yes (authenticate Git)"
echo "  - Paste your token when asked"
echo ""
read -p "Press Enter after you've logged in..."

echo ""
echo "📤 Step 2: Pushing to GitHub..."
git remote set-url origin https://github.com/raghavx03/api-key.git
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully pushed to GitHub!"
    echo "🔗 View your repo: https://github.com/raghavx03/api-key"
else
    echo ""
    echo "❌ Push failed. Try manual push:"
    echo "   git push -u origin main"
fi
