# GitHub Setup Instructions

## After creating your GitHub repository, run these commands:

```bash
# Add the remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/Network-Monitoring-Tool.git

# Rename branch to main if needed (if you're on master)
git branch -M main

# Push to GitHub
git push -u origin main
```

## Alternative: If you already have a remote, update it:

```bash
# Check current remote
git remote -v

# Update remote URL if needed
git remote set-url origin https://github.com/YOUR_USERNAME/Network-Monitoring-Tool.git

# Push to GitHub
git push -u origin main
```

## Quick One-Liner (after creating repo on GitHub):

Replace `YOUR_USERNAME` with your actual GitHub username:

```bash
git remote add origin https://github.com/YOUR_USERNAME/Network-Monitoring-Tool.git && git branch -M main && git push -u origin main
```

