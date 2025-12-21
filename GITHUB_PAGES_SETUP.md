# GitHub Pages Setup Guide

This guide will help you deploy the Bastion Firewall website to GitHub Pages.

## Files Created

The following files have been created for the GitHub Pages site:

- `index.html` - Main HTML page with modern, responsive design
- `styles.css` - Complete CSS styling with dark theme and animations
- `script.js` - JavaScript for interactivity and smooth scrolling

## Deployment Steps

### 1. Push the Files to GitHub

```bash
# Add the new files
git add index.html styles.css script.js

# Commit the changes
git commit -m "Add GitHub Pages site with modern design"

# Push to GitHub
git push origin master
```

### 2. Enable GitHub Pages

1. Go to your repository on GitHub: https://github.com/shipdocs/Bastion-Application-firewall-for-Linux
2. Click on **Settings** (top right)
3. Scroll down to **Pages** in the left sidebar
4. Under **Source**, select:
   - Branch: `master`
   - Folder: `/ (root)`
5. Click **Save**

### 3. Wait for Deployment

GitHub will automatically build and deploy your site. This usually takes 1-2 minutes.

### 4. Access Your Site

Your site will be available at:
```
https://shipdocs.github.io/Bastion-Application-firewall-for-Linux/
```

## Features of the Site

### Modern Design
- Dark theme with gradient accents
- Responsive layout for mobile and desktop
- Smooth animations and transitions
- Modern typography using Inter font

### Sections Included
1. **Hero Section** - Eye-catching introduction with call-to-action buttons
2. **Problem/Solution** - Clear explanation of what Bastion solves
3. **Features** - Grid of production-ready features
4. **Architecture** - Visual representation of the two-process design
5. **Installation** - Quick installation guides with code blocks
6. **Usage** - Step-by-step usage instructions
7. **Documentation** - Links to all documentation files
8. **Tested On** - Supported distributions
9. **CTA** - Call-to-action section
10. **Footer** - Links and additional information

### Interactive Features
- Smooth scrolling navigation
- Scroll-triggered animations
- Copy-to-clipboard for code blocks
- Responsive navigation
- Hover effects on cards

## Customization

### Update Repository Links
All GitHub links have been updated to point to:
```
https://github.com/shipdocs/Bastion-Application-firewall-for-Linux
```

### Add Screenshots (Optional)
To add screenshots:
1. Create a `screenshots` folder
2. Add your images
3. Update `index.html` to include them

Example:
```html
<section class="screenshots">
    <div class="container">
        <h2 class="section-title">Screenshots</h2>
        <div class="screenshot-grid">
            <img src="screenshots/popup.png" alt="Connection popup dialog">
            <img src="screenshots/control-panel.png" alt="Control panel">
        </div>
    </div>
</section>
```

### Change Colors
Edit `styles.css` and modify the CSS variables in `:root`:
```css
:root {
    --primary-color: #6366f1;  /* Change to your preferred color */
    --secondary-color: #8b5cf6;
    --accent-color: #ec4899;
}
```

## Testing Locally

To test the site locally before deploying:

```bash
# Using Python's built-in server
python3 -m http.server 8000

# Then open in browser:
# http://localhost:8000
```

## Troubleshooting

### Site Not Showing Up
- Wait 2-5 minutes after enabling GitHub Pages
- Check that the files are in the root directory
- Verify the branch is set to `master` in Settings > Pages

### Broken Links
- Ensure all documentation files exist in the repository
- Check that file names match exactly (case-sensitive)

### Styling Issues
- Clear browser cache
- Check browser console for errors
- Verify all CSS is in `styles.css`

## Maintenance

### Updating Content
1. Edit `index.html` for content changes
2. Edit `styles.css` for styling changes
3. Commit and push changes
4. GitHub Pages will automatically rebuild

### Adding New Sections
1. Add HTML in `index.html`
2. Add corresponding CSS in `styles.css`
3. Update navigation links if needed

## Support

For issues with the website:
- Check the browser console for errors
- Verify all files are committed and pushed
- Ensure GitHub Pages is enabled in repository settings

For issues with Bastion Firewall itself:
- Visit: https://github.com/shipdocs/Bastion-Application-firewall-for-Linux/issues

