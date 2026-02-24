/**
 * Privacy Settings Analyzer Utility
 * Simulates analysis of social media profiles for privacy leaks.
 */

function analyzePrivacy(url) {
    const result = {
        categories: [
            {
                id: 'visibility',
                title: 'Profile Visibility',
                icon: '⚠️',
                status: 'warning',
                issues: ['Profile is public', 'Location sharing enabled'],
                recommendations: ['Set profile to private', 'Disable location sharing']
            },
            {
                id: 'contact',
                title: 'Contact Information',
                icon: '✓',
                status: 'safe',
                issues: [],
                recommendations: ['Keep current settings']
            },
            {
                id: 'tracking',
                title: 'Activity Tracking',
                icon: '⚠️',
                status: 'warning',
                issues: ['Activity status visible', 'Online status shown'],
                recommendations: ['Hide activity status', 'Disable online indicators']
            }
        ]
    };

    // Simple simulation based on URL
    if (url.includes('facebook') || url.includes('fb.com')) {
        result.categories[0].issues = ['Friends list is public', 'Posts are visible to everyone'];
        result.categories[0].recommendations = ['Change post privacy to Friends', 'Hide friends list'];
    } else if (url.includes('github')) {
        result.categories[0].issues = ['Email address is public', 'Organization membership is visible'];
        result.categories[0].recommendations = ['Hide your email in settings', 'Keep organization memberships private'];
    }

    return result;
}

module.exports = { analyzePrivacy };
