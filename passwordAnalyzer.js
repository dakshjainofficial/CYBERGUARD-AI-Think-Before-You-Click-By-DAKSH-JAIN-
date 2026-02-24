/**
 * Password Analyzer Utility
 * Evaluates password strength and simulates various attack scenarios.
 */

function analyzePassword(password) {
    if (!password) return null;

    const result = {
        score: 0,
        strength: 'very weak',
        crackTime: 'Instant',
        attacks: {
            bruteForce: {
                attemptsPerSecond: '10 Billion',
                combinations: '0',
                timeEstimate: 'Instant'
            },
            dictionary: {
                vulnerable: false,
                timeEstimate: '0.01 seconds'
            },
            gpuCrack: {
                gpuCluster: '8x RTX 4090',
                attemptsPerSecond: '800 Billion',
                timeEstimate: 'Instant'
            }
        },
        warnings: [],
        suggestions: []
    };

    let score = 0;
    const warnings = [];
    const suggestions = [];

    // 1. Length analysis
    if (password.length < 8) {
        warnings.push('Password is too short (minimum 8 characters recommended)');
        score += password.length * 2;
    } else if (password.length >= 12) {
        score += 40;
    } else {
        score += 25;
    }

    // 2. Character variety
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);

    let varietyCount = 0;
    if (hasUpper) { varietyCount++; score += 15; } else { suggestions.push('Add uppercase letters'); }
    if (hasLower) { varietyCount++; score += 10; }
    if (hasNumber) { varietyCount++; score += 15; } else { suggestions.push('Add numbers'); }
    if (hasSpecial) { varietyCount++; score += 20; } else { suggestions.push('Add special characters (@, #, $, etc.)'); }

    // 3. Common patterns
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome', '12345678', 'password123'];
    if (commonPasswords.includes(password.toLowerCase())) {
        score = 5;
        warnings.push('This is a very common password and extremely easy to guess');
        result.attacks.dictionary.vulnerable = true;
        result.attacks.dictionary.timeEstimate = 'Instant';
    }

    // Calculate combinations for brute force
    let charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasNumber) charsetSize += 10;
    if (hasSpecial) charsetSize += 32;

    const combinations = Math.pow(charsetSize, password.length);
    result.attacks.bruteForce.combinations = combinations.toExponential(2);

    // Time estimates
    const bruteForceSpeed = 1e10; // 10 billion/sec
    const gpuSpeed = 8e11; // 800 billion/sec

    const bruteForceSeconds = combinations / bruteForceSpeed;
    const gpuSeconds = combinations / gpuSpeed;

    function formatTime(seconds) {
        if (seconds < 1) return 'Instant';
        if (seconds < 60) return Math.floor(seconds) + ' seconds';
        if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes';
        if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours';
        if (seconds < 31536000) return Math.floor(seconds / 86400) + ' days';
        if (seconds < 3153600000) return Math.floor(seconds / 31536000) + ' years';
        return 'Centuries';
    }

    result.crackTime = formatTime(bruteForceSeconds);
    result.attacks.bruteForce.timeEstimate = formatTime(bruteForceSeconds);
    result.attacks.gpuCrack.timeEstimate = formatTime(gpuSeconds);

    // Final strength determination
    result.score = Math.min(100, score);
    if (result.score >= 90) result.strength = 'very strong';
    else if (result.score >= 70) result.strength = 'strong';
    else if (result.score >= 50) result.strength = 'moderate';
    else if (result.score >= 30) result.strength = 'weak';
    else result.strength = 'very weak';

    result.warnings = warnings;
    result.suggestions = suggestions;

    if (result.score < 50) {
        suggestions.push('Make your password at least 12 characters long');
    }

    return result;
}

module.exports = { analyzePassword };
