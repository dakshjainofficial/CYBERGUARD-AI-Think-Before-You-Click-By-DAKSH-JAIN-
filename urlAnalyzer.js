/**
 * URL Analyzer Utility
 * Detects phishing, malicious patterns, and suspicious link characteristics.
 */

function analyzeURL(url) {
    const result = {
        riskLevel: 'safe',
        riskPercentage: 0,
        explanation: 'This URL appears to be safe based on our current analysis.',
        indicators: [],
        recommendation: 'You can proceed, but always remain cautious when entering sensitive information.'
    };

    if (!url) return result;

    const indicators = [];
    let score = 0;

    // 1. Check for IP-based links
    const ipRegex = /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}/i;
    if (ipRegex.test(url)) {
        score += 40;
        indicators.push('Uses an IP address instead of a domain name (common in phishing)');
    }

    // 2. Check for suspicious keywords
    const suspiciousKeywords = [
        'login', 'verify', 'account', 'secure', 'update', 'banking', 'paypal',
        'wallet', 'signin', 'confirm', 'urgent', 'suspend', 'disabled', 'bonus',
        'free', 'reward', 'gift', 'prize', 'claim', 'winner'
    ];

    const foundKeywords = suspiciousKeywords.filter(keyword =>
        url.toLowerCase().includes(keyword)
    );

    if (foundKeywords.length > 0) {
        score += foundKeywords.length * 15;
        indicators.push(`Contains suspicious keywords: ${foundKeywords.join(', ')}`);
    }

    // 3. Check for long URLs
    if (url.length > 75) {
        score += 15;
        indicators.push('Unusually long URL (often used to hide the actual domain)');
    }

    // 4. Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.zip', '.mov'];
    const urlLower = url.toLowerCase();
    if (suspiciousTLDs.some(tld => urlLower.endsWith(tld) || urlLower.includes(tld + '/'))) {
        score += 25;
        indicators.push('Uses a top-level domain frequently associated with malicious activity');
    }

    // 5. Check for brand impersonation (lookalike domains)
    const impersonationAttempts = [
        { brand: 'paypal', fake: 'paypa1' },
        { brand: 'google', fake: 'g00gle' },
        { brand: 'microsoft', fake: 'micosoft' },
        { brand: 'apple', fake: 'app1e' },
        { brand: 'facebook', fake: 'faceb00k' },
        { brand: 'amazon', fake: 'amaz0n' }
    ];

    impersonationAttempts.forEach(item => {
        if (urlLower.includes(item.fake) && !urlLower.includes(item.brand)) {
            score += 50;
            indicators.push(`Possible impersonation of ${item.brand} (found "${item.fake}")`);
        }
    });

    // 6. Check for excessive subdomains or hyphens
    const domainPart = url.split('/')[2] || '';
    const subdomains = domainPart.split('.').length - 2;
    if (subdomains > 3) {
        score += 20;
        indicators.push('Excessive number of subdomains detected');
    }

    if ((domainPart.match(/-/g) || []).length > 3) {
        score += 15;
        indicators.push('Large number of hyphens in domain name');
    }

    // 7. Check for missing HTTPS
    if (url.startsWith('http://')) {
        score += 10;
        indicators.push('Uses unencrypted HTTP instead of HTTPS');
    }

    // Final scoring and risk level determination
    result.riskPercentage = Math.min(100, score);
    result.indicators = indicators;

    if (score >= 80) {
        result.riskLevel = 'critical';
        result.explanation = 'This URL shows multiple high-risk indicators common in severe phishing or malware attacks.';
        result.recommendation = '⚠️ DO NOT CLICK! This link is extremely dangerous. Close the page immediately.';
    } else if (score >= 50) {
        result.riskLevel = 'high';
        result.explanation = 'This URL is highly suspicious and matches known phishing patterns.';
        result.recommendation = 'Avoid clicking this link. If you must, verify the source through official channels first.';
    } else if (score >= 30) {
        result.riskLevel = 'medium';
        result.explanation = 'Several suspicious elements were detected that are often found in deceptive links.';
        result.recommendation = 'Be cautious. Check if you were expecting this link and if the sender is trustworthy.';
    } else if (score >= 15) {
        result.riskLevel = 'low';
        result.explanation = 'A few minor red flags were detected, though the link might be legitimate.';
        result.recommendation = 'Use caution and double-check the website once it loads.';
    } else {
        result.riskLevel = 'safe';
        result.explanation = 'No significant threat indicators were found for this URL.';
        result.recommendation = 'This link appears safe, but always practice good cybersecurity hygiene.';
    }

    return result;
}

module.exports = { analyzeURL };
