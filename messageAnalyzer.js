/**
 * Message Analyzer Utility
 * Detects phishing, social engineering, and scam attempts in text messages.
 */

function analyzeMessage(message, simpleMode = false) {
    const result = {
        riskLevel: 'safe',
        scamProbability: '0%',
        explanation: 'This message shows no obvious signs of being a scam.',
        highlightedWords: [],
        indicators: [],
        recommendation: 'This message appears safe to engage with.'
    };

    if (!message) return result;

    const indicators = [];
    const highlightedWords = [];
    let score = 0;

    // 1. Urgency & Threats
    const urgencyKeywords = ['urgent', 'immediately', 'now', 'hurry', 'limited time', 'expires', 'last chance', 'suspended', 'blocked', 'closed', 'action required'];
    const foundUrgency = urgencyKeywords.filter(word => message.toLowerCase().includes(word));
    if (foundUrgency.length > 0) {
        score += foundUrgency.length * 15;
        foundUrgency.forEach(word => highlightedWords.push(word));
        indicators.push('Creates a false sense of urgency or fear to make you act without thinking');
    }

    // 2. Financial & Rewards
    const financialKeywords = ['lottery', 'winner', 'won', 'prize', 'reward', 'cash', 'dollars', 'bitcoin', 'crypto', 'bank', 'account', 'invoice', 'payment', 'refund', 'tax', 'irs', 'gift card'];
    const foundFinancial = financialKeywords.filter(word => message.toLowerCase().includes(word));
    if (foundFinancial.length > 0) {
        score += foundFinancial.length * 15;
        foundFinancial.forEach(word => highlightedWords.push(word));
        indicators.push('Offers suspicious rewards or mentions financial accounts to grab your attention');
    }

    // 3. Security & Verification
    const securityKeywords = ['verify', 'confirm', 'otp', 'password', 'login', 'security', 'identity', 'verification', 'unauthorized', 'suspicious activity'];
    const foundSecurity = securityKeywords.filter(word => message.toLowerCase().includes(word));
    if (foundSecurity.length > 0) {
        score += foundSecurity.length * 20;
        foundSecurity.forEach(word => highlightedWords.push(word));
        indicators.push('Asks for sensitive security information or verification codes');
    }

    // 4. Grammar & Style (Simple check)
    const suspiciousPatterns = [
        /\b(sir|madam|dear customer|winner)\b/i, // Generic greetings
        /\b(kindly|please do the needful|congratulations)\b/i, // Common scam phrasing
        /[A-Z]{3,}/, // Excessive caps
        /!!+/ // Excessive punctuation
    ];

    if (suspiciousPatterns[0].test(message)) {
        score += 10;
        indicators.push('Uses a generic greeting instead of your name');
    }
    if (suspiciousPatterns[1].test(message)) {
        score += 15;
        indicators.push('Uses language commonly used in international scams');
    }
    if (suspiciousPatterns[2].test(message)) {
        score += 10;
        indicators.push('Uses excessive capitalization to create panic');
    }

    // 5. Look for links or phone numbers
    if (message.includes('http') || message.includes('bit.ly') || message.includes('t.co')) {
        score += 20;
        indicators.push('Contains a link that might lead to a phishing website');
    }

    // Final scoring
    result.scamProbability = Math.min(100, score) + '%';
    result.highlightedWords = [...new Set(highlightedWords)];
    result.indicators = indicators;

    if (score >= 80) {
        result.riskLevel = 'critical';
        result.explanation = simpleMode
            ? 'This is 100% a TRAP! Someone is trying to trick you into giving them your secrets. They are using scary words to make you panic.'
            : 'This message exhibits multiple high-confidence characteristic patterns of a phishing scam. It uses urgency and authority to manipulate the recipient.';
        result.recommendation = 'DO NOT reply. DO NOT click any links. Block the sender and delete the message.';
    } else if (score >= 50) {
        result.riskLevel = 'high';
        result.explanation = simpleMode
            ? 'This looks very fishy! It talks about money or accounts in a way that feels like a trick.'
            : 'This message has a high probability of being a scam. The combination of keywords and tactics is very suspicious.';
        result.recommendation = 'Be extremely careful. Do not provide any information. If it claims to be from a company, contact them using their official website instead.';
    } else if (score >= 30) {
        result.riskLevel = 'medium';
        result.explanation = simpleMode
            ? 'Be careful! Some parts of this message are a bit strange and might be trying to trick you.'
            : 'This message contains some red flags. It might be legitimate, but it uses tactics often seen in marketing or low-level scams.';
        result.recommendation = 'Verify the sender\'s identity. If you didn\'t expect this message, treat it as suspicious.';
    } else if (score >= 10) {
        result.riskLevel = 'low';
        result.explanation = simpleMode
            ? 'This message is probably okay, but it\'s always good to stay alert!'
            : 'Only minor suspicious elements were detected. It could be a generic marketing message.';
        result.recommendation = 'Use normal caution. If anything feels "off", don\'t click on links.';
    } else {
        result.riskLevel = 'safe';
        result.explanation = simpleMode
            ? 'This message looks safe! No scary or tricky words found.'
            : 'No phishing indicators or scam patterns were detected in this message.';
        result.recommendation = 'This message appears to be safe.';
    }

    return result;
}

module.exports = { analyzeMessage };
