/**
 * File Analyzer Utility
 * Detects dangerous file types and suspicious naming patterns.
 */

function analyzeFile(fileName, fileSize, fileType) {
    const result = {
        riskLevel: 'safe',
        fileCategory: 'Document',
        fileExtension: 'unknown',
        explanation: 'This file appears to be a standard document and is likely safe.',
        indicators: [],
        recommendation: 'You can safely open this file, but stay alert for any unusual behavior.'
    };

    if (!fileName) return result;

    const parts = fileName.split('.');
    const extension = parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
    result.fileExtension = extension || 'none';

    const indicators = [];
    let score = 0;

    // 1. Dangerous Extensions
    const dangerousExtensions = ['exe', 'msi', 'bat', 'sh', 'cmd', 'ps1', 'vbs', 'scr', 'com', 'pif'];
    const suspiciousExtensions = ['zip', 'rar', '7z', 'iso', 'dmg', 'js', 'jar', 'svg'];

    if (dangerousExtensions.includes(extension)) {
        score += 80;
        result.fileCategory = 'Executable / Script';
        indicators.push(`High-risk executable extension (.${extension}) detected`);
    } else if (suspiciousExtensions.includes(extension)) {
        score += 40;
        result.fileCategory = 'Archive / Script';
        indicators.push(`Potentially suspicious extension (.${extension}) detected`);
    }

    // 2. Double Extensions (e.g., invoice.pdf.exe)
    if (parts.length > 2) {
        const secondLast = parts[parts.length - 2].toLowerCase();
        const commonDocs = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'jpg', 'png'];

        if (commonDocs.includes(secondLast) && dangerousExtensions.includes(extension)) {
            score += 50;
            indicators.push(`Double extension detected (trying to look like a .${secondLast} while being an .${extension})`);
        }
    }

    // 3. File Size Checks
    const sizeMB = fileSize / (1024 * 1024);
    if (sizeMB > 50) {
        score += 10;
        indicators.push('Unusually large file size for a simple document');
    }

    // 4. Content Type Mismatch
    if (fileType) {
        const typeParts = fileType.split('/');
        if (typeParts[0] === 'image' && dangerousExtensions.includes(extension)) {
            score += 40;
            indicators.push('MIME type indicates an image, but the extension is executable (highly suspicious)');
        }
    }

    // Final scoring
    if (score >= 80) {
        result.riskLevel = 'critical';
        result.explanation = 'This file is extremely dangerous. It is an executable program that could install malware, steal your data, or lock your computer.';
        result.recommendation = '⚠️ DO NOT OPEN THIS FILE. Delete it immediately and do not run it.';
    } else if (score >= 50) {
        result.riskLevel = 'high';
        result.explanation = 'This file has high-risk characteristics. It might be a virus disguised as a normal document.';
        result.recommendation = 'Do not open this file unless you are 100% sure you know who sent it and why. Scan it with a dedicated antivirus.';
    } else if (score >= 30) {
        result.riskLevel = 'medium';
        result.explanation = 'This file type is often used to hide malware. While it might be safe, it requires caution.';
        result.recommendation = 'Only open if you expected this file. If it asks for special permissions, deny them.';
    } else if (score >= 15) {
        result.riskLevel = 'low';
        result.explanation = 'Minor suspicious indicators found, possibly due to the file type or size.';
        result.recommendation = 'Proceed with caution. Ensure your antivirus software is active.';
    } else {
        result.riskLevel = 'safe';
        result.explanation = 'No significant threat indicators were found for this file structure.';
        result.recommendation = 'This file appears safe to use.';
    }

    result.indicators = indicators;
    return result;
}

module.exports = { analyzeFile };
