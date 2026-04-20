// Advanced Security Scanner UI - Complete Version

class SecurityScannerUI {
    constructor() {
        this.notificationQueue = [];
        this.isShowingNotification = false;
        this.init();
    }

    init() {
        this.attachEventListeners();
        this.initializeCharts();
        this.setupRealTimeValidation();
        this.setupKeyboardShortcuts();
        this.setupCopyButtons();
        this.setupTooltips();
        this.setupScrollAnimations();
        this.loadThemePreference();
    }

    attachEventListeners() {
        // URL input validation
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.addEventListener('input', (e) => {
                this.validateUrl(e.target.value);
            });

            urlInput.addEventListener('blur', (e) => {
                this.autoCompleteUrl(e.target.value);
            });
        }

        // Form submission
        const form = document.getElementById('checkForm');
        if (form) {
            form.addEventListener('submit', (e) => {
                this.handleFormSubmit(e);
            });
        }

        // Scan button enhancement
        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                this.addRippleEffect(scanBtn);
            });
        }

        // Mobile menu toggle
        const mobileMenuBtn = document.querySelector('.md\\:hidden');
        if (mobileMenuBtn) {
            mobileMenuBtn.addEventListener('click', () => {
                this.toggleMobileMenu();
            });
        }
    }

    validateUrl(url) {
        const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
        const ipPattern = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;
        const isValid = urlPattern.test(url) || ipPattern.test(url);

        const input = document.getElementById('urlInput');
        const validationIcon = document.getElementById('validationIcon');

        if (url && !isValid && url.length > 0) {
            input.classList.add('border-red-500', 'focus:border-red-500');
            if (!validationIcon) {
                const icon = document.createElement('i');
                icon.id = 'validationIcon';
                icon.className = 'fas fa-exclamation-circle absolute right-3 top-1/2 transform -translate-y-1/2 text-red-500';
                input.parentElement.appendChild(icon);
            }
            return false;
        } else {
            input.classList.remove('border-red-500', 'focus:border-red-500');
            const existingIcon = document.getElementById('validationIcon');
            if (existingIcon) existingIcon.remove();
            return true;
        }
    }

    autoCompleteUrl(url) {
        if (url && !url.startsWith('http')) {
            const input = document.getElementById('urlInput');
            const suggestions = [
                `https://${url}`,
                `http://${url}`,
                `https://www.${url}`
            ];
            this.showUrlSuggestions(suggestions);
        }
    }

    showUrlSuggestions(suggestions) {
        let suggestionBox = document.getElementById('suggestionBox');
        if (!suggestionBox) {
            suggestionBox = document.createElement('div');
            suggestionBox.id = 'suggestionBox';
            suggestionBox.className = 'absolute z-10 w-full mt-1 bg-white rounded-lg shadow-lg border border-gray-200 hidden';
            document.getElementById('urlInput').parentElement.appendChild(suggestionBox);
        }

        suggestionBox.innerHTML = suggestions.map(suggestion => `
            <div class="suggestion-item px-4 py-2 hover:bg-gray-100 cursor-pointer text-sm" data-url="${suggestion}">
                <i class="fas fa-link text-gray-400 mr-2"></i>${suggestion}
            </div>
        `).join('');

        suggestionBox.classList.remove('hidden');

        document.querySelectorAll('.suggestion-item').forEach(item => {
            item.addEventListener('click', () => {
                document.getElementById('urlInput').value = item.dataset.url;
                suggestionBox.classList.add('hidden');
                this.validateUrl(item.dataset.url);
            });
        });

        setTimeout(() => {
            suggestionBox.classList.add('hidden');
        }, 5000);
    }

    handleFormSubmit(e) {
        const urlInput = document.getElementById('urlInput');
        if (!urlInput.value.trim()) {
            e.preventDefault();
            this.showNotification('Please enter a URL to scan', 'error');
            return;
        }

        if (!this.validateUrl(urlInput.value)) {
            e.preventDefault();
            this.showNotification('Please enter a valid URL format', 'error');
            return;
        }

        // Show loading animation
        this.showLoading();
    }

    showLoading() {
        const loadingDiv = document.getElementById('loading');
        if (loadingDiv) {
            loadingDiv.style.display = 'block';
            loadingDiv.innerHTML = `
                <div class="flex flex-col items-center justify-center py-8">
                    <div class="relative">
                        <div class="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-600"></div>
                        <div class="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                            <i class="fas fa-shield-alt text-purple-600 text-xl animate-pulse"></i>
                        </div>
                    </div>
                    <p class="mt-4 text-gray-700 font-semibold">Analyzing security headers...</p>
                    <p class="text-sm text-gray-500 mt-2">Checking CSP, HSTS, X-Frame-Options and more</p>
                    <div class="mt-4 flex space-x-2">
                        <div class="w-2 h-2 bg-purple-600 rounded-full animate-bounce" style="animation-delay: 0s"></div>
                        <div class="w-2 h-2 bg-purple-600 rounded-full animate-bounce" style="animation-delay: 0.2s"></div>
                        <div class="w-2 h-2 bg-purple-600 rounded-full animate-bounce" style="animation-delay: 0.4s"></div>
                    </div>
                </div>
            `;
        }

        const scanBtn = document.getElementById('scanBtn');
        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Scanning...';
        }
    }

    initializeCharts() {
        const canvas = document.getElementById('securityChart');
        if (canvas && typeof Chart !== 'undefined') {
            const ctx = canvas.getContext('2d');

            // Get data from data attributes
            const presentHeaders = parseInt(canvas.dataset.present || 0);
            const totalHeaders = parseInt(canvas.dataset.total || 11);
            const missingHeaders = totalHeaders - presentHeaders;

            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Present Headers', 'Missing Headers'],
                    datasets: [{
                        data: [presentHeaders, missingHeaders],
                        backgroundColor: [
                            'rgba(34, 197, 94, 0.8)',
                            'rgba(239, 68, 68, 0.8)'
                        ],
                        borderColor: [
                            'rgb(34, 197, 94)',
                            'rgb(239, 68, 68)'
                        ],
                        borderWidth: 2,
                        hoverOffset: 15
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                font: {
                                    size: 12,
                                    family: 'Inter'
                                },
                                padding: 15,
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            },
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleFont: { size: 13, weight: 'bold' },
                            bodyFont: { size: 12 }
                        }
                    },
                    cutout: '60%',
                    animation: {
                        animateScale: true,
                        animateRotate: true,
                        duration: 1000,
                        easing: 'easeInOutQuart'
                    }
                }
            });
        }

        // Radar chart for detailed analysis
        const radarCanvas = document.getElementById('radarChart');
        if (radarCanvas && typeof Chart !== 'undefined') {
            const scores = JSON.parse(radarCanvas.dataset.scores || '{}');
            new Chart(radarCanvas, {
                type: 'radar',
                data: {
                    labels: Object.keys(scores),
                    datasets: [{
                        label: 'Security Score (%)',
                        data: Object.values(scores),
                        backgroundColor: 'rgba(102, 126, 234, 0.2)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 2,
                        pointBackgroundColor: 'rgba(102, 126, 234, 1)',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: 'rgba(102, 126, 234, 1)',
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        r: {
                            beginAtZero: true,
                            max: 100,
                            ticks: {
                                stepSize: 20,
                                backdropColor: 'transparent'
                            },
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)'
                            }
                        }
                    },
                    plugins: {
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    return `${context.label}: ${context.raw}%`;
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    setupRealTimeValidation() {
        const form = document.getElementById('checkForm');
        if (form) {
            // Add real-time URL validation
            const urlInput = document.getElementById('urlInput');
            if (urlInput) {
                urlInput.addEventListener('keyup', (e) => {
                    if (e.key === 'Enter') {
                        form.requestSubmit();
                    }
                });
            }
        }
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl + Enter to submit
            if (e.ctrlKey && e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('checkForm')?.requestSubmit();
            }

            // Ctrl + R to reset
            if (e.ctrlKey && e.key === 'r') {
                e.preventDefault();
                this.resetForm();
            }

            // Escape to close modals
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });
    }

    setupCopyButtons() {
        document.querySelectorAll('[data-copy]').forEach(button => {
            button.addEventListener('click', async () => {
                const textToCopy = button.dataset.copy;
                await this.copyToClipboard(textToCopy);
                this.showNotification('Copied to clipboard!', 'success');
            });
        });
    }

    setupTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(element.dataset.tooltip, element);
            });
            element.addEventListener('mouseleave', () => {
                this.hideTooltip();
            });
        });
    }

    setupScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-fade-in-up');
                    observer.unobserve(entry.target);
                }
            });
        }, observerOptions);

        document.querySelectorAll('.animate-on-scroll').forEach(el => {
            observer.observe(el);
        });
    }

    loadThemePreference() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark');
        }
    }

    toggleTheme() {
        document.body.classList.toggle('dark');
        const isDark = document.body.classList.contains('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        this.showNotification(`${isDark ? 'Dark' : 'Light'} mode activated`, 'info');
    }

    toggleMobileMenu() {
        const mobileMenu = document.getElementById('mobileMenu');
        if (mobileMenu) {
            mobileMenu.classList.toggle('hidden');
            mobileMenu.classList.toggle('animate-slide-down');
        }
    }

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            return true;
        }
    }

    showTooltip(message, element) {
        let tooltip = document.getElementById('dynamicTooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'dynamicTooltip';
            tooltip.className = 'fixed z-50 px-2 py-1 text-xs text-white bg-gray-900 rounded shadow-lg pointer-events-none';
            document.body.appendChild(tooltip);
        }

        const rect = element.getBoundingClientRect();
        tooltip.textContent = message;
        tooltip.style.top = `${rect.top - 30}px`;
        tooltip.style.left = `${rect.left + rect.width / 2 - tooltip.offsetWidth / 2}px`;
        tooltip.style.display = 'block';

        setTimeout(() => {
            this.hideTooltip();
        }, 2000);
    }

    hideTooltip() {
        const tooltip = document.getElementById('dynamicTooltip');
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        const colors = {
            success: 'bg-gradient-to-r from-green-500 to-emerald-600',
            error: 'bg-gradient-to-r from-red-500 to-rose-600',
            warning: 'bg-gradient-to-r from-yellow-500 to-orange-600',
            info: 'bg-gradient-to-r from-blue-500 to-indigo-600'
        };

        notification.className = `fixed top-4 right-4 z-50 px-5 py-3 rounded-xl shadow-2xl text-white transform transition-all duration-500 ${colors[type]} flex items-center gap-3 animate-slide-in-right`;
        notification.innerHTML = `
            <i class="fas ${icons[type]} text-xl"></i>
            <div class="flex-1">
                <p class="font-semibold text-sm">${type.charAt(0).toUpperCase() + type.slice(1)}</p>
                <p class="text-sm opacity-95">${message}</p>
            </div>
            <button onclick="this.parentElement.remove()" class="hover:opacity-80 transition">
                <i class="fas fa-times"></i>
            </button>
            <div class="absolute bottom-0 left-0 h-1 bg-white/30 rounded-b-xl" style="width: 100%; animation: shrink 3s linear forwards;"></div>
        `;

        document.body.appendChild(notification);

        // Add animation keyframes if not exists
        if (!document.querySelector('#notificationStyles')) {
            const style = document.createElement('style');
            style.id = 'notificationStyles';
            style.textContent = `
                @keyframes slideInRight {
                    from {
                        opacity: 0;
                        transform: translateX(100%);
                    }
                    to {
                        opacity: 1;
                        transform: translateX(0);
                    }
                }
                @keyframes shrink {
                    from {
                        width: 100%;
                    }
                    to {
                        width: 0%;
                    }
                }
                .animate-slide-in-right {
                    animation: slideInRight 0.3s ease-out;
                }
            `;
            document.head.appendChild(style);
        }

        // Auto remove after 3 seconds
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    addRippleEffect(element) {
        const ripple = document.createElement('div');
        ripple.className = 'absolute inset-0 bg-white opacity-30 rounded-xl pointer-events-none animate-ripple';
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);

        setTimeout(() => ripple.remove(), 600);
    }

    closeAllModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.add('hidden');
        });
    }

    resetForm() {
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.value = '';
            this.validateUrl('');
        }
        window.location.href = window.location.pathname;
        this.showNotification('Form reset successfully', 'info');
    }

    exportReport(format = 'json') {
        const reportData = this.collectReportData();

        if (format === 'json') {
            const dataStr = JSON.stringify(reportData, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            this.showNotification('Report exported as JSON', 'success');
        } else if (format === 'csv') {
            this.exportAsCSV(reportData);
        } else if (format === 'pdf') {
            this.exportAsPDF(reportData);
        }
    }

    collectReportData() {
        // Collect all report data from the page
        const score = document.querySelector('[data-score]')?.dataset.score || '0';
        const grade = document.querySelector('[data-grade]')?.dataset.grade || 'F';

        return {
            url: window.location.href,
            timestamp: new Date().toISOString(),
            security_score: score,
            grade: grade,
            headers: this.collectHeadersData(),
            recommendations: this.collectRecommendations()
        };
    }

    collectHeadersData() {
        const headers = [];
        document.querySelectorAll('.header-item').forEach(item => {
            headers.push({
                name: item.querySelector('.header-name')?.textContent,
                status: item.querySelector('.header-status')?.textContent,
                value: item.querySelector('.header-value')?.textContent
            });
        });
        return headers;
    }

    collectRecommendations() {
        const recommendations = [];
        document.querySelectorAll('.recommendation-item').forEach(item => {
            recommendations.push(item.textContent);
        });
        return recommendations;
    }

    exportAsCSV(data) {
        const headers = Object.keys(data);
        const csv = [headers.join(','), headers.map(h => JSON.stringify(data[h] || '')).join(',')].join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        this.showNotification('Report exported as CSV', 'success');
    }

    exportAsPDF(data) {
        this.showNotification('PDF export coming soon!', 'info');
        // Implement PDF export using jsPDF or similar library
    }

    shareReport() {
        if (navigator.share) {
            navigator.share({
                title: 'Security Scan Report',
                text: `Security scan results: ${document.querySelector('[data-score]')?.dataset.score}%`,
                url: window.location.href
            }).catch(() => {
                this.showNotification('Share cancelled', 'info');
            });
        } else {
            this.copyToClipboard(window.location.href);
            this.showNotification('Link copied to clipboard!', 'success');
        }
    }

    printReport() {
        window.print();
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    window.securityScanner = new SecurityScannerUI();
});

// Export functions for global use
window.copyToClipboard = (text) => {
    if (window.securityScanner) {
        return window.securityScanner.copyToClipboard(text);
    }
};

window.showNotification = (message, type) => {
    if (window.securityScanner) {
        window.securityScanner.showNotification(message, type);
    }
};

window.exportReport = (format) => {
    if (window.securityScanner) {
        window.securityScanner.exportReport(format);
    }
};

window.shareReport = () => {
    if (window.securityScanner) {
        window.securityScanner.shareReport();
    }
};

window.printReport = () => {
    if (window.securityScanner) {
        window.securityScanner.printReport();
    }
};

window.resetForm = () => {
    if (window.securityScanner) {
        window.securityScanner.resetForm();
    }
};

window.toggleTheme = () => {
    if (window.securityScanner) {
        window.securityScanner.toggleTheme();
    }
};

window.toggleRawHeaders = () => {
    const content = document.getElementById('rawHeadersContent');
    const icon = document.getElementById('rawHeadersIcon');
    if (content && icon) {
        content.classList.toggle('hidden');
        icon.classList.toggle('rotate-180');
    }
};