     // Form submission
        document.getElementById('checkForm')?.addEventListener('submit', function() {
            document.getElementById('loading').style.display = 'block';
        });

        // Toggle raw headers
        function toggleRawHeaders() {
            const content = document.getElementById('rawHeadersContent');
            const icon = document.getElementById('rawHeadersIcon');
            if (content && icon) {
                content.classList.toggle('hidden');
                icon.classList.toggle('rotate-180');
            }
        }

        // Copy to clipboard
        async function copyToClipboard(text) {
            try {
                await navigator.clipboard.writeText(text);
                showNotification('Copied to clipboard!', 'success');
            } catch(err) {
                alert('Could not copy');
            }
        }

        // Show notification
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            const colors = {
                success: 'bg-green-500',
                error: 'bg-red-500',
                info: 'bg-blue-500'
            };
            notification.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg text-white ${colors[type]} animate-pulse-slow`;
            notification.innerHTML = `<i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-info-circle'} mr-2"></i>${message}`;
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 3000);
        }

        // Export report
        function exportReport(format) {
            const reportData = {
                url: "{{ report.url|default:'' }}",
                score: {{ report.security_score|default:0 }},
                grade: "{{ report.grade.value|default:'F' }}",
                timestamp: new Date().toISOString()
            };

            if (format === 'json') {
                const dataStr = JSON.stringify(reportData, null, 2);
                const blob = new Blob([dataStr], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security-report-${Date.now()}.json`;
                a.click();
                URL.revokeObjectURL(url);
                showNotification('Report exported!', 'success');
            }
        }

        // Print report
        function printReport() {
            window.print();
        }

        // Share report
        function shareReport() {
            if (navigator.share) {
                navigator.share({
                    title: 'Security Scan Report',
                    text: `Security score: {{ report.security_score|default:0 }}%`,
                    url: window.location.href
                });
            } else {
                copyToClipboard(window.location.href);
            }
        }

        // Toggle theme
        function toggleTheme() {
            document.body.classList.toggle('dark');
        }

        window.showNotification = showNotification;
        window.exportReport = exportReport;
        window.printReport = printReport;
        window.shareReport = shareReport;
        window.toggleTheme = toggleTheme;