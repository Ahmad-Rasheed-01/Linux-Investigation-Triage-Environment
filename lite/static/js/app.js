// LITE Application JavaScript

// Global variables
let loadingOverlay;
let currentPage = 'dashboard';
let refreshInterval;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    startAutoRefresh();
});

// Initialize application components
function initializeApp() {
    // Create loading overlay
    createLoadingOverlay();
    
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize animations
    initializeAnimations();
    
    // Set current page
    setCurrentPage();
    
    // Initialize charts if on dashboard
    if (currentPage === 'dashboard') {
        initializeDashboard();
    }
    
    console.log('LITE Application initialized successfully');
}

// Setup event listeners
function setupEventListeners() {
    // Navigation links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', handleNavigation);
    });
    
    // Form submissions
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmission);
    });
    
    // File upload areas
    document.querySelectorAll('.file-upload-area').forEach(area => {
        setupFileUpload(area);
    });
    
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(handleSearch, 300));
    }
    
    // Modal events
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('show.bs.modal', handleModalShow);
        modal.addEventListener('hide.bs.modal', handleModalHide);
    });
    
    // Window events
    window.addEventListener('resize', handleWindowResize);
    window.addEventListener('beforeunload', handleBeforeUnload);
}

// Create loading overlay
function createLoadingOverlay() {
    loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'loading-overlay d-none';
    loadingOverlay.innerHTML = `
        <div class="text-center">
            <div class="loading-spinner"></div>
            <p class="mt-3 text-muted">Loading...</p>
        </div>
    `;
    document.body.appendChild(loadingOverlay);
}

// Show loading overlay
function showLoading(message = 'Loading...') {
    if (loadingOverlay) {
        loadingOverlay.querySelector('p').textContent = message;
        loadingOverlay.classList.remove('d-none');
        document.body.style.overflow = 'hidden';
    }
}

// Hide loading overlay
function hideLoading() {
    if (loadingOverlay) {
        loadingOverlay.classList.add('d-none');
        document.body.style.overflow = 'auto';
    }
}

// Initialize tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize animations
function initializeAnimations() {
    // Add fade-in animation to cards
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
        card.classList.add('fade-in');
    });
    
    // Add slide-in animation to sidebar items
    const sidebarItems = document.querySelectorAll('.sidebar .list-group-item');
    sidebarItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 0.05}s`;
        item.classList.add('slide-in-left');
    });
}

// Set current page
function setCurrentPage() {
    const path = window.location.pathname;
    if (path === '/' || path === '/dashboard') {
        currentPage = 'dashboard';
    } else if (path.includes('/cases')) {
        currentPage = 'cases';
    } else if (path.includes('/analysis')) {
        currentPage = 'analysis';
    }
    
    // Update active navigation
    updateActiveNavigation();
}

// Update active navigation
function updateActiveNavigation() {
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === window.location.pathname) {
            link.classList.add('active');
        }
    });
}

// Handle navigation
function handleNavigation(event) {
    const link = event.target.closest('.nav-link');
    if (link && !link.classList.contains('external')) {
        // Add loading state
        showLoading('Navigating...');
        
        // Allow default navigation
        setTimeout(() => {
            hideLoading();
        }, 500);
    }
}

// Handle form submission
function handleFormSubmission(event) {
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    
    if (submitBtn) {
        // Disable submit button
        submitBtn.disabled = true;
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
        
        // Re-enable after delay (will be overridden by actual response)
        setTimeout(() => {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }, 5000);
    }
}

// Setup file upload
function setupFileUpload(uploadArea) {
    const fileInput = uploadArea.querySelector('input[type="file"]');
    
    if (!fileInput) return;
    
    // Drag and drop events
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelection(files, uploadArea);
        }
    });
    
    // File input change
    fileInput.addEventListener('change', function(e) {
        handleFileSelection(e.target.files, uploadArea);
    });
    
    // Click to upload
    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });
}

// Handle file selection
function handleFileSelection(files, uploadArea) {
    const fileList = uploadArea.querySelector('.file-list') || createFileList(uploadArea);
    fileList.innerHTML = '';
    
    Array.from(files).forEach((file, index) => {
        const fileItem = createFileItem(file, index);
        fileList.appendChild(fileItem);
        
        // Validate file
        validateFile(file, fileItem);
    });
    
    // Show file list
    fileList.classList.remove('d-none');
}

// Create file list container
function createFileList(uploadArea) {
    const fileList = document.createElement('div');
    fileList.className = 'file-list mt-3 d-none';
    uploadArea.appendChild(fileList);
    return fileList;
}

// Create file item
function createFileItem(file, index) {
    const fileItem = document.createElement('div');
    fileItem.className = 'file-item card mb-2';
    fileItem.innerHTML = `
        <div class="card-body p-3">
            <div class="d-flex justify-content-between align-items-center">
                <div class="d-flex align-items-center">
                    <i class="fas fa-file-code text-primary me-3 fa-2x"></i>
                    <div>
                        <h6 class="mb-1">${file.name}</h6>
                        <small class="text-muted">${formatFileSize(file.size)} • ${file.type || 'Unknown type'}</small>
                    </div>
                </div>
                <div class="file-status">
                    <span class="badge bg-secondary">Ready</span>
                </div>
            </div>
            <div class="progress mt-2 d-none">
                <div class="progress-bar" role="progressbar" style="width: 0%"></div>
            </div>
        </div>
    `;
    return fileItem;
}

// Validate file
function validateFile(file, fileItem) {
    const statusBadge = fileItem.querySelector('.file-status .badge');
    const maxSize = 500 * 1024 * 1024; // 500MB
    const allowedTypes = ['.json'];
    
    // Check file size
    if (file.size > maxSize) {
        statusBadge.className = 'badge bg-danger';
        statusBadge.textContent = 'Too Large';
        return false;
    }
    
    // Check file type
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    if (!allowedTypes.includes(fileExtension)) {
        statusBadge.className = 'badge bg-warning';
        statusBadge.textContent = 'Invalid Type';
        return false;
    }
    
    statusBadge.className = 'badge bg-success';
    statusBadge.textContent = 'Valid';
    return true;
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Handle search
function handleSearch(event) {
    const query = event.target.value.trim();
    if (query.length < 2) {
        clearSearchResults();
        return;
    }
    
    // Show loading in search results
    showSearchLoading();
    
    // Perform search (implementation depends on current page)
    if (currentPage === 'cases') {
        searchCases(query);
    } else if (currentPage === 'analysis') {
        searchArtifacts(query);
    }
}

// Search cases
function searchCases(query) {
    fetch(`/api/cases/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displaySearchResults(data.results, 'cases');
            } else {
                showSearchError(data.message);
            }
        })
        .catch(error => {
            console.error('Search error:', error);
            showSearchError('Network error during search');
        });
}

// Search artifacts
function searchArtifacts(query) {
    const caseId = getCurrentCaseId();
    if (!caseId) return;
    
    fetch(`/analysis/${caseId}/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displaySearchResults(data.results, 'artifacts');
            } else {
                showSearchError(data.message);
            }
        })
        .catch(error => {
            console.error('Search error:', error);
            showSearchError('Network error during search');
        });
}

// Get current case ID from URL
function getCurrentCaseId() {
    const path = window.location.pathname;
    const matches = path.match(/\/analysis\/([^/]+)/);
    return matches ? matches[1] : null;
}

// Display search results
function displaySearchResults(results, type) {
    // Implementation depends on the page layout
    console.log('Search results:', results);
}

// Show search loading
function showSearchLoading() {
    // Implementation depends on the page layout
    console.log('Showing search loading...');
}

// Show search error
function showSearchError(message) {
    showNotification('Search Error', message, 'error');
}

// Clear search results
function clearSearchResults() {
    // Implementation depends on the page layout
    console.log('Clearing search results...');
}

// Handle modal show
function handleModalShow(event) {
    const modal = event.target;
    modal.classList.add('fade-in');
}

// Handle modal hide
function handleModalHide(event) {
    const modal = event.target;
    modal.classList.remove('fade-in');
}

// Handle window resize
function handleWindowResize() {
    // Update charts if they exist
    if (window.dashboardCharts) {
        Object.values(window.dashboardCharts).forEach(chart => {
            if (chart && chart.resize) {
                chart.resize();
            }
        });
    }
}

// Handle before unload
function handleBeforeUnload(event) {
    // Check for unsaved changes
    const forms = document.querySelectorAll('form');
    let hasUnsavedChanges = false;
    
    forms.forEach(form => {
        if (form.classList.contains('dirty')) {
            hasUnsavedChanges = true;
        }
    });
    
    if (hasUnsavedChanges) {
        event.preventDefault();
        event.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
        return event.returnValue;
    }
}

// Initialize dashboard
function initializeDashboard() {
    loadDashboardData();
    setupDashboardCharts();
}

// Load dashboard data
function loadDashboardData() {
    fetch('/api/dashboard/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateDashboardStats(data.stats);
                updateDashboardCharts(data.charts);
            } else {
                showNotification('Error', 'Failed to load dashboard data', 'error');
            }
        })
        .catch(error => {
            console.error('Dashboard data error:', error);
            showNotification('Error', 'Network error loading dashboard', 'error');
        });
}

// Update dashboard stats
function updateDashboardStats(stats) {
    Object.keys(stats).forEach(key => {
        const element = document.getElementById(`stat-${key}`);
        if (element) {
            animateNumber(element, stats[key]);
        }
    });
}

// Update dashboard charts
function updateDashboardCharts(chartData) {
    if (window.dashboardCharts) {
        Object.keys(chartData).forEach(chartId => {
            const chart = window.dashboardCharts[chartId];
            if (chart && chart.updateData) {
                chart.updateData(chartData[chartId]);
            }
        });
    }
}

// Setup dashboard charts
function setupDashboardCharts() {
    window.dashboardCharts = {};
    
    // Case status chart
    const caseStatusCanvas = document.getElementById('caseStatusChart');
    if (caseStatusCanvas) {
        window.dashboardCharts.caseStatus = createPieChart(caseStatusCanvas, {
            labels: ['Active', 'Inactive', 'Closed'],
            data: [0, 0, 0],
            colors: ['#1cc88a', '#f6c23e', '#e74a3b']
        });
    }
    
    // Artifact timeline chart
    const timelineCanvas = document.getElementById('artifactTimelineChart');
    if (timelineCanvas) {
        window.dashboardCharts.timeline = createLineChart(timelineCanvas, {
            labels: [],
            data: [],
            color: '#4e73df'
        });
    }
}

// Create pie chart
function createPieChart(canvas, config) {
    if (!window.Chart) {
        console.warn('Chart.js not loaded');
        return null;
    }
    
    return new Chart(canvas, {
        type: 'pie',
        data: {
            labels: config.labels,
            datasets: [{
                data: config.data,
                backgroundColor: config.colors,
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// Create line chart
function createLineChart(canvas, config) {
    if (!window.Chart) {
        console.warn('Chart.js not loaded');
        return null;
    }
    
    return new Chart(canvas, {
        type: 'line',
        data: {
            labels: config.labels,
            datasets: [{
                data: config.data,
                borderColor: config.color,
                backgroundColor: config.color + '20',
                borderWidth: 3,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Animate number
function animateNumber(element, targetValue) {
    const startValue = parseInt(element.textContent) || 0;
    const duration = 1000;
    const startTime = performance.now();
    
    function updateNumber(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const currentValue = Math.floor(startValue + (targetValue - startValue) * progress);
        element.textContent = currentValue.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame(updateNumber);
        }
    }
    
    requestAnimationFrame(updateNumber);
}

// Start auto refresh
function startAutoRefresh() {
    if (currentPage === 'dashboard') {
        refreshInterval = setInterval(() => {
            loadDashboardData();
        }, 30000); // Refresh every 30 seconds
    }
}

// Stop auto refresh
function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// Show notification
function showNotification(title, message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        <strong>${title}:</strong> ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Utility functions
const Utils = {
    // Format date
    formatDate: function(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    },
    
    // Format relative time
    formatRelativeTime: function(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
        if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
        return 'Just now';
    },
    
    // Copy to clipboard
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Success', 'Copied to clipboard', 'success');
        }).catch(() => {
            showNotification('Error', 'Failed to copy to clipboard', 'error');
        });
    },
    
    // Download file
    downloadFile: function(url, filename) {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    },
    
    // Confirm action
    confirmAction: function(message, callback) {
        if (confirm(message)) {
            callback();
        }
    }
};

// Export utilities to global scope
window.LiteUtils = Utils;
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.showNotification = showNotification;

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopAutoRefresh();
});

console.log('LITE Application JavaScript loaded successfully');