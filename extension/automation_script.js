
(function() {
    'use strict';
    
    let automationState = {
        sessionId: null,
        isAutomated: true,
        interceptClicks: false,
        interceptForms: false,
        interceptNavigation: false,
        recordScreenshots: false,
        blockPopups: true,
        blockNewTabs: true
    };
    
    function initAutomation() {
        console.log('[Automation Script] Initializing automation features');
        
        const urlParams = new URLSearchParams(window.location.search);
        automationState.sessionId = urlParams.get('sessionId') || 'unknown';
        
        setupClickInterception();
        setupFormInterception();
        setupNavigationInterception();
        setupPopupBlocking();
        setupScreenshotCapture();
        setupPerformanceMonitoring();
        
        if (typeof chrome !== 'undefined' && chrome.runtime) {
            chrome.runtime.sendMessage({
                action: 'automationReady',
                sessionId: automationState.sessionId,
                url: window.location.href,
                timestamp: Date.now()
            });
        }
        
        console.log('[Automation Script] Automation initialized for session:', automationState.sessionId);
    }
    
    function setupClickInterception() {
        document.addEventListener('click', function(event) {
            if (automationState.interceptClicks) {
                event.preventDefault();
                event.stopPropagation();
                
                const clickData = {
                    type: 'click',
                    target: getElementSelector(event.target),
                    coordinates: {
                        x: event.clientX,
                        y: event.clientY
                    },
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: clickData
                });
                
                console.log('[Automation] Click intercepted:', clickData);
            }
        }, true);
    }
    
    function setupFormInterception() {
        document.addEventListener('submit', function(event) {
            if (automationState.interceptForms) {
                event.preventDefault();
                
                const formData = new FormData(event.target);
                const formObject = {};
                formData.forEach((value, key) => {
                    formObject[key] = value;
                });
                
                const submitData = {
                    type: 'form_submit',
                    form: {
                        action: event.target.action,
                        method: event.target.method,
                        fields: formObject,
                        selector: getElementSelector(event.target)
                    },
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: submitData
                });
                
                console.log('[Automation] Form submission intercepted:', submitData);
            }
        }, true);
    }
    
    function setupNavigationInterception() {
        document.addEventListener('click', function(event) {
            if (automationState.interceptNavigation && event.target.tagName === 'A') {
                event.preventDefault();
                
                const navigationData = {
                    type: 'navigation',
                    url: event.target.href,
                    method: 'GET',
                    trigger: 'link_click',
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: navigationData
                });
                
                console.log('[Automation] Navigation intercepted:', navigationData);
            }
        }, true);
        
        let currentUrl = window.location.href;
        new MutationObserver(function() {
            if (window.location.href !== currentUrl) {
                const navigationData = {
                    type: 'navigation',
                    from: currentUrl,
                    to: window.location.href,
                    method: 'LOCATION_CHANGE',
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: navigationData
                });
                
                currentUrl = window.location.href;
                console.log('[Automation] Location change detected:', navigationData);
            }
        }).observe(document, { subtree: true, childList: true });
    }
    
    function setupPopupBlocking() {
        if (automationState.blockPopups) {
            const originalOpen = window.open;
            window.open = function(url, name, features) {
                const popupData = {
                    type: 'popup_blocked',
                    url: url,
                    name: name,
                    features: features,
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: popupData
                });
                
                console.log('[Automation] Popup blocked:', popupData);
                return null;
            };
        }
        
        if (automationState.blockNewTabs) {
            const originalCreate = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreate.call(this, tagName);
                if (tagName.toLowerCase() === 'a') {
                    element.addEventListener('click', function(event) {
                        if (event.target.target === '_blank' || event.target.target === '_new') {
                            event.preventDefault();
                            const tabData = {
                                type: 'new_tab_blocked',
                                url: event.target.href,
                                timestamp: Date.now(),
                                sessionId: automationState.sessionId
                            };
                            
                            chrome.runtime.sendMessage({
                                action: 'automationEvent',
                                data: tabData
                            });
                            
                            console.log('[Automation] New tab blocked:', tabData);
                        }
                    });
                }
                return element;
            };
        }
    }
    
    function setupScreenshotCapture() {
        if (automationState.recordScreenshots) {
            setInterval(function() {
                const screenshotData = {
                    type: 'screenshot',
                    url: window.location.href,
                    title: document.title,
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId,
                    scrollPosition: {
                        x: window.scrollX,
                        y: window.scrollY
                    },
                    viewport: {
                        width: window.innerWidth,
                        height: window.innerHeight
                    }
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: screenshotData
                });
                
            }, 5000); // Capture every 5 seconds
        }
    }
    
    function setupPerformanceMonitoring() {
        window.addEventListener('load', function() {
            if (performance.timing) {
                const perfData = {
                    type: 'performance',
                    url: window.location.href,
                    timing: {
                        loadTime: performance.timing.loadEventEnd - performance.timing.navigationStart,
                        domReady: performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart,
                        firstPaint: performance.timing.responseStart - performance.timing.navigationStart
                    },
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: perfData
                });
                
                console.log('[Automation] Performance data:', perfData);
            }
        });
        
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const startTime = Date.now();
            return originalFetch.apply(this, args).then(response => {
                const resourceData = {
                    type: 'resource_load',
                    url: args[0],
                    method: args[1]?.method || 'GET',
                    status: response.status,
                    loadTime: Date.now() - startTime,
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: resourceData
                });
                
                return response;
            }).catch(error => {
                const errorData = {
                    type: 'resource_error',
                    url: args[0],
                    error: error.message,
                    timestamp: Date.now(),
                    sessionId: automationState.sessionId
                };
                
                chrome.runtime.sendMessage({
                    action: 'automationEvent',
                    data: errorData
                });
                
                throw error;
            });
        };
    }
    
    function getElementSelector(element) {
        if (element.id) {
            return `#${element.id}`;
        }
        
        let selector = element.tagName.toLowerCase();
        
        if (element.className) {
            selector += '.' + element.className.split(' ').join('.');
        }
        
        return selector;
    }
    
    window.automationControls = {
        enableClickInterception: function() {
            automationState.interceptClicks = true;
            console.log('[Automation] Click interception enabled');
        },
        
        disableClickInterception: function() {
            automationState.interceptClicks = false;
            console.log('[Automation] Click interception disabled');
        },
        
        enableFormInterception: function() {
            automationState.interceptForms = true;
            console.log('[Automation] Form interception enabled');
        },
        
        disableFormInterception: function() {
            automationState.interceptForms = false;
            console.log('[Automation] Form interception disabled');
        },
        
        enableNavigationInterception: function() {
            automationState.interceptNavigation = true;
            console.log('[Automation] Navigation interception enabled');
        },
        
        disableNavigationInterception: function() {
            automationState.interceptNavigation = false;
            console.log('[Automation] Navigation interception disabled');
        },
        
        startScreenshotRecording: function() {
            automationState.recordScreenshots = true;
            console.log('[Automation] Screenshot recording started');
        },
        
        stopScreenshotRecording: function() {
            automationState.recordScreenshots = false;
            console.log('[Automation] Screenshot recording stopped');
        },
        
        getState: function() {
            return automationState;
        },
        
        clickElement: function(selector) {
            const element = document.querySelector(selector);
            if (element) {
                element.click();
                return true;
            }
            return false;
        },
        
        fillForm: function(formSelector, data) {
            const form = document.querySelector(formSelector);
            if (form) {
                Object.keys(data).forEach(key => {
                    const field = form.querySelector(`[name="${key}"], [id="${key}"]`);
                    if (field) {
                        field.value = data[key];
                    }
                });
                return true;
            }
            return false;
        },
        
        scrollTo: function(x, y) {
            window.scrollTo(x, y);
        },
        
        getCurrentUrl: function() {
            return window.location.href;
        },
        
        getPageTitle: function() {
            return document.title;
        },
        
        getPageContent: function() {
            return document.documentElement.outerHTML;
        }
    };
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initAutomation);
    } else {
        initAutomation();
    }
    
})();
