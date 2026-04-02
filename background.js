// Background service worker for Phishing Detector Pro
// Handles Google Safe Browsing API calls and notifications

// Google Safe Browsing API key
const API_KEY = 'Paste safe browisng Api key';
const SAFE_BROWSING_API_URL = 'Paste url here';

// Store current tab safety status
let tabSafetyStatus = new Map();

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detector Pro installed');
  
  // Initialize API key in storage if not already set
  chrome.storage.local.get(['apiKey'], (result) => {
    if (!result.apiKey) {
      console.log('Setting default API key');
      chrome.storage.local.set({ apiKey: API_KEY }, () => {
        console.log('Default API key saved to storage');
      });
    } else {
      console.log('API key already configured');
    }
  });
});

// Listen for web navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only check main frame loads and skip error pages
  if (details.frameId === 0 && !details.url.startsWith('chrome-error://')) {
    await checkUrlSafety(details.url, details.tabId);
  }
});

// Check URL safety using Google Safe Browsing API
async function checkUrlSafety(url, tabId) {
  try {
    // Skip invalid URLs
    if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('chrome-error://')) {
      console.log('Skipping invalid URL:', url);
      return;
    }

    // Get API key from storage
    const result = await chrome.storage.local.get(['apiKey']);
    const apiKey = result.apiKey || API_KEY;
    
    console.log('Using API key:', apiKey ? 'Configured' : 'Not configured');
    
    if (!apiKey || apiKey.includes('Paste')) {
      console.warn('Please configure your Google Safe Browsing API key');
      // Set unknown status when API key is not configured
      tabSafetyStatus.set(tabId, {
        url: url,
        safetyStatus: 'unknown',
        warningMessage: 'API key not configured',
        timestamp: Date.now()
      });
      return;
    }
    
    // Extract base domain
    const urlObj = new URL(url);
    const baseDomain = `${urlObj.protocol}//${urlObj.hostname}`;
    
    // Check both full URL and base domain
    const [urlResult, domainResult] = await Promise.all([
      checkSingleUrl(url, apiKey),
      checkSingleUrl(baseDomain, apiKey)
    ]);
    
    console.log(`URL check result for ${url}: ${urlResult}`);
    console.log(`Domain check result for ${baseDomain}: ${domainResult}`);
    
    // Determine safety status
    let safetyStatus = 'safe';
    let warningMessage = '';
    
    if (urlResult && domainResult) {
      safetyStatus = 'unsafe';
      warningMessage = '⚠️ Warning: This site or link may be unsafe.';
    } else if (urlResult) {
      safetyStatus = 'unsafe';
      warningMessage = '⚠️ Warning: This link may be unsafe.';
    } else if (domainResult) {
      safetyStatus = 'unsafe';
      warningMessage = '⚠️ Warning: This site may be unsafe.';
    }
    
    // Store status for popup
    tabSafetyStatus.set(tabId, {
      url: url,
      baseDomain: baseDomain,
      safetyStatus: safetyStatus,
      warningMessage: warningMessage,
      timestamp: Date.now()
    });
    
    // If unsafe, show notification and inject warning
    if (safetyStatus === 'unsafe') {
      showNotification(warningMessage, url);
      // Only inject banner if not on error page
      if (!url.startsWith('chrome-error://')) {
        injectWarningBanner(tabId, warningMessage);
      }
    }
    
    console.log(`Safety check for ${url}: ${safetyStatus}`);
    
  } catch (error) {
    console.error('Error checking URL safety:', error);
    // Set unknown status on error
    tabSafetyStatus.set(tabId, {
      url: url,
      safetyStatus: 'unknown',
      warningMessage: 'Unable to check safety status',
      timestamp: Date.now()
    });
  }
}

// Check a single URL against Safe Browsing API
async function checkSingleUrl(url, apiKey) {
  try {
    console.log(`Checking URL: ${url}`);
    
    const response = await fetch(`${SAFE_BROWSING_API_URL}?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: {
          clientId: 'phishing-detector-pro',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url }]
        }
      })
    });
    
    if (!response.ok) {
      console.error(`API request failed with status: ${response.status}`);
      return false;
    }
    
    const data = await response.json();
    console.log(`API response for ${url}:`, data);
    
    // Check if there are matches or if the API returned an error
    if (data.error) {
      console.error('Safe Browsing API error:', JSON.stringify(data.error));
      return false;
    }
    
    // Check if matches exist
    const hasMatches = data.matches && Array.isArray(data.matches) && data.matches.length > 0;
    console.log(`Has matches for ${url}: ${hasMatches}`);
    
    return hasMatches;
    
  } catch (error) {
    console.error('Safe Browsing API error:', error);
    return false;
  }
}

// Show Chrome notification
function showNotification(message, url) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Phishing Detector Pro',
      message: message,
      priority: 2
    });
  } catch (error) {
    console.error('Error showing notification:', error);
  }
}

// Inject warning banner into page
async function injectWarningBanner(tabId, message) {
  try {
    // Check if tab is still valid and not on error page
    const tab = await chrome.tabs.get(tabId);
    if (!tab || tab.url.startsWith('chrome-error://')) {
      console.log('Skipping banner injection for error page or invalid tab');
      return;
    }

    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      function: injectBanner,
      args: [message]
    });
  } catch (error) {
    console.error('Error injecting warning banner:', error);
  }
}

// Function to be injected into the page
function injectBanner(message) {
  try {
    // Remove existing banner if present
    const existingBanner = document.getElementById('phishing-detector-banner');
    if (existingBanner) {
      existingBanner.remove();
    }
    
    // Create warning banner
    const banner = document.createElement('div');
    banner.id = 'phishing-detector-banner';
    banner.innerHTML = `
      <div class="phishing-warning">
        <span class="warning-icon">⚠️</span>
        <span class="warning-text">${message}</span>
        <button class="warning-close" onclick="this.parentElement.parentElement.remove()">×</button>
      </div>
    `;
    
    // Insert at the top of the page
    if (document.body) {
      document.body.insertBefore(banner, document.body.firstChild);
      
      // Trigger slide-down animation
      setTimeout(() => {
        banner.classList.add('show');
      }, 100);
    }
  } catch (error) {
    console.error('Error in injectBanner function:', error);
  }
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getSafetyStatus') {
    const tabId = request.tabId;
    const status = tabSafetyStatus.get(tabId) || {
      safetyStatus: 'unknown',
      warningMessage: 'Status unknown',
      timestamp: Date.now()
    };
    sendResponse(status);
  }
  
  if (request.action === 'checkUrlSafety') {
    // Get the current tab URL and check safety
    chrome.tabs.get(request.tabId, async (tab) => {
      if (tab && tab.url) {
        await checkUrlSafety(tab.url, request.tabId);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'Tab not found' });
      }
    });
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'setApiKey') {
    chrome.storage.local.set({ apiKey: request.apiKey }, () => {
      sendResponse({ success: true });
    });
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'getApiKey') {
    chrome.storage.local.get(['apiKey'], (result) => {
      sendResponse({ apiKey: result.apiKey || '' });
    });
    return true; // Keep message channel open for async response
  }
});
