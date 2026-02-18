// keystroke.js - Enhanced keystroke recording for behavioral biometrics
class KeystrokeRecorder {
    constructor() {
        this.events = [];
        this.startTime = null;
        this.currentField = null;
        this.isRecording = false;
        this.sessionId = null;
    }

    startRecording(fieldId) {
        const field = document.getElementById(fieldId);
        if (!field) return;
        
        this.currentField = field;
        this.events = [];
        this.startTime = performance.now(); // More precise than Date.now()
        this.sessionId = this.generateSessionId();
        this.isRecording = true;
        
        // Remove any existing listeners to avoid duplicates
        field.removeEventListener('keydown', this.handleKeyDown);
        field.removeEventListener('keyup', this.handleKeyUp);
        
        // Bind handlers
        this.handleKeyDown = this.handleKeyDown.bind(this);
        this.handleKeyUp = this.handleKeyUp.bind(this);
        
        // Add new listeners
        field.addEventListener('keydown', this.handleKeyDown, { capture: true });
        field.addEventListener('keyup', this.handleKeyUp, { capture: true });
        
        console.log(`Started recording for ${fieldId}, session: ${this.sessionId}`);
    }

    stopRecording() {
        if (this.currentField) {
            this.currentField.removeEventListener('keydown', this.handleKeyDown);
            this.currentField.removeEventListener('keyup', this.handleKeyUp);
        }
        this.isRecording = false;
        const eventsCopy = [...this.events];
        console.log(`Stopped recording, captured ${eventsCopy.length} events`);
        return eventsCopy;
    }

    handleKeyDown(event) {
        if (!this.isRecording) return;
        
        // Don't record modifier keys (Shift, Ctrl, Alt, etc.)
        if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Tab', 'Escape'].includes(event.key)) {
            return;
        }
        
        const timestamp = performance.now() - this.startTime;
        this.events.push({
            type: 'keydown',
            timestamp: parseFloat(timestamp.toFixed(3)), // Store as milliseconds with 3 decimal places
            key: event.key,
            code: event.code,
            sessionId: this.sessionId
        });
    }

    handleKeyUp(event) {
        if (!this.isRecording) return;
        
        if (['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Tab', 'Escape'].includes(event.key)) {
            return;
        }
        
        const timestamp = performance.now() - this.startTime;
        this.events.push({
            type: 'keyup',
            timestamp: parseFloat(timestamp.toFixed(3)),
            key: event.key,
            code: event.code,
            sessionId: this.sessionId
        });
    }

    generateSessionId() {
        return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    getEvents() {
        return [...this.events];
    }

    clearEvents() {
        this.events = [];
        this.startTime = null;
        this.sessionId = null;
    }
}

// Global recorder instance
const keystrokeRecorder = new KeystrokeRecorder();

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check which page we're on
    if (document.getElementById('loginForm')) {
        setupLoginForm();
    }
    if (document.getElementById('registrationForm')) {
        setupRegistrationForm();
    }
});

function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    const loginPassword = document.getElementById('loginPassword');
    const loginResult = document.getElementById('loginResult');
    
    if (!loginForm || !loginPassword) return;
    
    // Start recording when password field gets focus
    loginPassword.addEventListener('focus', function() {
        keystrokeRecorder.clearEvents();
        keystrokeRecorder.startRecording('loginPassword');
    });
    
    // Stop recording when field loses focus (optional)
    loginPassword.addEventListener('blur', function() {
        // We don't stop here because we want to capture the entire typing session
    });
    
    // Handle form submission
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('loginUsername').value.trim();
        const password = loginPassword.value;
        
        // Basic validation
        if (!username || !password) {
            showMessage(loginResult, 'Please enter both username and password', 'error');
            return;
        }
        
        // Get keystroke events
        const keystrokes = keystrokeRecorder.stopRecording();
        
        if (keystrokes.length === 0) {
            showMessage(loginResult, 'No keystroke data captured. Please try typing again.', 'error');
            return;
        }
        
        // Show loading
        showMessage(loginResult, 'Authenticating... Analyzing your typing pattern...', 'info');
        
        // Prepare payload
        const payload = {
            username: username,
            password: password,
            keystrokes: keystrokes
        };
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            
            if (result.ok) {
                showMessage(loginResult, 
                    `✅ ${result.message}<br>
                     Confidence: ${(result.confidence * 100).toFixed(1)}%<br>
                     Rhythm Similarity: ${(result.rhythm_similarity * 100).toFixed(1)}%`,
                    'success');
                
                // Redirect to dashboard after 2 seconds
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 2000);
            } else {
                let errorMessage = `❌ ${result.message}`;
                if (result.reason) {
                    errorMessage += `<br>Reason: ${result.reason}`;
                }
                if (result.confidence) {
                    errorMessage += `<br>Confidence: ${(result.confidence * 100).toFixed(1)}%`;
                }
                
                showMessage(loginResult, errorMessage, 'error');
                
                // Clear keystroke events and restart recording for next attempt
                keystrokeRecorder.clearEvents();
                loginPassword.focus();
                keystrokeRecorder.startRecording('loginPassword');
            }
        } catch (error) {
            console.error('Login error:', error);
            showMessage(loginResult, 'Network error. Please check your connection and try again.', 'error');
        }
    });
}

function setupRegistrationForm() {
    const registerForm = document.getElementById('registrationForm');
    const usernameField = document.getElementById('username');
    const passwordField = document.getElementById('password');
    const confirmField = document.getElementById('confirmPassword');
    const registerResult = document.getElementById('registerResult');
    
    if (!registerForm || !passwordField || !confirmField) return;
    
    let passwordEvents = [];
    let confirmEvents = [];
    let passwordRecorder = new KeystrokeRecorder();
    let confirmRecorder = new KeystrokeRecorder();
    
    // Start recording for password field
    passwordField.addEventListener('focus', function() {
        passwordRecorder.clearEvents();
        passwordRecorder.startRecording('password');
    });
    
    // Start recording for confirm field
    confirmField.addEventListener('focus', function() {
        confirmRecorder.clearEvents();
        confirmRecorder.startRecording('confirmPassword');
    });
    
    // Handle form submission
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = usernameField.value.trim();
        const password = passwordField.value;
        const confirmPassword = confirmField.value;
        
        // Basic validation
        if (!username || !password || !confirmPassword) {
            showMessage(registerResult, 'Please fill in all fields', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage(registerResult, 'Passwords do not match', 'error');
            return;
        }
        
        // Check password strength
        if (!isStrongPassword(password)) {
            showMessage(registerResult, 
                'Password is weak. Must include at least 3 letters, 2 numbers, and 1 special character',
                'error');
            return;
        }
        
        // Get keystroke events
        passwordEvents = passwordRecorder.stopRecording();
        confirmEvents = confirmRecorder.stopRecording();
        
        if (passwordEvents.length === 0 || confirmEvents.length === 0) {
            showMessage(registerResult, 'No keystroke data captured. Please type both password fields.', 'error');
            return;
        }
        
        // Show loading
        showMessage(registerResult, 'Creating your biometric profile... Please wait...', 'info');
        
        // Prepare payload
        const payload = {
            username: username,
            password: password,
            passwordSamples: [passwordEvents, confirmEvents]
        };
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            
            const result = await response.json();
            
            if (result.ok) {
                showMessage(registerResult, 
                    `✅ ${result.message}<br>
                     Your typing pattern has been captured and analyzed.<br>
                     Redirecting to dashboard...`,
                    'success');
                
                // Redirect to dashboard after 2 seconds
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 2000);
            } else {
                let errorMessage = `❌ ${result.message}`;
                if (result.conditions) {
                    errorMessage += `<br>${result.conditions}`;
                }
                showMessage(registerResult, errorMessage, 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            showMessage(registerResult, 'Network error. Please check your connection and try again.', 'error');
        }
    });
}

function isStrongPassword(password) {
    if (!password || typeof password !== 'string') return false;
    
    const letters = (password.match(/[a-zA-Z]/g) || []).length;
    const digits = (password.match(/[0-9]/g) || []).length;
    const specials = (password.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;
    
    return password.length >= 8 && letters >= 3 && digits >= 2 && specials >= 1;
}

function showMessage(element, message, type) {
    if (!element) return;
    
    element.innerHTML = '';
    
    if (!message) {
        element.style.display = 'none';
        return;
    }
    
    element.style.display = 'block';
    
    switch (type) {
        case 'success':
            element.className = 'result success';
            break;
        case 'error':
            element.className = 'result error';
            break;
        case 'info':
            element.className = 'result info';
            element.style.backgroundColor = '#d1ecf1';
            element.style.color = '#0c5460';
            element.style.borderColor = '#bee5eb';
            break;
        default:
            element.className = 'result';
    }
    
    element.innerHTML = message;
}

// Utility function to switch tabs (if needed, can be called from HTML)
function switchTab(tabName) {
    // This function is already defined in login.html, but here's a backup
    const tabs = document.querySelectorAll('.tab');
    const sections = document.querySelectorAll('.form-section');
    
    tabs.forEach(tab => tab.classList.remove('active'));
    sections.forEach(section => section.classList.remove('active'));
    
    if (tabName === 'login') {
        document.querySelector('.tab:nth-child(1)').classList.add('active');
        document.getElementById('login-form').classList.add('active');
    } else {
        document.querySelector('.tab:nth-child(2)').classList.add('active');
        document.getElementById('register-form').classList.add('active');
    }
}

// Export for testing (if using modules)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { KeystrokeRecorder, isStrongPassword };
}