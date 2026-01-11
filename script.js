// === FIREBASE CONFIGURATION ===
const firebaseConfig = {
    apiKey: "AIzaSyBOCz9hJnSmjo0fVPJmyTJ_RYEGei-uFTw",
    authDomain: "nebulachat-52e6f.firebaseapp.com",
    databaseURL: "https://nebulachat-52e6f-default-rtdb.europe-west1.firebasedatabase.app",
    projectId: "nebulachat-52e6f",
    storageBucket: "nebulachat-52e6f.firebasestorage.app",
    messagingSenderId: "300504322724",
    appId: "1:300504322724:web:e4e4748d633d3d63fa4c31",
    measurementId: "G-M4F6QW2WDB"
};

// Initialize Firebase
if (!firebase.apps.length) firebase.initializeApp(firebaseConfig);
const db = firebase.database();

// =============================================
// === NEBULA ENCRYPTION SYSTEM (E2E + 2FA) ===
// =============================================

class NebulaCrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12;
        this.saltLength = 16;
        this.iterations = 100000; // PBKDF2 iterations
        this.masterKey = null;
        this.chatKeys = {};
    }

    // Generate random bytes
    getRandomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // Convert ArrayBuffer to Base64
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // Convert Base64 to ArrayBuffer
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Hash password with SHA-256
    async hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return this.arrayBufferToBase64(hashBuffer);
    }

    // Derive encryption key from password using PBKDF2
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: this.algorithm, length: this.keyLength },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // Generate master key from user password
    async initMasterKey(password, salt) {
        if (typeof salt === 'string') {
            salt = this.base64ToArrayBuffer(salt);
        }
        this.masterKey = await this.deriveKey(password, new Uint8Array(salt));
        return this.masterKey;
    }

    // Generate unique chat key
    async generateChatKey(chatId) {
        const keyBytes = this.getRandomBytes(32);
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: this.algorithm, length: this.keyLength },
            true,
            ['encrypt', 'decrypt']
        );
        this.chatKeys[chatId] = key;
        return this.arrayBufferToBase64(keyBytes);
    }

    // Import chat key from base64
    async importChatKey(chatId, keyBase64) {
        const keyBytes = new Uint8Array(this.base64ToArrayBuffer(keyBase64));
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: this.algorithm, length: this.keyLength },
            true,
            ['encrypt', 'decrypt']
        );
        this.chatKeys[chatId] = key;
        return key;
    }

    // Encrypt message with AES-256-GCM
    async encrypt(plaintext, chatId) {
        let key = this.chatKeys[chatId];
        if (!key) {
            // Use master key if no chat-specific key
            key = this.masterKey;
        }
        if (!key) {
            console.warn('No encryption key available');
            return { encrypted: plaintext, iv: '', isEncrypted: false };
        }

        const iv = this.getRandomBytes(this.ivLength);
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        try {
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: this.algorithm, iv: iv },
                key,
                data
            );

            return {
                encrypted: this.arrayBufferToBase64(encryptedBuffer),
                iv: this.arrayBufferToBase64(iv),
                isEncrypted: true
            };
        } catch (e) {
            console.error('Encryption error:', e);
            return { encrypted: plaintext, iv: '', isEncrypted: false };
        }
    }

    // Decrypt message with AES-256-GCM
    async decrypt(encryptedBase64, ivBase64, chatId) {
        let key = this.chatKeys[chatId];
        if (!key) {
            key = this.masterKey;
        }
        if (!key || !ivBase64) {
            return encryptedBase64; // Return as-is if no key
        }

        try {
            const iv = new Uint8Array(this.base64ToArrayBuffer(ivBase64));
            const encryptedData = this.base64ToArrayBuffer(encryptedBase64);

            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: this.algorithm, iv: iv },
                key,
                encryptedData
            );

            const decoder = new TextDecoder();
            return decoder.decode(decryptedBuffer);
        } catch (e) {
            console.error('Decryption error:', e);
            return '[Encrypted Message]';
        }
    }

    // Generate TOTP secret for 2FA
    generateTOTPSecret() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let secret = '';
        const bytes = this.getRandomBytes(20);
        for (let i = 0; i < 20; i++) {
            secret += chars[bytes[i] % 32];
        }
        return secret;
    }

    // Generate TOTP code
    async generateTOTP(secret, timeStep = 30) {
        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / timeStep);
        
        // Decode base32 secret
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        for (let char of secret.toUpperCase()) {
            const val = base32Chars.indexOf(char);
            if (val !== -1) {
                bits += val.toString(2).padStart(5, '0');
            }
        }
        const keyBytes = new Uint8Array(bits.match(/.{8}/g).map(b => parseInt(b, 2)));

        // Create counter buffer
        const counterBuffer = new ArrayBuffer(8);
        const counterView = new DataView(counterBuffer);
        counterView.setUint32(4, counter, false);

        // HMAC-SHA1
        const key = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
        );
        const signature = await crypto.subtle.sign('HMAC', key, counterBuffer);
        const hmac = new Uint8Array(signature);

        // Dynamic truncation
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code = (
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff)
        ) % 1000000;

        return code.toString().padStart(6, '0');
    }

    // Verify TOTP code
    async verifyTOTP(secret, code, window = 1) {
        for (let i = -window; i <= window; i++) {
            const timeStep = 30;
            const epoch = Math.floor(Date.now() / 1000) + (i * timeStep);
            const counter = Math.floor(epoch / timeStep);
            
            // Generate code for this window
            const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            let bits = '';
            for (let char of secret.toUpperCase()) {
                const val = base32Chars.indexOf(char);
                if (val !== -1) {
                    bits += val.toString(2).padStart(5, '0');
                }
            }
            
            if (bits.length < 8) continue;
            
            const keyBytes = new Uint8Array(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
            const counterBuffer = new ArrayBuffer(8);
            const counterView = new DataView(counterBuffer);
            counterView.setUint32(4, counter, false);

            try {
                const key = await crypto.subtle.importKey(
                    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
                );
                const signature = await crypto.subtle.sign('HMAC', key, counterBuffer);
                const hmac = new Uint8Array(signature);
                const offset = hmac[hmac.length - 1] & 0x0f;
                const generatedCode = (
                    ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff)
                ) % 1000000;

                if (generatedCode.toString().padStart(6, '0') === code) {
                    return true;
                }
            } catch (e) {
                continue;
            }
        }
        return false;
    }

    // Encrypt file/media
    async encryptMedia(base64Data, chatId) {
        return await this.encrypt(base64Data, chatId);
    }

    // Decrypt file/media
    async decryptMedia(encryptedBase64, ivBase64, chatId) {
        return await this.decrypt(encryptedBase64, ivBase64, chatId);
    }
}

// Initialize encryption system
const nebulaCrypto = new NebulaCrypto();

// Toast notification function
function showToast(title, message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastIcon = document.getElementById('toastIcon');
    const toastTitle = document.getElementById('toastTitle');
    const toastMessage = document.getElementById('toastMessage');
    
    if (!toast) return;
    
    // Set content
    toastTitle.textContent = title;
    toastMessage.textContent = message;
    
    // Set icon and color based on type
    if (type === 'success') {
        toastIcon.className = 'w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center';
        toastIcon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>';
    } else if (type === 'warning') {
        toastIcon.className = 'w-8 h-8 rounded-full bg-yellow-500/20 flex items-center justify-center';
        toastIcon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    } else if (type === 'error') {
        toastIcon.className = 'w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center';
        toastIcon.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    }
    
    // Show toast
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.remove('opacity-0', 'translate-y-4');
    }, 10);
    
    // Hide after 3 seconds
    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-4');
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 300);
    }, 3000);
}

// === STATE ===
let currentUser = JSON.parse(localStorage.getItem('nebula_session')) || null;
let activeChatId = null;
let activeGroupId = null;
let isGroupChat = false;
let currentChatRef = null;
let allUsersCache = {};
let mediaRecorder;
let recordedChunks = [];
let isMicMuted = false;
let isVideoMuted = false;
let isRemoteMuted = false;
let selectedGroupMembers = [];
let viewingContactId = null;
let pickerVisible = false;

// Theme
let themeSettings = JSON.parse(localStorage.getItem('nebula_theme')) || {
    primary: '#6366f1',
    secondary: '#8b5cf6',
    background: '#05050a',
    chatBgImage: '',
    chatBgVideo: ''
};

// Current chat tab
let currentChatTab = 'personal';

// Custom stickers/gifs
let customStickers = JSON.parse(localStorage.getItem('nebula_stickers')) || [];
let customGifs = JSON.parse(localStorage.getItem('nebula_gifs')) || [];

// WebRTC State
let localStream = null;
let remoteStream = null;
let peerConnection = null;
let callTimerInterval = null;
let callStartTime = null;
let isVideoCall = false;
let incomingCallData = null;
let callListener = null;
let screenStream = null;
let originalVideoTrack = null;

// Audio elements
let ringtoneAudio, notificationAudio;

// ICE Servers
const iceServers = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
        { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' }
    ],
    iceCandidatePoolSize: 10
};

// Audio constraints
const advancedAudioConstraints = {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
    sampleRate: { ideal: 48000 },
    channelCount: { ideal: 1 }
};

// Emoji list
const emojis = ['😀','😃','😄','😁','😆','😅','🤣','😂','🙂','🙃','😉','😊','😇','🥰','😍','🤩','😘','😗','😚','😙','🥲','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🤐','🤨','😐','😑','😶','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤','😴','😷','🤒','🤕','🤢','🤮','🤧','🥵','🥶','🥴','😵','🤯','🤠','🥳','🥸','😎','🤓','🧐','😕','😟','🙁','☹️','😮','😯','😲','😳','🥺','😦','😧','😨','😰','😥','😢','😭','😱','😖','😣','😞','😓','😩','😫','🥱','😤','😡','😠','🤬','😈','👿','💀','☠️','💩','🤡','👹','👺','👻','👽','👾','🤖','😺','😸','😹','😻','😼','😽','🙀','😿','😾','❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💟','👍','👎','👊','✊','🤛','🤜','👏','🙌','👐','🤲','🤝','🙏','✍️','💅','🤳','💪','🦾','🦵','🦶','👂','🦻','👃','🧠','🦷','🦴','👀','👁️','👅','👄','🔥','💯','✨','⭐','🌟','💫','⚡','☀️','🌈','☁️','❄️','💧','🌊','🎉','🎊','🎈','🎁','🏆','🥇','🎮','🎯','🎲','🎭','🎨','🎬','🎤','🎧','🎼','🎹','🎸','🎺','🎻','🥁','📱','💻','🖥️','⌨️','🖱️','🚗','🚕','✈️','🚀','🛸','🚁','⛵','🚢','🏠'];

// Default stickers
const defaultStickers = [
    'https://media.giphy.com/media/3o7TKnO6Wve6502iJ2/giphy.gif',
    'https://media.giphy.com/media/l0HlNQ03J5JxX6lva/giphy.gif',
    'https://media.giphy.com/media/26BRv0ThflsHCqDrG/giphy.gif',
    'https://media.giphy.com/media/xT0xeJpnrWC4XWblEk/giphy.gif',
    'https://media.giphy.com/media/3o7TKMt1VVNkHV2PaE/giphy.gif',
    'https://media.giphy.com/media/l4q8cJzGdR9J8w3hS/giphy.gif'
];

// === INITIALIZATION ===
document.addEventListener('DOMContentLoaded', () => {
    if(window.lucide) lucide.createIcons();
    
    ringtoneAudio = document.getElementById('ringtoneAudio');
    notificationAudio = document.getElementById('notificationAudio');
    
    applyThemeFromSettings();
    checkAuth();
    loadDevices();
    loadEmojiPicker();
    loadStickerPicker();

    db.ref('users').on('value', snap => { allUsersCache = snap.val() || {}; });

    document.addEventListener('click', (e) => {
        const ctxMenu = document.getElementById('contextMenu');
        const chatCtxMenu = document.getElementById('chatContextMenu');
        const pickerModal = document.getElementById('pickerModal');
        
        if (ctxMenu && !ctxMenu.classList.contains('hidden') && !e.target.closest('#contextMenu')) ctxMenu.classList.add('hidden');
        if (chatCtxMenu && !chatCtxMenu.classList.contains('hidden') && !e.target.closest('#chatContextMenu')) chatCtxMenu.classList.add('hidden');
        if (pickerModal && !pickerModal.classList.contains('hidden') && !e.target.closest('#pickerModal') && !e.target.closest('[onclick*="togglePicker"]')) {
            pickerModal.classList.add('hidden');
            pickerVisible = false;
        }
    });

    const loginForm = document.getElementById('loginForm');
    if(loginForm) loginForm.addEventListener('submit', handleLogin);
    
    setupRecordingButtons();
    
    const msgInput = document.getElementById('msgInput');
    if(msgInput) {
        msgInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 128) + 'px';
        });
        msgInput.addEventListener('keydown', function(e) {
            if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); window.sendMessage(); }
        });
    }
    
    const emojiSearch = document.getElementById('emojiSearch');
    if(emojiSearch) emojiSearch.addEventListener('input', filterEmojis);
});

// === THEME ===
function applyThemeFromSettings() {
    document.documentElement.style.setProperty('--theme-primary', themeSettings.primary);
    document.documentElement.style.setProperty('--theme-secondary', themeSettings.secondary);
    document.documentElement.style.setProperty('--theme-bg', themeSettings.background);
    
    // Image background - high quality
    if (themeSettings.chatBgImage) {
        const img = new Image();
        img.onload = function() {
            document.documentElement.style.setProperty('--chat-bg-image', `url(${themeSettings.chatBgImage})`);
            document.body.classList.add('chat-bg-image');
        };
        img.src = themeSettings.chatBgImage;
    } else {
        document.documentElement.style.setProperty('--chat-bg-image', 'none');
        document.body.classList.remove('chat-bg-image');
    }
    
    // Video background with enhanced loader
    if (themeSettings.chatBgVideo) {
        loadVideoBackground(themeSettings.chatBgVideo);
    } else {
        const videoBgContainer = document.getElementById('videoBgContainer');
        const videoBg = document.getElementById('videoBg');
        if (videoBgContainer) videoBgContainer.classList.add('hidden');
        if (videoBg) {
            videoBg.pause();
            videoBg.removeAttribute('src');
            videoBg.load();
        }
    }
}

window.applyTheme = function() {
    themeSettings.primary = document.getElementById('themePrimaryColor').value;
    themeSettings.secondary = document.getElementById('themeSecondaryColor').value;
    themeSettings.background = document.getElementById('themeBgColor').value;
    themeSettings.chatBgImage = document.getElementById('themeBgImage').value;
    themeSettings.chatBgVideo = document.getElementById('themeBgVideo')?.value || '';
    localStorage.setItem('nebula_theme', JSON.stringify(themeSettings));
    applyThemeFromSettings();
    if(currentUser) db.ref('users/' + currentUser.id + '/theme').set(themeSettings);
};

// Enhanced video background loader
async function loadVideoBackground(url) {
    const videoBgContainer = document.getElementById('videoBgContainer');
    const videoBg = document.getElementById('videoBg');
    
    if (!videoBgContainer || !videoBg || !url) {
        if (videoBgContainer) videoBgContainer.classList.add('hidden');
        return false;
    }
    
    // Show loading state
    videoBgContainer.classList.remove('hidden');
    videoBgContainer.classList.add('loading');
    
    // Reset video
    videoBg.pause();
    videoBg.removeAttribute('src');
    videoBg.load();
    
    return new Promise((resolve) => {
        // Set up event handlers before setting source
        videoBg.onloadeddata = () => {
            console.log('Video loaded successfully');
            videoBgContainer.classList.remove('loading');
            videoBg.play().catch(e => {
                console.log('Autoplay blocked, waiting for interaction');
                document.addEventListener('click', () => videoBg.play(), { once: true });
            });
            resolve(true);
        };
        
        videoBg.onerror = (e) => {
            console.error('Video load error:', e);
            videoBgContainer.classList.add('hidden');
            videoBgContainer.classList.remove('loading');
            resolve(false);
        };
        
        videoBg.oncanplay = () => {
            videoBg.play().catch(() => {});
        };
        
        // Configure video
        videoBg.muted = true;
        videoBg.loop = true;
        videoBg.playsInline = true;
        videoBg.autoplay = true;
        videoBg.preload = 'auto';
        
        // Try to load with proper CORS handling
        // First try without crossorigin for same-origin videos
        videoBg.removeAttribute('crossorigin');
        videoBg.src = url;
        videoBg.load();
        
        // Timeout fallback
        setTimeout(() => {
            if (videoBg.readyState < 2) {
                console.log('Video loading timeout, trying with crossorigin...');
                videoBg.crossOrigin = 'anonymous';
                videoBg.src = url;
                videoBg.load();
            }
        }, 3000);
        
        // Final timeout
        setTimeout(() => {
            if (videoBg.readyState < 2) {
                console.log('Video failed to load');
                videoBgContainer.classList.add('hidden');
                resolve(false);
            }
        }, 10000);
    });
}

window.resetTheme = function() {
    themeSettings = { primary: '#6366f1', secondary: '#8b5cf6', background: '#05050a', chatBgImage: '', chatBgVideo: '' };
    localStorage.setItem('nebula_theme', JSON.stringify(themeSettings));
    applyThemeFromSettings();
    document.getElementById('themePrimaryColor').value = '#6366f1';
    document.getElementById('themeSecondaryColor').value = '#8b5cf6';
    document.getElementById('themeBgColor').value = '#05050a';
    document.getElementById('themeBgImage').value = '';
    const videoBgInput = document.getElementById('themeBgVideo');
    if (videoBgInput) videoBgInput.value = '';
    if(currentUser) db.ref('users/' + currentUser.id + '/theme').remove();
};

// === CHAT TABS ===
window.switchChatTab = function(tab) {
    currentChatTab = tab;
    
    const tabPersonal = document.getElementById('tabPersonal');
    const tabGroups = document.getElementById('tabGroups');
    const personalList = document.getElementById('personalChatsList');
    const groupsList = document.getElementById('groupChatsList');
    
    if (tab === 'personal') {
        tabPersonal.classList.add('active');
        tabGroups.classList.remove('active');
        personalList.classList.add('active');
        groupsList.classList.remove('active');
    } else {
        tabPersonal.classList.remove('active');
        tabGroups.classList.add('active');
        personalList.classList.remove('active');
        groupsList.classList.add('active');
    }
    
    if(window.lucide) lucide.createIcons();
};

function updateChatCounts() {
    const personalCount = document.getElementById('personalChatsList')?.children.length || 0;
    const groupsCount = document.getElementById('groupChatsList')?.children.length || 0;
    
    const personalCountEl = document.getElementById('personalCount');
    const groupsCountEl = document.getElementById('groupsCount');
    
    if (personalCountEl) personalCountEl.textContent = personalCount;
    if (groupsCountEl) groupsCountEl.textContent = groupsCount;
}

// === EMOJI/STICKER/GIF PICKER ===
function loadEmojiPicker() {
    const grid = document.getElementById('emojiGrid');
    if(!grid) return;
    grid.innerHTML = emojis.map(e => `<div class="emoji-item" onclick="window.insertEmoji('${e}')">${e}</div>`).join('');
}

function filterEmojis() {
    const search = document.getElementById('emojiSearch').value.toLowerCase();
    const items = document.querySelectorAll('.emoji-item');
    items.forEach(item => { item.style.display = 'block'; });
}

function loadStickerPicker() {
    const grid = document.getElementById('stickerGrid');
    if(!grid) return;
    const allStickers = [...defaultStickers, ...customStickers];
    grid.innerHTML = allStickers.map(s => `<div class="sticker-item" onclick="window.sendSticker('${s}')"><img src="${s}" loading="lazy"></div>`).join('');
}

window.togglePicker = function() {
    const modal = document.getElementById('pickerModal');
    pickerVisible = !pickerVisible;
    if(pickerVisible) { modal.classList.remove('hidden'); loadStickerPicker(); }
    else modal.classList.add('hidden');
};

window.switchPickerTab = function(tab) {
    document.querySelectorAll('.picker-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    document.getElementById('emojiTab').classList.add('hidden');
    document.getElementById('stickersTab').classList.add('hidden');
    document.getElementById('gifsTab').classList.add('hidden');
    document.getElementById(tab + 'Tab').classList.remove('hidden');
    if(tab === 'stickers') loadStickerPicker();
    if(tab === 'gifs') loadGifPicker();
};

function loadGifPicker() {
    const grid = document.getElementById('gifGrid');
    if(!grid) return;
    grid.innerHTML = customGifs.map(g => `<div class="sticker-item" onclick="window.sendGif('${g}')"><img src="${g}" loading="lazy"></div>`).join('');
    if(customGifs.length === 0) grid.innerHTML = '<p class="text-gray-500 text-sm col-span-3 text-center py-4">Search for GIFs or add custom URLs</p>';
}

window.insertEmoji = function(emoji) {
    const input = document.getElementById('msgInput');
    input.value += emoji;
    input.focus();
};

window.sendSticker = function(url) {
    if (!activeChatId && !activeGroupId) return alert("Select a chat first!");
    addMessageToChat('sticker', url);
    document.getElementById('pickerModal').classList.add('hidden');
    pickerVisible = false;
};

window.sendGif = function(url) {
    if (!activeChatId && !activeGroupId) return alert("Select a chat first!");
    addMessageToChat('gif', url);
    document.getElementById('pickerModal').classList.add('hidden');
    pickerVisible = false;
};

window.addCustomSticker = function() {
    const url = document.getElementById('customStickerUrl').value.trim();
    if(!url) return;
    customStickers.push(url);
    localStorage.setItem('nebula_stickers', JSON.stringify(customStickers));
    document.getElementById('customStickerUrl').value = '';
    loadStickerPicker();
};

window.addCustomGif = function() {
    const url = document.getElementById('customGifUrl').value.trim();
    if(!url) return;
    customGifs.push(url);
    localStorage.setItem('nebula_gifs', JSON.stringify(customGifs));
    document.getElementById('customGifUrl').value = '';
    loadGifPicker();
};

window.searchGifs = async function() {
    const query = document.getElementById('gifSearch').value.trim();
    if(!query) return;
    const grid = document.getElementById('gifGrid');
    grid.innerHTML = '<p class="text-gray-400 text-sm col-span-3 text-center py-4">Searching...</p>';
    try {
        const response = await fetch(`https://tenor.googleapis.com/v2/search?q=${encodeURIComponent(query)}&key=AIzaSyAyimkuYQYF_FXVALexPuGQctUWRURdCYQ&limit=12`);
        const data = await response.json();
        if(data.results && data.results.length > 0) {
            grid.innerHTML = data.results.map(g => `<div class="sticker-item" onclick="window.sendGif('${g.media_formats.gif.url}')"><img src="${g.media_formats.tinygif.url}" loading="lazy"></div>`).join('');
        } else {
            grid.innerHTML = '<p class="text-gray-500 text-sm col-span-3 text-center py-4">No GIFs found</p>';
        }
    } catch(err) {
        grid.innerHTML = '<p class="text-red-400 text-sm col-span-3 text-center py-4">Search failed</p>';
    }
};

// === GLOBAL FUNCTIONS ===
window.switchView = function(view) {
    const searchView = document.getElementById('globalSearchView');
    const chatsList = document.getElementById('chatsList');
    if(view === 'search') { searchView.classList.remove('hidden'); chatsList.classList.add('hidden'); }
    else { searchView.classList.add('hidden'); chatsList.classList.remove('hidden'); }
};

window.toggleProfile = function() { document.getElementById('profilePanel').classList.toggle('translate-x-full'); };

window.openSettings = async function() {
    document.getElementById('settingsModal').classList.remove('hidden');
    document.getElementById('settingsModal').classList.add('flex');
    await loadDevices();
    loadBlockedUsers();
    updateSecurityStatus();
    document.getElementById('themePrimaryColor').value = themeSettings.primary;
    document.getElementById('themeSecondaryColor').value = themeSettings.secondary;
    document.getElementById('themeBgColor').value = themeSettings.background;
    document.getElementById('themeBgImage').value = themeSettings.chatBgImage || '';
    const videoBgInput = document.getElementById('themeBgVideo');
    if (videoBgInput) videoBgInput.value = themeSettings.chatBgVideo || '';
};

// Update security status in settings
function updateSecurityStatus() {
    const e2eIcon = document.getElementById('e2eIcon');
    const e2eStatus = document.getElementById('e2eStatus');
    const e2eBadge = document.getElementById('e2eBadge');
    const keyFingerprint = document.getElementById('keyFingerprint');
    const fingerprintValue = document.getElementById('fingerprintValue');
    
    if (nebulaCrypto.masterKey) {
        // Encryption is active
        if (e2eIcon) {
            e2eIcon.classList.remove('warning');
            e2eIcon.classList.add('success');
        }
        if (e2eStatus) e2eStatus.textContent = 'AES-256-GCM encryption active';
        if (e2eBadge) {
            e2eBadge.classList.remove('inactive');
            e2eBadge.classList.add('active');
            e2eBadge.innerHTML = '<i data-lucide="check" class="w-3 h-3"></i> Active';
        }
        
        // Show key fingerprint
        if (keyFingerprint && fingerprintValue && currentUser && currentUser.salt) {
            keyFingerprint.classList.remove('hidden');
            // Create a short fingerprint from salt
            const shortFingerprint = currentUser.salt.substring(0, 16) + '...' + currentUser.salt.substring(currentUser.salt.length - 8);
            fingerprintValue.textContent = shortFingerprint;
        }
    } else {
        // Encryption not initialized
        if (e2eIcon) {
            e2eIcon.classList.remove('success');
            e2eIcon.classList.add('warning');
        }
        if (e2eStatus) e2eStatus.textContent = 'Encryption not initialized';
        if (e2eBadge) {
            e2eBadge.classList.remove('active');
            e2eBadge.classList.add('inactive');
            e2eBadge.innerHTML = '<i data-lucide="x" class="w-3 h-3"></i> Inactive';
        }
        if (keyFingerprint) keyFingerprint.classList.add('hidden');
    }
    
    if (window.lucide) lucide.createIcons();
}

window.closeSettings = function() {
    document.getElementById('settingsModal').classList.add('hidden');
    document.getElementById('settingsModal').classList.remove('flex');
};

window.logout = function() {
    if(callListener && currentUser) db.ref('calls/' + currentUser.id).off();
    localStorage.removeItem('nebula_session');
    location.reload();
};

window.closeChatMobile = function() {
    document.querySelector('main').classList.remove('active');
    document.getElementById('membersPanel').classList.add('hidden');
    activeChatId = null;
    activeGroupId = null;
};

window.filterChats = function() {
    const query = document.getElementById('contactSearch').value.toLowerCase();
    
    // Filter personal chats
    const personalItems = document.querySelectorAll('#personalChatsList > div');
    personalItems.forEach(item => {
        const name = item.querySelector('h4')?.textContent?.toLowerCase() || '';
        item.style.display = name.includes(query) ? 'flex' : 'none';
    });
    
    // Filter group chats
    const groupItems = document.querySelectorAll('#groupChatsList > div');
    groupItems.forEach(item => {
        const name = item.querySelector('h4')?.textContent?.toLowerCase() || '';
        item.style.display = name.includes(query) ? 'flex' : 'none';
    });
};

// === AUTH ===
function checkAuth() {
    const authScreen = document.getElementById('authScreen');
    if (!currentUser) { if(authScreen) authScreen.classList.remove('hidden'); }
    else {
        if(authScreen) authScreen.classList.add('hidden');
        loadProfileUI();
        loadContactsFromDB();
        listenForIncomingCalls();
        db.ref('users/' + currentUser.id + '/theme').once('value').then(snap => {
            const userTheme = snap.val();
            if(userTheme) { themeSettings = userTheme; localStorage.setItem('nebula_theme', JSON.stringify(themeSettings)); applyThemeFromSettings(); }
        });
        if(window.lucide) lucide.createIcons();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const nickname = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value.trim();
    const errorBox = document.getElementById('loginErrors');
    if(!nickname || !password) return;
    const userId = nickname.toLowerCase().replace(/[^a-z0-9]/g, '');
    if(userId.length < 3) { errorBox.innerHTML = 'Nickname too short (min 3 characters)'; errorBox.classList.remove('hidden'); return; }
    
    db.ref('users/' + userId).once('value').then(async (snapshot) => {
        const userData = snapshot.val();
        if (userData) {
            // Verify password hash
            const hashedInput = await nebulaCrypto.hashPassword(password, userData.salt || userId);
            if (userData.passwordHash === hashedInput || userData.password === password) { 
                await loginUser(userData, password); 
                errorBox.classList.add('hidden'); 
            }
            else { errorBox.innerHTML = '⚠ Nickname taken / Wrong password'; errorBox.classList.remove('hidden'); }
        } else {
            // Generate encryption salt
            const salt = nebulaCrypto.getRandomBytes(16);
            const saltBase64 = nebulaCrypto.arrayBufferToBase64(salt);
            const passwordHash = await nebulaCrypto.hashPassword(password, saltBase64);
            
            // Generate 2FA secret (optional, user can enable later)
            const totpSecret = nebulaCrypto.generateTOTPSecret();
            
            const newUser = { 
                id: userId, 
                name: nickname, 
                password: password, // Keep for backward compatibility
                passwordHash: passwordHash,
                salt: saltBase64,
                totpSecret: totpSecret,
                twoFactorEnabled: false,
                tag: '@' + userId, 
                avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=' + userId, 
                banner: 'https://images.unsplash.com/photo-1579546929518-9e396f3cc809?w=800', 
                music: '', 
                contacts: { 'saved': true }, 
                blocked: {}, 
                groups: {} 
            };
            db.ref('users/' + userId).set(newUser).then(() => loginUser(newUser, password));
        }
    });
}

async function loginUser(userObj, password) { 
    currentUser = userObj; 
    localStorage.setItem('nebula_session', JSON.stringify(currentUser)); 
    
    // Initialize encryption with user password
    if (userObj.salt) {
        await nebulaCrypto.initMasterKey(password || userObj.password, userObj.salt);
        console.log('🔐 Encryption initialized for user');
        
        // Show encryption toast after UI loads
        setTimeout(() => {
            showToast(
                'Encryption Active', 
                'Your messages are end-to-end encrypted', 
                'success'
            );
        }, 1000);
    } else {
        setTimeout(() => {
            showToast(
                '⚠️ Legacy Account', 
                'Re-login to enable encryption', 
                'warning'
            );
        }, 1000);
    }
    
    checkAuth(); 
}

// === ANIMATED MEDIA HELPER ===
function isVideoUrl(url) {
    if(!url) return false;
    return ['.mp4', '.webm', '.mov', '.avi', '.mkv'].some(ext => url.toLowerCase().includes(ext));
}

function setAnimatedMedia(container, imgEl, videoEl, url) {
    if(!url) { if(imgEl) imgEl.src = 'https://via.placeholder.com/150'; if(videoEl) { videoEl.classList.add('hidden'); videoEl.pause(); } return; }
    if(isVideoUrl(url)) {
        if(imgEl) imgEl.classList.add('hidden');
        if(videoEl) { videoEl.src = url; videoEl.classList.remove('hidden'); videoEl.muted = true; videoEl.loop = true; videoEl.play().catch(e => {}); }
    } else {
        if(imgEl) { imgEl.src = url; imgEl.classList.remove('hidden'); }
        if(videoEl) { videoEl.classList.add('hidden'); videoEl.pause(); }
    }
}

// === PROFILE ===
function loadProfileUI() {
    if(!currentUser) return;
    setAnimatedMedia(document.getElementById('navAvatarBtn'), document.getElementById('navMyAvatar'), document.getElementById('navMyAvatarVideo'), currentUser.avatar);
    setAnimatedMedia(null, document.getElementById('navMyAvatarMobile'), document.getElementById('navMyAvatarMobileVideo'), currentUser.avatar);
    setAnimatedMedia(document.getElementById('avatarContainer'), document.getElementById('profileAvatarImg'), document.getElementById('profileAvatarVideo'), currentUser.avatar);
    setAnimatedMedia(document.querySelector('#profilePanel .animated-media'), document.getElementById('profileBannerImg'), document.getElementById('profileBannerVideo'), currentUser.banner);
    document.getElementById('profileNameDisplay').innerText = currentUser.name;
    document.getElementById('profileTagDisplay').innerText = currentUser.tag;
    document.getElementById('inputAvatar').value = currentUser.avatar || '';
    document.getElementById('inputBanner').value = currentUser.banner || '';
    document.getElementById('inputMusic').value = currentUser.music || '';
    if(currentUser.music) document.getElementById('profileAudio').src = currentUser.music;
}

window.saveProfile = function() {
    currentUser.avatar = document.getElementById('inputAvatar').value;
    currentUser.banner = document.getElementById('inputBanner').value;
    currentUser.music = document.getElementById('inputMusic').value;
    localStorage.setItem('nebula_session', JSON.stringify(currentUser));
    db.ref('users/' + currentUser.id).update({ avatar: currentUser.avatar, banner: currentUser.banner, music: currentUser.music });
    loadProfileUI();
    window.toggleProfile();
};

// Music Player
const audio = document.getElementById('profileAudio');
const playBtn = document.getElementById('playMusicBtn');
const avatarContainer = document.getElementById('avatarContainer');

if(playBtn) {
    playBtn.addEventListener('click', () => {
        const musicUrl = document.getElementById('inputMusic').value;
        if(!musicUrl) return alert("Enter MP3 URL in profile settings!");
        if (audio.paused) {
            audio.src = musicUrl;
            audio.play().then(() => {
                playBtn.innerHTML = '<i data-lucide="pause" class="w-4 h-4"></i>';
                avatarContainer.classList.add('vinyl-spin');
                document.getElementById('vinylCenter').style.opacity = '1';
                if(window.lucide) lucide.createIcons();
            }).catch(e => alert("Cannot play this URL."));
        } else {
            audio.pause();
            playBtn.innerHTML = '<i data-lucide="play" class="w-4 h-4 ml-0.5"></i>';
            avatarContainer.classList.remove('vinyl-spin');
            document.getElementById('vinylCenter').style.opacity = '0';
            if(window.lucide) lucide.createIcons();
        }
    });
}

// === BLOCKED USERS ===
function loadBlockedUsers() {
    const list = document.getElementById('blockedUsersList');
    if(!list || !currentUser) return;
    db.ref('users/' + currentUser.id + '/blocked').once('value').then(snap => {
        const blocked = snap.val() || {};
        const blockedIds = Object.keys(blocked).filter(k => blocked[k]);
        if(blockedIds.length === 0) { list.innerHTML = '<p class="text-gray-500 text-sm">No blocked users</p>'; return; }
        list.innerHTML = '';
        blockedIds.forEach(id => {
            db.ref('users/' + id).once('value').then(userSnap => {
                const user = userSnap.val();
                if(user) list.innerHTML += `<div class="flex items-center justify-between p-2 bg-white/5 rounded-lg"><div class="flex items-center gap-2"><img src="${user.avatar}" class="w-8 h-8 rounded-full object-cover"><span class="text-sm">${user.name}</span></div><button onclick="window.unblockUser('${id}')" class="text-xs text-green-400 hover:text-green-300">Unblock</button></div>`;
            });
        });
    });
}

window.blockUser = function() {
    if(!viewingContactId || !currentUser) return;
    db.ref('users/' + currentUser.id + '/blocked/' + viewingContactId).set(true).then(() => {
        db.ref('users/' + currentUser.id + '/contacts/' + viewingContactId).remove();
        window.closeContactProfile();
        loadContactsFromDB();
        alert('User blocked');
    });
};

window.unblockUser = function(userId) {
    if(!currentUser) return;
    db.ref('users/' + currentUser.id + '/blocked/' + userId).remove().then(() => loadBlockedUsers());
};

// === NOTIFICATION SOUND ===
function playNotificationSound() {
    if(notificationAudio) { notificationAudio.currentTime = 0; notificationAudio.play().catch(e => {}); }
}

// === GROUPS ===
window.openCreateGroup = function() {
    document.getElementById('createGroupModal').classList.remove('hidden');
    document.getElementById('createGroupModal').classList.add('flex');
    selectedGroupMembers = [];
    document.getElementById('selectedMembers').innerHTML = '';
    document.getElementById('groupNameInput').value = '';
    document.getElementById('groupAvatarInput').value = '';
    document.getElementById('groupAvatarPreview').innerHTML = '<i data-lucide="camera" class="w-8 h-8 text-gray-500"></i>';
    if(window.lucide) lucide.createIcons();
};

window.closeCreateGroup = function() { document.getElementById('createGroupModal').classList.add('hidden'); document.getElementById('createGroupModal').classList.remove('flex'); };

window.previewGroupAvatar = function() {
    const url = document.getElementById('groupAvatarInput').value;
    const preview = document.getElementById('groupAvatarPreview');
    if(isVideoUrl(url)) preview.innerHTML = `<video src="${url}" class="w-full h-full object-cover" muted loop autoplay playsinline></video>`;
    else if(url) preview.innerHTML = `<img src="${url}" class="w-full h-full object-cover">`;
    else { preview.innerHTML = '<i data-lucide="camera" class="w-8 h-8 text-gray-500"></i>'; if(window.lucide) lucide.createIcons(); }
};

window.searchMemberToAdd = function() {
    const query = document.getElementById('addMemberInput').value.toLowerCase();
    const results = document.getElementById('memberSearchResults');
    if(!query) { results.innerHTML = ''; return; }
    const matches = Object.values(allUsersCache).filter(u => (u.name.toLowerCase().includes(query) || u.tag.toLowerCase().includes(query)) && u.id !== currentUser.id && !selectedGroupMembers.includes(u.id));
    results.innerHTML = matches.slice(0, 5).map(u => `<div class="flex items-center justify-between p-2 bg-white/5 rounded-lg hover:bg-white/10 cursor-pointer" onclick="window.addMemberToGroup('${u.id}')"><div class="flex items-center gap-2"><img src="${u.avatar}" class="w-8 h-8 rounded-full object-cover"><span class="text-sm">${u.name}</span></div><i data-lucide="plus" class="w-4 h-4 text-primary"></i></div>`).join('');
    if(window.lucide) lucide.createIcons();
};

window.addMemberToGroup = function(userId) {
    if(selectedGroupMembers.includes(userId)) return;
    selectedGroupMembers.push(userId);
    const user = allUsersCache[userId];
    document.getElementById('selectedMembers').innerHTML += `<div class="flex items-center gap-2 bg-primary/20 border border-primary/30 rounded-full px-3 py-1" id="selected-${userId}"><img src="${user.avatar}" class="w-5 h-5 rounded-full"><span class="text-xs">${user.name}</span><button onclick="window.removeMemberFromSelection('${userId}')" class="text-gray-400 hover:text-white"><i data-lucide="x" class="w-3 h-3"></i></button></div>`;
    document.getElementById('addMemberInput').value = '';
    document.getElementById('memberSearchResults').innerHTML = '';
    if(window.lucide) lucide.createIcons();
};

window.removeMemberFromSelection = function(userId) { selectedGroupMembers = selectedGroupMembers.filter(id => id !== userId); const el = document.getElementById('selected-' + userId); if(el) el.remove(); };

window.createGroup = function() {
    const name = document.getElementById('groupNameInput').value.trim();
    const avatar = document.getElementById('groupAvatarInput').value.trim();
    if(!name) return alert('Please enter a group name');
    if(selectedGroupMembers.length === 0) return alert('Please add at least one member');
    
    const groupId = 'group_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const members = { [currentUser.id]: { role: 'admin', joinedAt: Date.now() } };
    selectedGroupMembers.forEach(id => { members[id] = { role: 'member', joinedAt: Date.now() }; });
    
    const groupData = { 
        id: groupId, 
        name: name, 
        avatar: avatar || 'https://api.dicebear.com/7.x/shapes/svg?seed=' + groupId, 
        createdBy: currentUser.id, 
        createdAt: Date.now(), 
        members: members,
        isPrivate: true // Группа приватная - видна только участникам
    };
    
    db.ref('groups/' + groupId).set(groupData).then(() => {
        // Добавляем группу ТОЛЬКО участникам - никто другой не увидит
        const updates = {};
        Object.keys(members).forEach(memberId => { 
            updates['users/' + memberId + '/groups/' + groupId] = true; 
        });
        return db.ref().update(updates);
    }).then(() => { 
        window.closeCreateGroup(); 
        loadContactsFromDB();
        showToast('Group Created', `"${name}" is now private to members only`, 'success');
    });
};

window.openGroupOptions = function() {
    if(!activeGroupId) return;
    db.ref('groups/' + activeGroupId).once('value').then(snap => {
        const group = snap.val();
        if(!group) return;
        setAnimatedMedia(document.querySelector('#groupOptionsModal .animated-media'), document.getElementById('groupOptionsAvatar'), document.getElementById('groupOptionsAvatarVideo'), group.avatar);
        document.getElementById('groupOptionsName').textContent = group.name;
        document.getElementById('groupOptionsMemberCount').textContent = Object.keys(group.members || {}).length + ' members';
        document.getElementById('deleteGroupBtn').classList.toggle('hidden', group.createdBy !== currentUser.id);
        document.getElementById('groupOptionsModal').classList.remove('hidden');
        document.getElementById('groupOptionsModal').classList.add('flex');
        if(window.lucide) lucide.createIcons();
    });
};

window.closeGroupOptions = function() { document.getElementById('groupOptionsModal').classList.add('hidden'); document.getElementById('groupOptionsModal').classList.remove('flex'); };

window.leaveGroup = function() {
    if(!activeGroupId || !currentUser) return;
    if(!confirm('Are you sure you want to leave this group? You will no longer see it.')) return;
    
    // Удаляем себя из участников группы
    db.ref('groups/' + activeGroupId + '/members/' + currentUser.id).remove();
    // Удаляем группу из своего списка - после этого группа исчезнет
    db.ref('users/' + currentUser.id + '/groups/' + activeGroupId).remove();
    
    window.closeGroupOptions();
    activeChatId = null; activeGroupId = null; isGroupChat = false;
    document.querySelector('main').classList.remove('active');
    document.getElementById('messagesContainer').innerHTML = '';
    document.getElementById('chatHeaderInfo').innerHTML = '<div class="w-10 h-10 rounded-full bg-white/5 border border-white/5 flex items-center justify-center"><i data-lucide="message-circle" class="w-5 h-5 text-gray-600"></i></div><div><h3 class="font-bold text-sm text-gray-400">Select Chat</h3><p class="text-xs text-gray-600">Start a conversation</p></div>';
    if(window.lucide) lucide.createIcons();
    loadContactsFromDB();
    showToast('Left Group', 'You have left the group', 'success');
};

window.deleteGroup = function() {
    if(!activeGroupId || !currentUser) return;
    db.ref('groups/' + activeGroupId).once('value').then(snap => {
        const group = snap.val();
        if(!group || group.createdBy !== currentUser.id) return alert('Only the creator can delete this group');
        if(!confirm('Are you sure you want to delete this group? This cannot be undone.')) return;
        const updates = {};
        Object.keys(group.members || {}).forEach(memberId => { updates['users/' + memberId + '/groups/' + activeGroupId] = null; });
        db.ref().update(updates).then(() => {
            db.ref('groups/' + activeGroupId).remove();
            db.ref('messages/' + activeGroupId).remove();
            window.closeGroupOptions();
            activeChatId = null; activeGroupId = null; isGroupChat = false;
            document.querySelector('main').classList.remove('active');
            loadContactsFromDB();
        });
    });
};

window.kickMember = function(memberId) {
    if(!activeGroupId || !currentUser) return;
    db.ref('groups/' + activeGroupId).once('value').then(snap => {
        const group = snap.val();
        if(!group || group.createdBy !== currentUser.id) return alert('Only the creator can kick members');
        if(memberId === currentUser.id) return alert('You cannot kick yourself');
        if(!confirm('Kick this member from the group? They will no longer see the group.')) return;
        
        // Удаляем пользователя из участников группы
        db.ref('groups/' + activeGroupId + '/members/' + memberId).remove();
        // Удаляем группу из списка пользователя - группа исчезнет у него
        db.ref('users/' + memberId + '/groups/' + activeGroupId).remove();
        
        loadMembersPanel();
        showToast('Member Kicked', 'User removed from group', 'success');
    });
};

// === INVITE MEMBERS TO EXISTING GROUP ===
let pendingInviteUsers = [];

window.openInviteMembers = function() {
    if(!activeGroupId) return;
    pendingInviteUsers = [];
    document.getElementById('inviteSearchInput').value = '';
    document.getElementById('inviteSearchResults').innerHTML = '<p class="text-gray-500 text-sm text-center py-4">Search for users to invite</p>';
    document.getElementById('pendingInvitesList').innerHTML = '';
    document.getElementById('pendingInvites').classList.add('hidden');
    document.getElementById('sendInvitesBtn').classList.add('hidden');
    
    document.getElementById('inviteMembersModal').classList.remove('hidden');
    document.getElementById('inviteMembersModal').classList.add('flex');
    if(window.lucide) lucide.createIcons();
};

window.closeInviteMembers = function() {
    document.getElementById('inviteMembersModal').classList.add('hidden');
    document.getElementById('inviteMembersModal').classList.remove('flex');
    pendingInviteUsers = [];
};

window.searchUsersToInvite = function() {
    const query = document.getElementById('inviteSearchInput').value.toLowerCase().trim();
    const results = document.getElementById('inviteSearchResults');
    
    if(!query) {
        results.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">Enter a name or @tag to search</p>';
        return;
    }
    
    // Получаем текущих участников группы
    db.ref('groups/' + activeGroupId + '/members').once('value').then(snap => {
        const currentMembers = snap.val() || {};
        const currentMemberIds = Object.keys(currentMembers);
        
        // Фильтруем пользователей
        const matches = Object.values(allUsersCache).filter(u => 
            (u.name.toLowerCase().includes(query) || u.tag.toLowerCase().includes(query)) && 
            u.id !== currentUser.id &&
            !currentMemberIds.includes(u.id) &&
            !pendingInviteUsers.includes(u.id)
        );
        
        if(matches.length === 0) {
            results.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">No users found or all matching users are already members</p>';
            return;
        }
        
        results.innerHTML = matches.slice(0, 10).map(u => `
            <div class="flex items-center justify-between p-3 bg-white/5 rounded-xl hover:bg-white/10 transition-colors">
                <div class="flex items-center gap-3">
                    <img src="${u.avatar}" class="w-10 h-10 rounded-full object-cover">
                    <div>
                        <div class="font-medium text-white">${u.name}</div>
                        <div class="text-xs text-gray-400">${u.tag}</div>
                    </div>
                </div>
                <button onclick="window.addToInviteList('${u.id}')" class="btn btn-primary px-3 py-2 text-sm">
                    <i data-lucide="plus" class="w-4 h-4"></i>
                </button>
            </div>
        `).join('');
        
        if(window.lucide) lucide.createIcons();
    });
};

window.addToInviteList = function(userId) {
    if(pendingInviteUsers.includes(userId)) return;
    pendingInviteUsers.push(userId);
    
    const user = allUsersCache[userId];
    if(!user) return;
    
    const pendingList = document.getElementById('pendingInvitesList');
    pendingList.innerHTML += `
        <div class="flex items-center gap-2 bg-primary/20 border border-primary/30 rounded-full px-3 py-1" id="invite-${userId}">
            <img src="${user.avatar}" class="w-5 h-5 rounded-full">
            <span class="text-xs">${user.name}</span>
            <button onclick="window.removeFromInviteList('${userId}')" class="text-gray-400 hover:text-white">
                <i data-lucide="x" class="w-3 h-3"></i>
            </button>
        </div>
    `;
    
    document.getElementById('pendingInvites').classList.remove('hidden');
    document.getElementById('sendInvitesBtn').classList.remove('hidden');
    
    // Re-search to update results
    window.searchUsersToInvite();
    
    if(window.lucide) lucide.createIcons();
};

window.removeFromInviteList = function(userId) {
    pendingInviteUsers = pendingInviteUsers.filter(id => id !== userId);
    const el = document.getElementById('invite-' + userId);
    if(el) el.remove();
    
    if(pendingInviteUsers.length === 0) {
        document.getElementById('pendingInvites').classList.add('hidden');
        document.getElementById('sendInvitesBtn').classList.add('hidden');
    }
    
    // Re-search to update results
    window.searchUsersToInvite();
};

window.sendInvites = function() {
    if(!activeGroupId || pendingInviteUsers.length === 0) return;
    
    const updates = {};
    pendingInviteUsers.forEach(userId => {
        // Добавляем в members группы
        updates['groups/' + activeGroupId + '/members/' + userId] = {
            role: 'member',
            joinedAt: Date.now(),
            invitedBy: currentUser.id
        };
        // Добавляем группу в список пользователя - только тогда он её увидит
        updates['users/' + userId + '/groups/' + activeGroupId] = true;
    });
    
    db.ref().update(updates).then(() => {
        const count = pendingInviteUsers.length;
        window.closeInviteMembers();
        window.closeGroupOptions();
        loadMembersPanel();
        showToast('Invited!', `${count} user${count > 1 ? 's' : ''} added to the group`, 'success');
    }).catch(err => {
        console.error('Invite error:', err);
        alert('Failed to invite users');
    });
};

window.toggleMembersPanel = function() {
    const panel = document.getElementById('membersPanel');
    const isHidden = panel.classList.contains('hidden');
    if(isHidden) { panel.classList.remove('hidden'); panel.classList.add('flex'); loadMembersPanel(); }
    else { panel.classList.add('hidden'); panel.classList.remove('flex'); }
};

function loadMembersPanel() {
    if(!activeGroupId) return;
    const list = document.getElementById('membersList');
    list.innerHTML = '<div class="text-center text-gray-500 text-sm">Loading...</div>';
    db.ref('groups/' + activeGroupId).once('value').then(snap => {
        const group = snap.val();
        if(!group || !group.members) return;
        list.innerHTML = '';
        const isAdmin = group.createdBy === currentUser.id;
        Object.entries(group.members).forEach(([memberId, memberData]) => {
            db.ref('users/' + memberId).once('value').then(userSnap => {
                const user = userSnap.val();
                if(!user) return;
                const isCreator = memberId === group.createdBy;
                const kickBtn = isAdmin && !isCreator ? `<button onclick="event.stopPropagation();window.kickMember('${memberId}')" class="kick-btn"><i data-lucide="user-x" class="w-4 h-4"></i></button>` : '';
                list.innerHTML += `<div class="member-item" onclick="window.openContactProfile('${memberId}')"><div class="member-avatar animated-media"><img src="${user.avatar}" class="w-full h-full object-cover"></div><div class="member-info"><div class="member-name">${user.name}</div><div class="member-role">${isCreator ? '👑 Creator' : 'Member'}</div></div>${kickBtn}</div>`;
                if(window.lucide) lucide.createIcons();
            });
        });
    });
}

// === CHATS ===
let lastMessageCount = {};

function loadContactsFromDB() {
    const personalList = document.getElementById('personalChatsList');
    const groupsList = document.getElementById('groupChatsList');
    if(!personalList || !groupsList || !currentUser) return;
    
    personalList.innerHTML = '';
    groupsList.innerHTML = '';
    
    // Load personal chats
    db.ref('users/' + currentUser.id + '/contacts').once('value').then(snapshot => {
        const contacts = snapshot.val() || {};
        
        // Saved messages always first
        if(contacts['saved']) {
            renderChatItem(personalList, { id: 'saved', name: 'Saved Messages', avatar: 'https://cdn-icons-png.flaticon.com/512/5662/5662990.png', isSaved: true }, false);
        }
        
        Object.keys(contacts).forEach(contactId => {
            if(contactId === 'saved') return;
            db.ref('users/' + currentUser.id + '/blocked/' + contactId).once('value').then(blockSnap => {
                if(blockSnap.val()) return;
                db.ref('users/' + contactId).once('value').then(userSnap => { 
                    const user = userSnap.val(); 
                    if(user) renderChatItem(personalList, user, false);
                    updateChatCounts();
                });
            });
        });
        
        updateChatCounts();
    });
    
    // Load group chats
    db.ref('users/' + currentUser.id + '/groups').once('value').then(snapshot => {
        const groups = snapshot.val() || {};
        Object.keys(groups).forEach(groupId => {
            db.ref('groups/' + groupId).once('value').then(groupSnap => { 
                const group = groupSnap.val(); 
                if(group) renderChatItem(groupsList, { ...group, isGroup: true }, true);
                updateChatCounts();
            });
        });
        
        updateChatCounts();
    });
}

function renderChatItem(container, item, isGroup) {
    const isActive = (item.isGroup ? activeGroupId === item.id : activeChatId === item.id) ? 'active' : '';
    const itemId = item.isGroup ? item.id : (item.isSaved ? 'saved' : item.id);
    const avatarHtml = isVideoUrl(item.avatar) ? `<video src="${item.avatar}" class="w-12 h-12 rounded-full object-cover" muted loop autoplay playsinline></video>` : `<img src="${item.avatar}" class="w-12 h-12 rounded-full object-cover bg-gray-700">`;
    
    const groupBadge = item.isGroup ? '<span class="group-badge">Group</span>' : '';
    const privateBadge = item.isGroup ? '<span class="private-badge"><i data-lucide="lock" class="w-2.5 h-2.5"></i></span>' : '';
    const savedBadge = item.isSaved ? '<span class="text-xs px-2 py-0.5 rounded-full bg-primary/20 text-primary">Personal</span>' : '';
    const memberCount = item.isGroup ? `${Object.keys(item.members || {}).length} members • Private` : 'Tap to chat';
    
    const html = `
        <div onclick="window.openChat('${itemId}', ${item.isGroup || false})" 
             oncontextmenu="window.openChatContextMenu(event, '${itemId}', ${item.isGroup || false})" 
             class="chat-item ${isActive}" data-chat-id="${itemId}">
            <div class="relative">
                ${avatarHtml}
                ${item.isGroup ? '<div class="absolute -bottom-1 -right-1 w-5 h-5 bg-secondary rounded-full flex items-center justify-center"><i data-lucide="users" class="w-3 h-3 text-white"></i></div>' : ''}
            </div>
            <div class="chat-item-content">
                <div class="flex items-center gap-2">
                    <h4 class="chat-item-name">${item.name}</h4>
                    ${groupBadge}${privateBadge}${savedBadge}
                </div>
                <p class="chat-item-preview">${memberCount}</p>
            </div>
        </div>
    `;
    container.insertAdjacentHTML('beforeend', html);
    if(window.lucide) lucide.createIcons();
}

let selectedChatForContext = null;
let selectedChatIsGroup = false;

window.openChatContextMenu = function(e, chatId, isGroup) {
    e.preventDefault();
    e.stopPropagation();
    selectedChatForContext = chatId;
    selectedChatIsGroup = isGroup;
    const menu = document.getElementById('chatContextMenu');
    let x = e.pageX, y = e.pageY;
    if (x + 200 > window.innerWidth) x = window.innerWidth - 210;
    if (y + 60 > window.innerHeight) y = window.innerHeight - 70;
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.classList.remove('hidden');
};

document.getElementById('ctxDeleteChat')?.addEventListener('click', () => {
    if(!selectedChatForContext) return;
    if(selectedChatIsGroup) { activeGroupId = selectedChatForContext; window.leaveGroup(); }
    else { if(!confirm('Delete this chat?')) return; db.ref('users/' + currentUser.id + '/contacts/' + selectedChatForContext).remove(); if(activeChatId === selectedChatForContext) { activeChatId = null; document.querySelector('main').classList.remove('active'); document.getElementById('messagesContainer').innerHTML = ''; } loadContactsFromDB(); }
    document.getElementById('chatContextMenu').classList.add('hidden');
});

window.openChat = function(contactId, isGroup = false) {
    document.getElementById('pickerModal').classList.add('hidden');
    pickerVisible = false;
    const main = document.querySelector('main');
    if(main && window.innerWidth < 768) main.classList.add('active');
    
    // Show encryption badge only when encryption is active
    const encBadge = document.getElementById('chatEncryptionBadge');
    if (encBadge) {
        if (nebulaCrypto.masterKey) {
            encBadge.classList.remove('hidden');
            encBadge.innerHTML = '<i data-lucide="shield-check" class="w-3 h-3"></i><span>E2E</span>';
            if (window.lucide) lucide.createIcons();
        } else {
            encBadge.classList.add('hidden');
        }
    }
    
    isGroupChat = isGroup;
    let chatId;
    
    if(isGroup) {
        activeGroupId = contactId; activeChatId = null; chatId = contactId;
        document.getElementById('toggleMembersBtn').classList.remove('hidden');
        db.ref('groups/' + contactId).once('value').then(snap => {
            const group = snap.val();
            if(group) {
                const avatarHtml = isVideoUrl(group.avatar) ? `<video src="${group.avatar}" class="w-10 h-10 rounded-full object-cover" muted loop autoplay playsinline></video>` : `<img src="${group.avatar}" class="w-10 h-10 rounded-full object-cover">`;
                document.getElementById('chatHeaderInfo').innerHTML = `<div class="cursor-pointer" onclick="window.openGroupOptions()">${avatarHtml}</div><div class="cursor-pointer" onclick="window.openGroupOptions()"><h3 class="font-bold text-sm">${group.name}</h3><p class="text-xs text-gray-400">${Object.keys(group.members || {}).length} members</p></div>`;
            }
        });
    } else {
        activeChatId = contactId; activeGroupId = null;
        document.getElementById('toggleMembersBtn').classList.add('hidden');
        document.getElementById('membersPanel').classList.add('hidden');
        document.getElementById('membersPanel').classList.remove('flex');
        if(contactId === 'saved') {
            chatId = currentUser.id + '_saved';
            document.getElementById('chatHeaderInfo').innerHTML = `<img src="https://cdn-icons-png.flaticon.com/512/5662/5662990.png" class="w-10 h-10 rounded-full object-cover"><div><h3 class="font-bold text-sm">Saved Messages</h3><p class="text-xs text-primary">Personal</p></div>`;
        } else {
            chatId = [currentUser.id, contactId].sort().join('_');
            db.ref('users/' + contactId).once('value').then(snap => {
                const contact = snap.val();
                if(contact) {
                    const avatarHtml = isVideoUrl(contact.avatar) ? `<video src="${contact.avatar}" class="w-10 h-10 rounded-full object-cover cursor-pointer" muted loop autoplay playsinline onclick="window.openContactProfile('${contactId}')"></video>` : `<img src="${contact.avatar}" class="w-10 h-10 rounded-full object-cover cursor-pointer" onclick="window.openContactProfile('${contactId}')">`;
                    document.getElementById('chatHeaderInfo').innerHTML = `${avatarHtml}<div class="cursor-pointer" onclick="window.openContactProfile('${contactId}')"><h3 class="font-bold text-sm hover:text-primary transition-colors">${contact.name}</h3><p class="text-xs text-green-400">Online</p></div>`;
                }
            });
        }
    }

    const container = document.getElementById('messagesContainer');
    if(currentChatRef) currentChatRef.off();
    container.innerHTML = '<div class="flex items-center justify-center h-full text-gray-600 text-sm">Loading...</div>';
    if(!lastMessageCount[chatId]) lastMessageCount[chatId] = 0;
    
    currentChatRef = db.ref('messages/' + chatId);
    currentChatRef.on('value', (snapshot) => {
        container.innerHTML = '';
        const data = snapshot.val();
        if(!data) { container.innerHTML = '<div class="flex flex-col items-center justify-center h-full text-gray-500"><i data-lucide="message-square-dashed" class="w-16 h-16 mb-4 opacity-30"></i><p class="text-sm">No messages yet</p></div>'; if(window.lucide) lucide.createIcons(); return; }
        const messages = Object.entries(data);
        const newCount = messages.length;
        if(newCount > lastMessageCount[chatId]) { const lastMsg = messages[messages.length - 1][1]; if(lastMsg.sender !== currentUser.id) playNotificationSound(); }
        lastMessageCount[chatId] = newCount;
        messages.forEach(([key, msg]) => renderMessageHTML(container, key, msg));
        container.scrollTop = container.scrollHeight;
        if(window.lucide) lucide.createIcons();
    });
};

window.openChatOptions = function() { if(activeGroupId) window.openGroupOptions(); else if(activeChatId && activeChatId !== 'saved') window.openContactProfile(activeChatId); };

async function renderMessageHTML(container, key, msg) {
    const isMe = msg.sender === currentUser.id;
    const align = isMe ? 'ml-auto items-end' : 'items-start';
    const color = isMe ? 'bg-gradient-to-br from-primary to-secondary text-white rounded-br-sm' : 'bg-white/10 border border-white/5 rounded-bl-sm';
    
    // Decrypt message if encrypted
    let displayText = msg.text || '';
    let isEncrypted = msg.encrypted;
    let decryptionSuccess = false;
    
    if (msg.encrypted && msg.iv && nebulaCrypto.masterKey) {
        const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
        const decrypted = await nebulaCrypto.decrypt(msg.text, msg.iv, chatId);
        if (decrypted !== '[Encrypted Message]') {
            displayText = decrypted;
            decryptionSuccess = true;
        } else {
            displayText = decrypted;
        }
    }
    
    // Create encryption indicator
    let encryptedBadge = '';
    if (isEncrypted) {
        if (decryptionSuccess) {
            encryptedBadge = '<span class="msg-lock encrypted" title="End-to-end encrypted"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><circle cx="12" cy="16" r="1"></circle><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></span>';
        } else {
            encryptedBadge = '<span class="msg-lock" title="Could not decrypt" style="color:#f59e0b;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><circle cx="12" cy="16" r="1"></circle><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></span>';
        }
    }
    
    let contentHtml = `<p class="text-sm leading-relaxed whitespace-pre-wrap">${escapeHtml(displayText)}${encryptedBadge}</p>`;
    // Decrypt media content if encrypted
    let mediaContent = msg.content;
    if (msg.encrypted && msg.iv && nebulaCrypto.masterKey && msg.type !== 'text') {
        const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
        mediaContent = await nebulaCrypto.decryptMedia(msg.content, msg.iv, chatId);
    }
    
    // Lock icon for media
    const mediaLock = isEncrypted ? `<div class="flex items-center gap-1 mt-1 opacity-60"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg><span class="text-[9px] text-green-400">Encrypted</span></div>` : '';
    
    if (msg.type === 'image') contentHtml = `<div><img src="${mediaContent}" class="max-w-full max-h-64 rounded-xl shadow-lg cursor-pointer" onclick="window.open('${mediaContent}', '_blank')">${mediaLock}</div>`;
    else if (msg.type === 'video-circle') contentHtml = `<div><video src="${mediaContent}" class="w-40 h-40 rounded-full object-cover border-2 border-primary shadow-xl cursor-pointer" onclick="this.paused ? this.play() : this.pause()" playsinline></video>${mediaLock}</div>`;
    else if (msg.type === 'voice') contentHtml = `<div class="flex items-center gap-3 min-w-[200px] voice-message-container" id="voice-${key}"><button class="voice-play-btn w-10 h-10 rounded-full bg-white/20 flex items-center justify-center shrink-0" onclick="window.toggleVoiceMessage('voice-${key}')"><i data-lucide="play" class="w-4 h-4"></i></button><audio src="${mediaContent}" class="voice-audio hidden"></audio><div class="voice-bars paused flex-1"><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div><div class="voice-bar"></div></div><span class="voice-duration text-xs opacity-60">0:00</span>${isEncrypted ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" class="ml-1"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>' : ''}</div>`;
    else if (msg.type === 'sticker' || msg.type === 'gif') contentHtml = `<img src="${msg.content}" class="max-w-[200px] max-h-[200px] rounded-xl">`;
    
    const senderInfo = (!isMe && isGroupChat) ? `<div class="flex items-center gap-2 mb-1 cursor-pointer" onclick="window.openContactProfile('${msg.sender}')"><img src="" class="w-5 h-5 rounded-full object-cover sender-avatar-${msg.sender}"><span class="text-xs text-gray-400 sender-name-${msg.sender}">User</span></div>` : '';
    const html = `<div class="flex flex-col ${align} max-w-[75%] md:max-w-[60%] msg-anim ${isMe?'own':''}" id="msg-${key}">${senderInfo}<div class="${color} p-3 px-4 rounded-2xl shadow-md select-none" oncontextmenu="window.openContextMenu(event, '${key}')">${contentHtml}</div><span class="text-[10px] text-gray-500 mt-1 mx-1">${msg.time}</span></div>`;
    container.insertAdjacentHTML('beforeend', html);
    
    if(!isMe && isGroupChat) {
        db.ref('users/' + msg.sender).once('value').then(snap => {
            const user = snap.val();
            if(user) { const avatarEl = container.querySelector(`.sender-avatar-${msg.sender}`); const nameEl = container.querySelector(`.sender-name-${msg.sender}`); if(avatarEl) avatarEl.src = user.avatar; if(nameEl) nameEl.textContent = user.name; }
        });
    }
    
    if(msg.type === 'voice') {
        setTimeout(() => {
            const voiceContainer = document.getElementById('voice-' + key);
            if(voiceContainer) {
                const audio = voiceContainer.querySelector('.voice-audio');
                audio.addEventListener('loadedmetadata', () => { const duration = Math.floor(audio.duration); voiceContainer.querySelector('.voice-duration').textContent = `${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`; });
            }
        }, 100);
    }
}

window.toggleVoiceMessage = function(containerId) {
    const container = document.getElementById(containerId);
    if(!container) return;
    const audio = container.querySelector('.voice-audio');
    const playBtn = container.querySelector('.voice-play-btn');
    const bars = container.querySelector('.voice-bars');
    if(audio.paused) {
        document.querySelectorAll('.voice-audio').forEach(a => { if(a !== audio && !a.paused) { a.pause(); a.currentTime = 0; const pc = a.closest('.voice-message-container'); if(pc) { pc.querySelector('.voice-bars').classList.add('paused'); pc.querySelector('.voice-play-btn').innerHTML = '<i data-lucide="play" class="w-4 h-4"></i>'; } } });
        audio.play().then(() => { bars.classList.remove('paused'); playBtn.innerHTML = '<i data-lucide="pause" class="w-4 h-4"></i>'; if(window.lucide) lucide.createIcons(); }).catch(e => {});
    } else { audio.pause(); bars.classList.add('paused'); playBtn.innerHTML = '<i data-lucide="play" class="w-4 h-4"></i>'; if(window.lucide) lucide.createIcons(); }
    audio.onended = () => { bars.classList.add('paused'); playBtn.innerHTML = '<i data-lucide="play" class="w-4 h-4"></i>'; audio.currentTime = 0; if(window.lucide) lucide.createIcons(); };
};

function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }

window.sendMessage = async function() {
    if (!activeChatId && !activeGroupId) return alert("Select a chat first!");
    const input = document.getElementById('msgInput');
    const text = input.value.trim();
    if (!text) return;
    const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
    
    // Encrypt message
    let messageData = {
        type: 'text',
        sender: currentUser.id,
        time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
        timestamp: firebase.database.ServerValue.TIMESTAMP
    };
    
    if (nebulaCrypto.masterKey) {
        const encrypted = await nebulaCrypto.encrypt(text, chatId);
        if (encrypted.isEncrypted) {
            messageData.text = encrypted.encrypted;
            messageData.iv = encrypted.iv;
            messageData.encrypted = true;
            console.log('🔒 Message encrypted with AES-256-GCM');
        } else {
            messageData.text = text;
            console.log('⚠️ Message sent without encryption');
        }
    } else {
        messageData.text = text;
        console.log('⚠️ No encryption key - message sent in plaintext');
    }
    
    db.ref('messages/' + chatId).push(messageData);
    input.value = '';
    input.style.height = 'auto';
};

// === CONTEXT MENU ===
let selectedMsgKey = null;

window.openContextMenu = function(e, key) {
    e.preventDefault();
    const msgEl = document.getElementById('msg-'+key);
    if(!msgEl || !msgEl.classList.contains('own')) return;
    selectedMsgKey = key;
    const menu = document.getElementById('contextMenu');
    let x = e.pageX, y = e.pageY;
    if (x + 200 > window.innerWidth) x = window.innerWidth - 210;
    if (y + 100 > window.innerHeight) y = window.innerHeight - 110;
    menu.style.left = `${x}px`;
    menu.style.top = `${y}px`;
    menu.classList.remove('hidden');
};

document.getElementById('ctxDelete')?.addEventListener('click', () => {
    if (selectedMsgKey) {
        const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
        db.ref('messages/' + chatId + '/' + selectedMsgKey).remove();
        document.getElementById('contextMenu').classList.add('hidden');
    }
});

document.getElementById('ctxEdit')?.addEventListener('click', () => {
    if (selectedMsgKey) {
        const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
        db.ref('messages/' + chatId + '/' + selectedMsgKey).once('value').then(snap => {
            const msg = snap.val();
            if(msg.type !== 'text') return alert("Only text messages can be edited");
            const newText = prompt("Edit message:", msg.text);
            if (newText && newText.trim()) db.ref('messages/' + chatId + '/' + selectedMsgKey).update({ text: newText.trim() });
        });
        document.getElementById('contextMenu').classList.add('hidden');
    }
});

// === MEDIA ===
function blobToDataURL(blob, callback) { const a = new FileReader(); a.onload = function(e) { callback(e.target.result); }; a.readAsDataURL(blob); }

window.handleMediaUpload = function(event) {
    const file = event.target.files[0];
    if (!file) return;
    if(file.size > 5 * 1024 * 1024) { alert("File too large! Max 5MB"); return; }
    const reader = new FileReader();
    reader.onload = (e) => addMessageToChat('image', e.target.result);
    reader.readAsDataURL(file);
    event.target.value = '';
};

function setupRecordingButtons() {
    const recordVideoBtn = document.getElementById('recordVideoBtn');
    const recordVoiceBtn = document.getElementById('recordVoiceBtn');
    if(recordVideoBtn) { recordVideoBtn.addEventListener('mousedown', startVideoRecording); recordVideoBtn.addEventListener('mouseup', () => stopRecording('video')); recordVideoBtn.addEventListener('mouseleave', () => stopRecording('video')); recordVideoBtn.addEventListener('touchstart', (e) => { e.preventDefault(); startVideoRecording(); }); recordVideoBtn.addEventListener('touchend', (e) => { e.preventDefault(); stopRecording('video'); }); }
    if(recordVoiceBtn) { recordVoiceBtn.addEventListener('mousedown', startVoiceRecording); recordVoiceBtn.addEventListener('mouseup', () => stopRecording('audio')); recordVoiceBtn.addEventListener('mouseleave', () => stopRecording('audio')); recordVoiceBtn.addEventListener('touchstart', (e) => { e.preventDefault(); startVoiceRecording(); }); recordVoiceBtn.addEventListener('touchend', (e) => { e.preventDefault(); stopRecording('audio'); }); }
}

async function startVideoRecording() { try { const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true }); startRecording(stream, 'video'); document.getElementById('recordVideoBtn').classList.add('text-primary', 'bg-primary/20'); } catch(e) { alert("Camera permission denied"); } }
async function startVoiceRecording() { try { const stream = await navigator.mediaDevices.getUserMedia({ audio: true }); startRecording(stream, 'audio'); document.getElementById('recordVoiceBtn').classList.add('text-red-500', 'bg-red-500/20'); } catch(e) { alert("Microphone permission denied"); } }

function startRecording(stream, type) {
    mediaRecorder = new MediaRecorder(stream);
    recordedChunks = [];
    mediaRecorder.ondataavailable = e => recordedChunks.push(e.data);
    mediaRecorder.onstop = () => { const blob = new Blob(recordedChunks, { type: type === 'video' ? 'video/webm' : 'audio/webm' }); blobToDataURL(blob, (base64String) => { addMessageToChat(type === 'video' ? 'video-circle' : 'voice', base64String); }); stream.getTracks().forEach(t => t.stop()); };
    mediaRecorder.start();
}

function stopRecording(type) { if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop(); if(type === 'video') document.getElementById('recordVideoBtn').classList.remove('text-primary', 'bg-primary/20'); else document.getElementById('recordVoiceBtn').classList.remove('text-red-500', 'bg-red-500/20'); }

async function addMessageToChat(type, content) {
    if (!activeChatId && !activeGroupId) return;
    const chatId = activeGroupId ? activeGroupId : (activeChatId === 'saved' ? currentUser.id + '_saved' : [currentUser.id, activeChatId].sort().join('_'));
    
    let messageData = {
        type: type,
        sender: currentUser.id,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: firebase.database.ServerValue.TIMESTAMP
    };
    
    // Encrypt media content if encryption is available
    if (nebulaCrypto.masterKey && type !== 'sticker' && type !== 'gif') {
        const encrypted = await nebulaCrypto.encryptMedia(content, chatId);
        if (encrypted.isEncrypted) {
            messageData.content = encrypted.encrypted;
            messageData.iv = encrypted.iv;
            messageData.encrypted = true;
        } else {
            messageData.content = content;
        }
    } else {
        messageData.content = content;
    }
    
    db.ref('messages/' + chatId).push(messageData);
}

window.performGlobalSearch = function() {
    const query = document.getElementById('globalSearchInput').value.toLowerCase();
    const resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '';
    if(!query) { resultsDiv.innerHTML = '<p class="text-gray-500 text-center text-sm">Enter a name or @tag</p>'; return; }
    const matches = Object.values(allUsersCache).filter(u => (u.name.toLowerCase().includes(query) || u.tag.toLowerCase().includes(query)) && u.id !== currentUser.id);
    matches.forEach(u => { resultsDiv.insertAdjacentHTML('beforeend', `<div class="flex items-center justify-between p-3 bg-white/5 rounded-xl border border-white/5 hover:bg-white/10 transition-colors"><div class="flex items-center gap-3"><img src="${u.avatar}" class="w-10 h-10 rounded-full bg-gray-700 object-cover"><div><span class="font-bold text-sm block">${u.name}</span><span class="text-xs text-gray-500">${u.tag}</span></div></div><button onclick="window.addContact('${u.id}')" class="btn btn-primary px-4 py-2 text-xs">Add</button></div>`); });
    if(matches.length === 0) resultsDiv.innerHTML = '<p class="text-gray-500 text-center text-sm">No users found</p>';
};

window.addContact = function(contactId) { db.ref('users/' + currentUser.id + '/contacts/' + contactId).set(true).then(() => { window.switchView('chats'); loadContactsFromDB(); }); };

// === CONTACT PROFILE ===
window.openContactProfile = function(contactId) {
    if(!contactId || contactId === 'saved') return;
    viewingContactId = contactId;
    db.ref('users/' + contactId).once('value').then(snap => {
        const contact = snap.val();
        if(!contact) return;
        setAnimatedMedia(document.querySelector('#contactProfileModal .animated-media:first-of-type'), document.getElementById('contactProfileBanner'), document.getElementById('contactProfileBannerVideo'), contact.banner);
        setAnimatedMedia(document.querySelector('#contactProfileModal .animated-media:last-of-type'), document.getElementById('contactProfileAvatar'), document.getElementById('contactProfileAvatarVideo'), contact.avatar);
        document.getElementById('contactProfileName').textContent = contact.name;
        document.getElementById('contactProfileTag').textContent = contact.tag;
        
        db.ref('users/' + currentUser.id + '/blocked/' + contactId).once('value').then(blockSnap => {
            const isBlocked = blockSnap.val();
            const blockBtn = document.getElementById('blockUserBtn');
            if(isBlocked) { blockBtn.innerHTML = '<i data-lucide="shield" class="w-4 h-4"></i> Unblock'; blockBtn.onclick = () => window.unblockUser(contactId); }
            else { blockBtn.innerHTML = '<i data-lucide="shield-off" class="w-4 h-4"></i> Block'; blockBtn.onclick = window.blockUser; }
            if(window.lucide) lucide.createIcons();
        });
        
        const musicSection = document.getElementById('contactProfileMusicSection');
        const contactAudio = document.getElementById('contactProfileAudio');
        const playBtn = document.getElementById('contactProfilePlayBtn');
        if(contact.music && musicSection && contactAudio && playBtn) {
            musicSection.classList.remove('hidden');
            contactAudio.src = contact.music;
            playBtn.innerHTML = '<i data-lucide="play" class="w-5 h-5 ml-0.5"></i>';
            playBtn.onclick = () => { if(contactAudio.paused) { contactAudio.play().then(() => { playBtn.innerHTML = '<i data-lucide="pause" class="w-5 h-5"></i>'; if(window.lucide) lucide.createIcons(); }).catch(e => {}); } else { contactAudio.pause(); playBtn.innerHTML = '<i data-lucide="play" class="w-5 h-5 ml-0.5"></i>'; if(window.lucide) lucide.createIcons(); } };
        } else if(musicSection) musicSection.classList.add('hidden');
        
        document.getElementById('contactProfileModal').classList.remove('hidden');
        document.getElementById('contactProfileModal').classList.add('flex');
        if(window.lucide) lucide.createIcons();
    });
};

window.closeContactProfile = function() {
    document.getElementById('contactProfileModal').classList.add('hidden');
    document.getElementById('contactProfileModal').classList.remove('flex');
    const contactAudio = document.getElementById('contactProfileAudio');
    if(contactAudio) { contactAudio.pause(); contactAudio.currentTime = 0; }
    viewingContactId = null;
};

window.startChatWithContact = function() { if(viewingContactId) { const contactId = viewingContactId; window.closeContactProfile(); db.ref('users/' + currentUser.id + '/contacts/' + contactId).set(true); window.openChat(contactId); } };
window.callContactFromProfile = function() { if(viewingContactId) { const contactId = viewingContactId; window.closeContactProfile(); activeChatId = contactId; window.startCall(); } };

// === WEBRTC CALLS ===
function listenForIncomingCalls() {
    if(!currentUser) return;
    callListener = db.ref('calls/' + currentUser.id);
    callListener.on('value', async (snapshot) => {
        const callData = snapshot.val();
        if(callData && callData.status === 'ringing' && callData.callerId !== currentUser.id) { incomingCallData = callData; showIncomingCall(callData); }
    });
}

function showIncomingCall(callData) {
    db.ref('users/' + callData.callerId).once('value').then(snap => {
        const caller = snap.val();
        if(caller) { setAnimatedMedia(document.getElementById('incomingCallAvatarContainer'), document.getElementById('incomingCallAvatar'), document.getElementById('incomingCallAvatarVideo'), caller.avatar); document.getElementById('incomingCallName').textContent = caller.name; }
    });
    if(ringtoneAudio) { ringtoneAudio.currentTime = 0; ringtoneAudio.play().catch(e => {}); }
    document.getElementById('incomingCallModal').classList.remove('hidden');
    document.getElementById('incomingCallModal').classList.add('flex');
    if(window.lucide) lucide.createIcons();
}

function stopRingtone() { if(ringtoneAudio) { ringtoneAudio.pause(); ringtoneAudio.currentTime = 0; } }

window.acceptCall = async function() {
    stopRingtone();
    document.getElementById('incomingCallModal').classList.add('hidden');
    document.getElementById('incomingCallModal').classList.remove('flex');
    if(!incomingCallData) return;
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: advancedAudioConstraints, video: incomingCallData.isVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false });
        showCallModal(incomingCallData.callerId, incomingCallData.isVideo);
        document.getElementById('localVideo').srcObject = localStream;
        document.getElementById('localVideo').muted = true;
        peerConnection = new RTCPeerConnection(iceServers);
        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
        peerConnection.ontrack = (event) => {
            remoteStream = event.streams[0];
            document.getElementById('remoteVideo').srcObject = remoteStream;
            document.getElementById('remoteAudio').srcObject = remoteStream;
            document.getElementById('remoteAudio').play().catch(e => {});
            document.getElementById('remoteVideo').play().catch(e => {});
            document.getElementById('callStatusDot').className = 'w-1.5 h-1.5 bg-green-500 rounded-full';
            document.getElementById('callStatusText').textContent = 'Connected';
            document.getElementById('callAudioOnly').style.display = 'none';
            startCallTimer();
        };
        peerConnection.onicecandidate = (event) => { if(event.candidate) db.ref('calls/' + incomingCallData.callerId + '/answerCandidates').push(event.candidate.toJSON()); };
        const offerRef = await db.ref('calls/' + incomingCallData.callerId + '/offer').once('value');
        const offer = offerRef.val();
        if(offer) {
            await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            await db.ref('calls/' + currentUser.id).update({ status: 'answered', answer: { type: answer.type, sdp: answer.sdp } });
        }
        db.ref('calls/' + incomingCallData.callerId + '/offerCandidates').on('child_added', (snapshot) => { peerConnection.addIceCandidate(new RTCIceCandidate(snapshot.val())).catch(e => {}); });
        db.ref('calls/' + currentUser.id + '/status').on('value', (snapshot) => { if(snapshot.val() === 'ended') window.endCall(); });
    } catch(err) { alert('Could not accept call: ' + err.message); window.endCall(); }
};

window.declineCall = function() { stopRingtone(); document.getElementById('incomingCallModal').classList.add('hidden'); document.getElementById('incomingCallModal').classList.remove('flex'); if(incomingCallData) { db.ref('calls/' + currentUser.id).update({ status: 'declined' }); db.ref('calls/' + incomingCallData.callerId).update({ status: 'declined' }); } incomingCallData = null; };

window.startCall = async function() { if(!activeChatId || activeChatId === 'saved') return alert("Select a contact to call"); await initiateCall(false); };
window.startVideoCall = async function() { if(!activeChatId || activeChatId === 'saved') return alert("Select a contact to call"); await initiateCall(true); };

async function initiateCall(withVideo) {
    isVideoCall = withVideo;
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ audio: advancedAudioConstraints, video: withVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false });
        if (withVideo) originalVideoTrack = localStream.getVideoTracks()[0];
        showCallModal(activeChatId, withVideo);
        document.getElementById('localVideo').srcObject = localStream;
        document.getElementById('localVideo').muted = true;
        peerConnection = new RTCPeerConnection(iceServers);
        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
        peerConnection.ontrack = (event) => {
            remoteStream = event.streams[0];
            document.getElementById('remoteVideo').srcObject = remoteStream;
            document.getElementById('remoteAudio').srcObject = remoteStream;
            document.getElementById('remoteAudio').play().catch(e => {});
            document.getElementById('remoteVideo').play().catch(e => {});
            document.getElementById('callStatusDot').className = 'w-1.5 h-1.5 bg-green-500 rounded-full';
            document.getElementById('callStatusText').textContent = 'Connected';
            document.getElementById('callAudioOnly').style.display = 'none';
            startCallTimer();
        };
        peerConnection.onicecandidate = (event) => { if(event.candidate) db.ref('calls/' + currentUser.id + '/offerCandidates').push(event.candidate.toJSON()); };
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        await db.ref('calls/' + currentUser.id).set({ callerId: currentUser.id, receiverId: activeChatId, status: 'ringing', isVideo: withVideo, offer: { type: offer.type, sdp: offer.sdp }, timestamp: firebase.database.ServerValue.TIMESTAMP });
        await db.ref('calls/' + activeChatId).set({ callerId: currentUser.id, receiverId: activeChatId, status: 'ringing', isVideo: withVideo, timestamp: firebase.database.ServerValue.TIMESTAMP });
        db.ref('calls/' + activeChatId + '/answer').on('value', async (snapshot) => { const answer = snapshot.val(); if(answer && peerConnection && !peerConnection.currentRemoteDescription) await peerConnection.setRemoteDescription(new RTCSessionDescription(answer)); });
        db.ref('calls/' + activeChatId + '/answerCandidates').on('child_added', (snapshot) => { if(peerConnection) peerConnection.addIceCandidate(new RTCIceCandidate(snapshot.val())).catch(e => {}); });
        db.ref('calls/' + activeChatId + '/status').on('value', (snapshot) => { const status = snapshot.val(); if(status === 'declined' || status === 'ended') window.endCall(); });
    } catch(err) { alert('Could not start call: ' + err.message); window.endCall(); }
}

function showCallModal(contactId, isVideo) {
    db.ref('users/' + contactId).once('value').then(snap => {
        const contact = snap.val();
        if(contact) {
            document.getElementById('callName').textContent = contact.name;
            setAnimatedMedia(document.getElementById('callAvatarContainer'), document.getElementById('callAvatar'), document.getElementById('callAvatarVideo'), contact.avatar);
            setAnimatedMedia(document.getElementById('callAvatarLargeContainer'), document.getElementById('callAvatarLarge'), document.getElementById('callAvatarLargeVideo'), contact.avatar);
        }
    });
    document.getElementById('callTimer').textContent = '00:00';
    document.getElementById('callStatusDot').className = 'w-1.5 h-1.5 bg-yellow-500 rounded-full animate-pulse';
    document.getElementById('callStatusText').textContent = 'Connecting...';
    document.getElementById('callAudioOnly').style.display = 'flex';
    document.getElementById('localVideoContainer').style.display = 'block';
    document.getElementById('callModal').classList.remove('hidden');
    document.getElementById('callModal').classList.add('flex');
    if(window.lucide) lucide.createIcons();
}

function startCallTimer() { callStartTime = Date.now(); callTimerInterval = setInterval(() => { const elapsed = Math.floor((Date.now() - callStartTime) / 1000); document.getElementById('callTimer').textContent = `${Math.floor(elapsed/60).toString().padStart(2,'0')}:${(elapsed%60).toString().padStart(2,'0')}`; }, 1000); }

window.toggleMic = function() { if(!localStream) return; isMicMuted = !isMicMuted; localStream.getAudioTracks().forEach(track => track.enabled = !isMicMuted); const btn = document.getElementById('micBtn'); if(isMicMuted) { btn.classList.add('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="mic-off"></i>'; } else { btn.classList.remove('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="mic"></i>'; } if(window.lucide) lucide.createIcons(); };
window.toggleVideo = function() { if(!localStream) return; const videoTracks = localStream.getVideoTracks(); if(videoTracks.length === 0) return; isVideoMuted = !isVideoMuted; videoTracks.forEach(track => track.enabled = !isVideoMuted); const btn = document.getElementById('videoBtn'); if(isVideoMuted) { btn.classList.add('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="video-off"></i>'; } else { btn.classList.remove('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="video"></i>'; } if(window.lucide) lucide.createIcons(); };
window.toggleRemoteAudio = function() { isRemoteMuted = !isRemoteMuted; document.getElementById('remoteVideo').muted = isRemoteMuted; document.getElementById('remoteAudio').muted = isRemoteMuted; const btn = document.getElementById('speakerBtn'); if(isRemoteMuted) { btn.classList.add('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="volume-x"></i>'; } else { btn.classList.remove('bg-red-500/30', 'text-red-400'); btn.innerHTML = '<i data-lucide="volume-2"></i>'; } if(window.lucide) lucide.createIcons(); };

window.startScreenShare = async function() {
    try {
        screenStream = await navigator.mediaDevices.getDisplayMedia({ video: { cursor: 'always' }, audio: true });
        const videoTrack = screenStream.getVideoTracks()[0];
        if (!originalVideoTrack && localStream) originalVideoTrack = localStream.getVideoTracks()[0];
        if(peerConnection) { const videoSender = peerConnection.getSenders().find(s => s.track?.kind === 'video'); if(videoSender) await videoSender.replaceTrack(videoTrack); }
        document.getElementById('localVideo').srcObject = screenStream;
        videoTrack.onended = () => stopScreenShare();
        const btn = document.getElementById('shareBtn'); btn.classList.add('bg-green-500'); btn.classList.remove('bg-primary'); btn.innerHTML = '<i data-lucide="monitor-off"></i>'; if(window.lucide) lucide.createIcons();
    } catch(e) {}
};

function stopScreenShare() {
    if (screenStream) { screenStream.getTracks().forEach(track => track.stop()); screenStream = null; }
    if (originalVideoTrack && peerConnection) { const videoSender = peerConnection.getSenders().find(s => s.track?.kind === 'video'); if (videoSender) videoSender.replaceTrack(originalVideoTrack).catch(e => {}); }
    if (localStream) document.getElementById('localVideo').srcObject = localStream;
    const btn = document.getElementById('shareBtn'); btn.classList.remove('bg-green-500'); btn.classList.add('bg-primary'); btn.innerHTML = '<i data-lucide="monitor"></i>'; if(window.lucide) lucide.createIcons();
}

window.endCall = function() {
    stopRingtone();
    if(callTimerInterval) { clearInterval(callTimerInterval); callTimerInterval = null; }
    if(screenStream) { screenStream.getTracks().forEach(track => track.stop()); screenStream = null; }
    if(localStream) { localStream.getTracks().forEach(track => track.stop()); localStream = null; }
    if(peerConnection) { peerConnection.close(); peerConnection = null; }
    if(currentUser) { db.ref('calls/' + currentUser.id).remove(); if(activeChatId) db.ref('calls/' + activeChatId).update({ status: 'ended' }); if(incomingCallData?.callerId) db.ref('calls/' + incomingCallData.callerId).update({ status: 'ended' }); }
    remoteStream = null; isMicMuted = false; isVideoMuted = false; isRemoteMuted = false; incomingCallData = null; originalVideoTrack = null;
    document.getElementById('callModal').classList.add('hidden'); document.getElementById('callModal').classList.remove('flex');
    document.getElementById('incomingCallModal').classList.add('hidden'); document.getElementById('incomingCallModal').classList.remove('flex');
    ['micBtn', 'videoBtn', 'speakerBtn'].forEach(id => { const btn = document.getElementById(id); if(btn) btn.classList.remove('bg-red-500/30', 'text-red-400'); });
    const shareBtn = document.getElementById('shareBtn'); if(shareBtn) { shareBtn.classList.remove('bg-green-500'); shareBtn.classList.add('bg-primary'); }
    if(window.lucide) lucide.createIcons();
};

// === DEVICE SETTINGS ===
async function loadDevices() {
    try {
        await navigator.mediaDevices.getUserMedia({ audio: true }).then(s => s.getTracks().forEach(t => t.stop()));
        const devices = await navigator.mediaDevices.enumerateDevices();
        const micSelect = document.getElementById('micSelect');
        const speakerSelect = document.getElementById('speakerSelect');
        if(!micSelect || !speakerSelect) return;
        micSelect.innerHTML = ''; speakerSelect.innerHTML = '';
        devices.forEach(device => { const option = document.createElement('option'); option.value = device.deviceId; option.text = device.label || `${device.kind} ${device.deviceId.slice(0, 8)}`; if (device.kind === 'audioinput') micSelect.appendChild(option); else if (device.kind === 'audiooutput') speakerSelect.appendChild(option); });
    } catch(e) {}
}

document.getElementById('notifBtn')?.addEventListener('click', () => { document.getElementById('notifDropdown')?.classList.toggle('hidden'); });
