const express = require('express');
const axios = require('axios');
const cors = require('cors');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const TelegramBot = require('node-telegram-bot-api');
const config = require('./config');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const port = 3001;

const SITE_MAPPINGS = {
    '75': 'main55', '19': 'dana55', '25': 'goku55',
    '30': 'gol33', '35': 'nami55', '40': 'fanta55',
    '45': 'mekar55', '50': 'kenzo55', '54': 'nona55',
    '59': 'bass99', '64': 'topspin88'
};

app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: process.env.SESSION_SECRET || 'dj2n3k4n2k3n4k23n4k23n4kj2n3k4j2h3g4k23h4',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

const ADMIN_CREDENTIALS = {
    username: 'seoulmkt',
    password: '$2b$10$YourHashedPasswordHere'
};

app.use((req, res, next) => {
    console.log('Request URL:', req.url);
    console.log('Request Method:', req.method);
    console.log('Request Body:', req.body);
    console.log('Session:', req.session);
    console.log('Auth status:', req.session.isAuthenticated);
    next();
});

const bot = new TelegramBot(config.TELEGRAM_TOKEN, { polling: true });

const axiosInstance = axios.create({
    timeout: 10000,
    maxRetries: 3,
    retryDelay: 1000
});

axiosInstance.interceptors.response.use(null, async (error) => {
    const { config } = error;
    if (!config || !config.retry) return Promise.reject(error);
    config.retry -= 1;
    if (config.retry === 0) return Promise.reject(error);
    await new Promise(resolve => setTimeout(resolve, config.retryDelay));
    return axiosInstance(config);
});

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

function requireAuth(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/gogo');
    }
}

app.get('/gogo', (req, res) => {
    if (req.session.isAuthenticated) {
        res.redirect('/redirect');
    } else {
        res.sendFile(path.join(__dirname, 'gogo', 'index.html'));
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username dan password harus diisi' });
    }

    if (username === ADMIN_CREDENTIALS.username && password === 'qwertyuiop88@!') {
        req.session.isAuthenticated = true;
        req.session.username = username;
        return res.status(200).json({ success: true });
    }
    
    return res.status(401).json({ success: false, message: 'Username atau password salah' });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Gagal logout' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

function requireAuth(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.redirect('/gogo');
    }
}

app.use('/redirect', requireAuth);
app.use('/redirect', express.static(path.join(__dirname, 'redirect')));

app.get('/redirect/*', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'redirect', 'index.html'));
});

function initializeDomainFiles() {
    for (const [linkId, siteName] of Object.entries(SITE_MAPPINGS)) {
        const filePath = path.join(__dirname, `domains_${siteName}.txt`);
        if (!fs.existsSync(filePath)) {
            fs.writeFileSync(filePath, '', 'utf8');
        }
    }
}

function readDomains(linkId) {
    try {
        const siteName = SITE_MAPPINGS[linkId];
        const filePath = path.join(__dirname, `domains_${siteName}.txt`);
        if (fs.existsSync(filePath)) {
            return fs.readFileSync(filePath, 'utf8')
                .split('\n')
                .map(d => d.trim())
                .filter(d => d);
        }
        return [];
    } catch (error) {
        return [];
    }
}

function saveDomains(linkId, domains) {
    const siteName = SITE_MAPPINGS[linkId];
    const filePath = path.join(__dirname, `domains_${siteName}.txt`);
    fs.writeFileSync(filePath, domains.join('\n'));
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/config', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const clientConfig = {
        API_ENDPOINTS: config.API_ENDPOINTS,
        LINK_ID: config.LINK_ID
    };
    res.json(clientConfig);
});

app.get('/api/domains/all', (req, res) => {
    try {
        const allDomains = {};
        for (const linkId of Object.keys(SITE_MAPPINGS)) {
            allDomains[linkId] = readDomains(linkId);
        }
        res.json(allDomains);
    } catch (error) {
        res.status(500).json({ error: 'Failed to read domains' });
    }
});

app.post('/api/domains/:linkId', (req, res) => {
    const { linkId } = req.params;
    const { domains } = req.body;
    try {
        saveDomains(linkId, domains);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save domains' });
    }
});

app.post('/api/check', async (req, res) => {
    try {
        const { domain } = req.body;
        const response = await axiosInstance.post(config.API_ENDPOINTS.TRUST_POSITIF, {
            name: domain
        }, {
            headers: { 'Content-Type': 'application/json' },
            retry: 3,
            retryDelay: 1000
        });
        
        if (!response.data || !response.data.values) {
            return res.json({
                values: [{
                    Domain: domain,
                    Status: "Tidak Ada"
                }]
            });
        }
        
        res.json(response.data);
    } catch (error) {
        res.json({
            values: [{
                Domain: domain,
                Status: "Tidak Ada"
            }]
        });
    }
});

app.get('/api/links/:linkId', async (req, res) => {
    const { linkId } = req.params;
    try {
        const response = await axios.get(`${config.API_ENDPOINTS.KLIKLI}/links/${linkId}`, {
            headers: { 'Authorization': `Bearer ${config.API_KEY}` }
        });
        
        const linkData = {
            destination_url: response.data.data.location_url,
            short_url: `klikli.ink/${response.data.data.url}`
        };
        
        res.json(linkData);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching URL data' });
    }
});

app.put('/api/links/:linkId', async (req, res) => {
    const { linkId } = req.params;
    const { destination_url } = req.body;
    try {
        const currentData = await axios.get(`https://klikli.ink/api/links/${linkId}`, {
            headers: { 'Authorization': `Bearer ${config.API_KEY}` }
        });
        
        const form = new FormData();
        form.append('_method', 'PUT');
        form.append('url', currentData.data.data.url);
        form.append('location_url', destination_url);
        form.append('type', 'link');
        
        const response = await axios.post(`https://klikli.ink/api/links/${linkId}`, form, {
            headers: {
                ...form.getHeaders(),
                'Authorization': `Bearer ${config.API_KEY}`
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Error updating URL' });
    }
});

app.use('/redirect', express.static(path.join(__dirname, 'redirect')));

app.get('/redirect/*', (req, res) => {
    res.sendFile(path.join(__dirname, 'redirect', 'index.html'));
});

async function autoUpdateDomain() {
    try {
        const linkIds = Object.keys(SITE_MAPPINGS);
        console.log('Starting automatic domain check...');
        
        for (const linkId of linkIds) {
            try {
                const linkResponse = await axios.get(`${config.API_ENDPOINTS.KLIKLI}/links/${linkId}`, {
                    headers: { 'Authorization': `Bearer ${config.API_KEY}` }
                });

                let currentDomain = linkResponse.data.data.location_url
                    .replace(/^https?:\/\//, '')
                    .replace(/^www\./, '')
                    .replace(/\/$/, '');

                const currentUrl = linkResponse.data.data.url;
                console.log(`\nChecking domain for ${SITE_MAPPINGS[linkId]}: ${currentDomain}`);

                const checkResponse = await axiosInstance.post(config.API_ENDPOINTS.TRUST_POSITIF, {
                    name: currentDomain
                }, {
                    headers: { 'Content-Type': 'application/json' },
                    retry: 3,
                    retryDelay: 1000
                });

                const wwwCheckResponse = await axiosInstance.post(config.API_ENDPOINTS.TRUST_POSITIF, {
                    name: `www.${currentDomain}`
                }, {
                    headers: { 'Content-Type': 'application/json' },
                    retry: 3,
                    retryDelay: 1000
                });

                const isBlocked = checkResponse.data.values?.[0]?.Status === "Ada" || 
                                wwwCheckResponse.data.values?.[0]?.Status === "Ada";

                console.log(`Check result for ${currentDomain}:`, checkResponse.data);
                console.log(`Check result for www.${currentDomain}:`, wwwCheckResponse.data);
                
                if (isBlocked) {
                    console.log(`Domain ${currentDomain} terblokir, mencari domain pengganti...`);
                    
                    const domains = readDomains(linkId);
                    console.log(`Mencoba ${domains.length} domain alternatif untuk ${SITE_MAPPINGS[linkId]}...`);
                    
                    for (const domain of domains) {
                        const cleanDomain = domain
                            .replace(/^https?:\/\//, '')
                            .replace(/^www\./, '')
                            .replace(/\/$/, '');

                        console.log(`Memeriksa domain alternatif: ${cleanDomain}`);
                        
                        const altCheckResponse = await axiosInstance.post(config.API_ENDPOINTS.TRUST_POSITIF, {
                            name: cleanDomain
                        }, {
                            headers: { 'Content-Type': 'application/json' },
                            retry: 3,
                            retryDelay: 1000
                        });

                        const altWwwCheckResponse = await axiosInstance.post(config.API_ENDPOINTS.TRUST_POSITIF, {
                            name: `www.${cleanDomain}`
                        }, {
                            headers: { 'Content-Type': 'application/json' },
                            retry: 3,
                            retryDelay: 1000
                        });
                        
                        const isAltSafe = altCheckResponse.data.values?.[0]?.Status === "Tidak Ada" &&
                                        altWwwCheckResponse.data.values?.[0]?.Status === "Tidak Ada";
                        
                        if (isAltSafe) {
                            console.log(`Menemukan domain pengganti yang tidak terblokir: ${cleanDomain}`);
                            
                            const form = new FormData();
                            form.append('_method', 'PUT');
                            form.append('url', currentUrl);
                            form.append('location_url', `https://${cleanDomain}`);
                            form.append('type', 'link');
                            
                            const updateResponse = await axios.post(`${config.API_ENDPOINTS.KLIKLI}/links/${linkId}`, form, {
                                headers: {
                                    ...form.getHeaders(),
                                    'Authorization': `Bearer ${config.API_KEY}`
                                }
                            });
                            
                            console.log('Update response:', updateResponse.data);
                            bot.sendMessage(config.CHAT_ID, `Domain ${currentDomain} telah diblokir. Diganti dengan ${cleanDomain}`);
                            break;
                        }
                    }
                } else {
                    console.log(`Domain ${currentDomain} masih aman`);
                }
            } catch (error) {
                console.error(`Error processing ${SITE_MAPPINGS[linkId]}:`, error.message);
                continue;
            }
        }
    } catch (error) {
        console.error('Error in auto update:', error);
    }
}

initializeDomainFiles();
autoUpdateDomain();
setInterval(autoUpdateDomain, 300000);

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});